// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

//go:build linux && amd64

package inmem

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// A small, always-present multi-call binary stands in for the embedded tool.
const samplePayload = "/usr/bin/id"

func TestSealedMemfdIsImmutable(t *testing.T) {
	data, err := os.ReadFile(samplePayload)
	if err != nil {
		t.Skipf("no sample payload: %v", err)
	}
	f, err := sealedMemfd("probe", data)
	if err != nil {
		t.Fatalf("sealedMemfd: %v", err)
	}
	defer f.Close()

	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), fGetSeals, 0)
	if errno != 0 {
		t.Fatalf("F_GET_SEALS: %v", errno)
	}
	if int(seals)&fSealWrite == 0 {
		t.Fatalf("memfd is not write-sealed (seals=%#x)", seals)
	}
	if int(seals) != allSeals {
		t.Fatalf("seals=%#x, want %#x", seals, allSeals)
	}
	if _, err := f.WriteAt([]byte{0}, 0); err == nil {
		t.Fatal("write to a sealed memfd should be refused")
	}
}

func TestCommandRunsFromMemory(t *testing.T) {
	data, err := os.ReadFile(samplePayload)
	if err != nil {
		t.Skipf("no sample payload: %v", err)
	}
	cmd, cleanup, err := Command(data, "id")
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	defer cleanup()

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run from memory: %v", err)
	}
	if !strings.Contains(string(out), "uid=") {
		t.Fatalf("tool output %q does not look like id output", out)
	}
}
