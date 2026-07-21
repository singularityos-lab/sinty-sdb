// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

//go:build linux && amd64

// Package inmem runs a tool that lives only in memory. The tool bytes, embedded
// in the signed daemon, are written into an anonymous in-memory file
// (memfd_create), sealed immutable, and executed through /proc/self/fd, so the
// binary never touches the read-only disk and leaves nothing behind when the fd
// closes. This is the mechanism for the assistance tier: privileged helpers that
// exist as an attack surface only while an authorized session holds them in RAM,
// not sitting on disk the rest of the time. It carries the mechanism, not the
// policy: what a tool may do, and who may run it, is decided by the caller.
package inmem

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// syscall numbers and flags not exposed by the stdlib on this arch.
const (
	sysMemfdCreate = 319 // linux/amd64
	mfdAllowSealing = 0x0002
	fAddSeals       = 1033
	fGetSeals       = 1034
	fSealSeal       = 0x0001
	fSealShrink     = 0x0002
	fSealGrow       = 0x0004
	fSealWrite      = 0x0008
	allSeals        = fSealSeal | fSealShrink | fSealGrow | fSealWrite
)

// sealedMemfd materializes payload into an anonymous file, seals it so it can no
// longer be written or resized, and returns the open file. The seal makes the
// in-RAM binary immutable between materialization and execution.
func sealedMemfd(name string, payload []byte) (*os.File, error) {
	cname := append([]byte(name), 0)
	fd, _, errno := syscall.Syscall(sysMemfdCreate,
		uintptr(unsafe.Pointer(&cname[0])), mfdAllowSealing, 0)
	if errno != 0 {
		return nil, fmt.Errorf("memfd_create: %w", errno)
	}
	f := os.NewFile(fd, "memfd:"+name)
	if _, err := f.Write(payload); err != nil {
		f.Close()
		return nil, fmt.Errorf("write memfd: %w", err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, fAddSeals, allSeals); errno != 0 {
		f.Close()
		return nil, fmt.Errorf("seal memfd: %w", errno)
	}
	return f, nil
}

// Command materializes payload into a sealed in-memory file and returns a Cmd
// that will execute it with argv[0]=name and the given args, plus a cleanup to
// release the memory. The binary runs from /proc/self/fd, so it has no path on
// disk. The caller sets Stdin/Stdout/Stderr and any credential (the privilege
// the tool runs with is the caller's decision, not this package's), then runs
// the Cmd; it must not set ExtraFiles, which this package owns.
func Command(payload []byte, name string, args ...string) (*exec.Cmd, func(), error) {
	f, err := sealedMemfd(name, payload)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Args = append([]string{name}, args...)
	cmd.ExtraFiles = []*os.File{f} // becomes fd 3 in the child
	return cmd, func() { f.Close() }, nil
}
