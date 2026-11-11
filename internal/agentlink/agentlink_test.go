// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package agentlink

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fake(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, args []string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	code := 0
	if e, ok := err.(*exec.ExitError); ok {
		code = e.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestAskPassesTheWordsUntouched(t *testing.T) {
	bin := t.TempDir()
	fake(t, bin, "sinty", `printf '%s|' "$@"; echo "$DBUS_SESSION_BUS_ADDRESS"`)
	out, code := run(t, AskArgs([]string{"what's", "the $HOME", "`id`"}), "PATH="+bin+":/usr/bin:/bin", "XDG_RUNTIME_DIR=/run/user/7")
	if code != 0 || out != "ask|what's|the $HOME|`id`|unix:path=/run/user/7/bus\n" {
		t.Fatalf("got %q (%d)", out, code)
	}
}

func TestAskWithoutSintyAI(t *testing.T) {
	out, code := run(t, AskArgs([]string{"hi"}), "PATH="+t.TempDir(), "XDG_RUNTIME_DIR=/x")
	if code != 127 || !strings.Contains(out, "not installed") {
		t.Fatalf("got %q (%d)", out, code)
	}
}

func TestMCPJoinsTheAgentSocket(t *testing.T) {
	bin, rt := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(rt, "sinty-agent"), 0700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(rt, "sinty-agent", "mcp.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fake(t, bin, "sinty-agent-bridge", `echo "bridge $1"`)
	args := MCPArgs()
	args[2] = strings.Replace(args[2], "b=/usr/libexec/sinty-agent-bridge", "b=/nonexistent", 1)
	out, code := run(t, args, "PATH="+bin+":/usr/bin:/bin", "XDG_RUNTIME_DIR="+rt)
	if code != 0 || out != "bridge "+filepath.Join(rt, "sinty-agent", "mcp.sock")+"\n" {
		t.Fatalf("got %q (%d)", out, code)
	}
}

func TestMCPWhenTheAgentNeverStarts(t *testing.T) {
	bin := t.TempDir()
	fake(t, bin, "sinty-agent-bridge", `echo bridge`)
	args := MCPArgs()
	args[2] = strings.Replace(args[2], "b=/usr/libexec/sinty-agent-bridge", "b=/nonexistent", 1)
	out, code := run(t, args, "PATH="+bin+":/usr/bin:/bin", "XDG_RUNTIME_DIR="+t.TempDir())
	if code != 1 || !strings.Contains(out, "not running") {
		t.Fatalf("got %q (%d)", out, code)
	}
}
