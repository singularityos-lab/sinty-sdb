// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package session_test

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singularityos-lab/sinty-sdb/internal/forward"
	"github.com/singularityos-lab/sinty-sdb/internal/logs"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
	"github.com/singularityos-lab/sinty-sdb/internal/session"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
	"github.com/singularityos-lab/sinty-sdb/internal/transfer"
)

// One connection, one dispatch: every phase-two command must reach its handler
// through session.Serve, or it is orphaned code that compiles but never runs.
func TestSessionDispatchesEveryKind(t *testing.T) {
	root := t.TempDir()
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	t.Cleanup(func() { client.Close() })
	logSrc := func(unit string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("log for " + unit)), nil
	}
	go session.Serve(c2, session.Config{Root: root, Logs: logSrc})

	// shell
	sh, err := client.Open(shell.StreamKind, "echo", "wired")
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	out, _ := io.ReadAll(sh)
	if string(out) != "wired\n" {
		t.Fatalf("shell got %q, want %q", out, "wired\n")
	}

	// push then pull
	content := []byte("dispatched through the session")
	local := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(local, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := transfer.Push(client, local, "f"); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "f")); !bytes.Equal(got, content) {
		t.Fatalf("push landed %q, want %q", got, content)
	}
	back := filepath.Join(t.TempDir(), "back")
	if err := transfer.Pull(client, "f", back); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got, _ := os.ReadFile(back); !bytes.Equal(got, content) {
		t.Fatalf("pull got %q, want %q", got, content)
	}

	// forward
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
		conn.Close()
	}()
	fw, err := forward.Dial(client, ln.Addr().String())
	if err != nil {
		t.Fatalf("open forward: %v", err)
	}
	if _, err := fw.Write([]byte("echo")); err != nil {
		t.Fatalf("forward write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(fw, buf); err != nil {
		t.Fatalf("forward read: %v", err)
	}
	if string(buf) != "echo" {
		t.Fatalf("forward got %q, want %q", buf, "echo")
	}
	_ = fw.Close()

	// logs
	lg, err := client.Open(logs.StreamKind, "sdbd")
	if err != nil {
		t.Fatalf("open logs: %v", err)
	}
	logOut, _ := io.ReadAll(lg)
	if string(logOut) != "log for sdbd" {
		t.Fatalf("logs got %q, want %q", logOut, "log for sdbd")
	}
}
