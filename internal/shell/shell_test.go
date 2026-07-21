// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
)

// pair wires a client and a device mux session over an in-memory pipe and runs
// the device side, serving every accepted shell stream.
func pair(t *testing.T) *mux.Session {
	t.Helper()
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	server := mux.NewSession(c2, true)
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		for {
			st, err := server.Accept()
			if err != nil {
				return
			}
			go func(st *mux.Stream) {
				if st.Kind() == shell.StreamKind {
					_, _ = shell.ServeStream(st)
				} else {
					_ = st.Close()
				}
			}(st)
		}
	}()
	return client
}

func TestShellCommandOutput(t *testing.T) {
	client := pair(t)
	st, err := client.Open(shell.StreamKind, "echo", "hello")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	out, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(out) != "hello\n" {
		t.Fatalf("got %q, want %q", out, "hello\n")
	}
	if code, ok := st.ExitCode(); !ok || code != 0 {
		t.Fatalf("exit code (%d, %v), want (0, true)", code, ok)
	}
}

func TestShellExitCode(t *testing.T) {
	client := pair(t)
	st, err := client.Open(shell.StreamKind, "sh", "-c", "exit 3")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := io.ReadAll(st); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	code, ok := st.ExitCode()
	if !ok || code != 3 {
		t.Fatalf("exit code (%d, %v), want (3, true)", code, ok)
	}
}

func TestShellStdinToStdout(t *testing.T) {
	client := pair(t)
	st, err := client.Open(shell.StreamKind, "cat")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := make(chan []byte, 1)
	go func() {
		out, _ := io.ReadAll(st)
		done <- out
	}()
	select {
	case out := <-done:
		if string(out) != "ping" {
			t.Fatalf("got %q, want %q", out, "ping")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cat did not echo stdin back over the stream")
	}
}
