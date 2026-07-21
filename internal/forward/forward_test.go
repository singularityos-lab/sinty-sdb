// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package forward_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/forward"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// device wires a client and device mux session and serves forward streams.
func device(t *testing.T) *mux.Session {
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
				if st.Kind() == forward.KindForward {
					_ = forward.ServeForward(st)
				} else {
					_ = st.Close()
				}
			}(st)
		}
	}()
	return client
}

// echoServer accepts TCP connections and echoes bytes until closed.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestForwardEchoesThroughTunnel(t *testing.T) {
	ln := echoServer(t)
	client := device(t)

	st, err := forward.Dial(client, ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want %q", buf, "ping")
	}
	_ = st.Close()
}

func TestForwardPrivilegedPortRefused(t *testing.T) {
	client := device(t)

	st, err := forward.Dial(client, "127.0.0.1:80")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	done := make(chan struct{})
	go func() { _, _ = io.ReadAll(st); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("device did not refuse the privileged port")
	}
	if code, ok := st.ExitCode(); !ok || code != 5 {
		t.Fatalf("exit code (%d, %v), want (5, true)", code, ok)
	}
}
