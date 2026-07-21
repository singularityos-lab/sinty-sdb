// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package rforward_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
	"github.com/singularityos-lab/sinty-sdb/internal/rforward"
)

// wire builds a host and device mux pair, runs the device listen handler and
// the host connection handler, and returns the host session and a gate control.
func wire(t *testing.T, allowPrivileged bool) *mux.Session {
	t.Helper()
	c1, c2 := net.Pipe()
	host := mux.NewSession(c1, false)
	device := mux.NewSession(c2, true)
	t.Cleanup(func() { host.Close(); device.Close() })
	go func() {
		for {
			st, err := device.Accept()
			if err != nil {
				return
			}
			if st.Kind() == rforward.KindListen {
				go rforward.Listen(device, st, func() bool { return allowPrivileged })
			}
		}
	}()
	go func() {
		for {
			st, err := host.Accept()
			if err != nil {
				return
			}
			if st.Kind() == rforward.KindConn {
				go rforward.HandleConn(st)
			}
		}
	}()
	return host
}

func echoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }(conn)
		}
	}()
	return ln.Addr().String()
}

func TestReverseTunnelCarriesToHostTarget(t *testing.T) {
	target := echoTarget(t)
	host := wire(t, true)

	ctrl, err := host.Open(rforward.KindListen, "127.0.0.1:0", target)
	if err != nil {
		t.Fatalf("open listen: %v", err)
	}
	bound, err := rforward.ReadBoundAddr(ctrl)
	if err != nil {
		t.Fatalf("read bound addr: %v", err)
	}

	conn, err := net.Dial("tcp", bound)
	if err != nil {
		t.Fatalf("dial device bind: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want %q", buf, "ping")
	}
}

func TestReversePrivilegedBindRefused(t *testing.T) {
	host := wire(t, false)

	ctrl, err := host.Open(rforward.KindListen, "127.0.0.1:80", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("open listen: %v", err)
	}
	// The device refuses to bind and closes the control stream with code 5,
	// so no bound address arrives.
	if _, err := rforward.ReadBoundAddr(ctrl); err == nil {
		t.Fatal("privileged bind should be refused, got a bound address")
	}
	if code, ok := ctrl.ExitCode(); !ok || code != 5 {
		t.Fatalf("exit (%d,%v), want (5,true)", code, ok)
	}
}
