// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package broker

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// mockBroker listens on a unix socket and answers one request per connection
// with handler's decision, sending the parsed request on reqs.
func mockBroker(t *testing.T, reqs chan<- Request, handler func(Request) Response) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "broker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadBytes('\n')
				var req Request
				_ = json.Unmarshal(line, &req)
				if reqs != nil {
					reqs <- req
				}
				resp := handler(req)
				b, _ := json.Marshal(resp)
				_, _ = c.Write(append(b, '\n'))
			}(conn)
		}
	}()
	return sock
}

func TestElevateGrantedCarriesExactWire(t *testing.T) {
	reqs := make(chan Request, 1)
	sock := mockBroker(t, reqs, func(Request) Response {
		return Response{OK: true, Message: "granted"}
	})
	ok, msg := New(sock).Elevate(ActionWriteSystem, "/etc/hosts", "sdb:laptop", "sess-1")
	if !ok {
		t.Fatalf("granted call returned ok=false (%q)", msg)
	}
	req := <-reqs
	if req.Method != Method {
		t.Fatalf("method %q, want %q", req.Method, Method)
	}
	if req.Action != ActionWriteSystem || req.Detail != "/etc/hosts" ||
		req.Origin != "sdb:laptop" || req.Session != "sess-1" {
		t.Fatalf("wire mismatch: %+v", req)
	}
}

func TestElevateDenied(t *testing.T) {
	sock := mockBroker(t, nil, func(Request) Response {
		return Response{OK: false, Message: "user declined"}
	})
	ok, msg := New(sock).Elevate(ActionShellRoot, "", "sdb:laptop", "sess-2")
	if ok {
		t.Fatal("denied call returned ok=true")
	}
	if msg != "user declined" {
		t.Fatalf("message %q, want %q", msg, "user declined")
	}
}

func TestElevateFailsClosedWithoutBroker(t *testing.T) {
	ok, _ := New(filepath.Join(t.TempDir(), "absent.sock")).Elevate(ActionShellRoot, "", "sdb:x", "s")
	if ok {
		t.Fatal("a missing broker must deny, not grant")
	}
}

func TestElevateFailsClosedOnGarbageReply(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "garbage.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte("not json\n"))
	}()
	ok, _ := New(sock).Elevate(ActionShellRoot, "", "sdb:x", "s")
	if ok {
		t.Fatal("an unparsable reply must deny, not grant")
	}
}
