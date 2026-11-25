// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package protocol

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func pipeConn(t *testing.T, input []byte) *Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() {
		_, _ = b.Write(input)
		b.Close()
	}()
	return NewConn(a, "peer")
}

func TestReadRequestRefusesAnEndlessLine(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		chunk := bytes.Repeat([]byte{'a'}, 4096)
		for {
			select {
			case <-stop:
				b.Close()
				return
			default:
			}
			if _, err := b.Write(chunk); err != nil {
				return
			}
		}
	}()
	c := NewConn(a, "peer")
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.ReadRequest(); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("endless line: err %v, want %v", err, errFrameTooLarge)
	}
}

func TestReadRequestAcrossBufferBoundaries(t *testing.T) {
	label := string(bytes.Repeat([]byte{'x'}, 10000))
	var buf bytes.Buffer
	buf.WriteString(`{"op":"pair","label":"` + label + `"}` + "\n")
	c := pipeConn(t, buf.Bytes())
	req, err := c.ReadRequest()
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if req.Label != label {
		t.Fatalf("label of %d bytes, want %d", len(req.Label), len(label))
	}
}

func TestReadRequestWithoutTrailingNewline(t *testing.T) {
	c := pipeConn(t, []byte(`{"op":"pair"}`))
	if _, err := c.ReadRequest(); err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if _, err := c.ReadRequest(); err != io.EOF {
		t.Fatalf("after the last frame: err %v, want EOF", err)
	}
}

func FuzzReadRequest(f *testing.F) {
	f.Add([]byte(`{"op":"pair","label":"laptop"}` + "\n"))
	f.Add([]byte("{\n}\n"))
	f.Add([]byte(`{"op":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := pipeConn(t, data)
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		for i := 0; i < 4; i++ {
			if _, err := c.ReadRequest(); err != nil {
				return
			}
		}
	})
}
