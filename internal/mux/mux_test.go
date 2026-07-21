// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package mux

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Frame{StreamID: 0x01020304, Type: FrameData, Payload: []byte("hello")}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if buf.Len() != HeaderSize+len(in.Payload) {
		t.Fatalf("encoded length %d, want %d", buf.Len(), HeaderSize+len(in.Payload))
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if out.StreamID != in.StreamID || out.Type != in.Type || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("round trip mismatch: got %+v want %+v", out, in)
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, Frame{Payload: make([]byte, MaxPayload+1)})
	if err != ErrFrameTooLarge {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

// A server that echoes every stream the peer opens.
func echoServer(s *Session) {
	for {
		st, err := s.Accept()
		if err != nil {
			return
		}
		go func(st *Stream) {
			_, _ = io.Copy(st, st)
			_ = st.Close()
		}(st)
	}
}

func TestConcurrentStreamsDoNotMix(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1, false)
	server := NewSession(c2, true)
	defer client.Close()
	defer server.Close()
	go echoServer(server)

	payloads := []string{"stream-one-AAAAAA", "stream-two-BBBBBBBBBB"}
	var wg sync.WaitGroup
	got := make([]string, len(payloads))
	for i, p := range payloads {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			st, err := client.Open("echo")
			if err != nil {
				t.Errorf("Open: %v", err)
				return
			}
			if _, err := st.Write([]byte(p)); err != nil {
				t.Errorf("Write: %v", err)
				return
			}
			buf := make([]byte, len(p))
			if _, err := io.ReadFull(st, buf); err != nil {
				t.Errorf("ReadFull: %v", err)
				return
			}
			got[i] = string(buf)
			_ = st.Close()
		}(i, p)
	}
	wg.Wait()
	for i, p := range payloads {
		if got[i] != p {
			t.Fatalf("stream %d got %q, want %q (streams mixed?)", i, got[i], p)
		}
	}
}

func TestWindowBlocksAndResumes(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1, false)
	server := NewSession(c2, true)
	defer client.Close()
	defer server.Close()
	client.SetInitialWindow(4)
	server.SetInitialWindow(4)

	st, err := client.Open("shell")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	serverSt, err := server.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	payload := []byte("ABCDEFGH") // 8 bytes, initial window is 4
	done := make(chan int, 1)
	go func() {
		n, _ := st.Write(payload)
		done <- n
	}()

	select {
	case <-done:
		t.Fatal("write completed before the window was replenished")
	case <-time.After(150 * time.Millisecond):
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(serverSt, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	select {
	case n := <-done:
		if n != len(payload) {
			t.Fatalf("wrote %d bytes, want %d", n, len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write did not resume after the window opened")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestUnknownStreamClosesSession(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewSession(c2, true)
	defer server.Close()

	go func() {
		_ = WriteFrame(c1, Frame{StreamID: 99, Type: FrameData, Payload: []byte("x")})
	}()

	select {
	case <-server.done:
	case <-time.After(time.Second):
		t.Fatal("session did not close on a frame for an unknown stream")
	}
	if server.err0() == nil {
		t.Fatal("expected an error after an unknown-stream frame")
	}
}
