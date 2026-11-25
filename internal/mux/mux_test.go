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

func waitClosed(t *testing.T, s *Session) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("session stayed open after a protocol violation")
	}
}

func TestDataPastWindowClosesSession(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewSession(c2, true)
	defer server.Close()
	go func() {
		_ = WriteFrame(c1, Frame{StreamID: 1, Type: FrameOpen, Payload: []byte(`{"kind":"shell"}`)})
		_ = WriteFrame(c1, Frame{StreamID: 1, Type: FrameData, Payload: make([]byte, DefaultWindow+1)})
	}()
	if _, err := server.Accept(); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	waitClosed(t, server)
}

func TestPeerCannotOpenOurStreamIDs(t *testing.T) {
	for _, id := range []uint32{2, 1<<31 + 1} {
		c1, c2 := net.Pipe()
		server := NewSession(c2, true)
		go func() {
			_ = WriteFrame(c1, Frame{StreamID: id, Type: FrameOpen, Payload: []byte(`{"kind":"shell"}`)})
		}()
		waitClosed(t, server)
		server.Close()
	}
}

func TestPeerCannotReuseStreamIDs(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewSession(c2, true)
	defer server.Close()
	accepted := make(chan struct{})
	go func() {
		_ = WriteFrame(c1, Frame{StreamID: 3, Type: FrameOpen, Payload: []byte(`{"kind":"a"}`)})
		_ = WriteFrame(c1, Frame{StreamID: 1, Type: FrameOpen, Payload: []byte(`{"kind":"b"}`)})
		<-accepted
		_ = WriteFrame(c1, Frame{StreamID: 1, Type: FrameOpen, Payload: []byte(`{"kind":"c"}`)})
	}()
	for _, want := range []string{"a", "b"} {
		st, err := server.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if st.Kind() != want {
			t.Fatalf("accepted %q, want %q", st.Kind(), want)
		}
	}
	close(accepted)
	waitClosed(t, server)
}

func TestPeerCannotSkipTooFar(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewSession(c2, true)
	defer server.Close()
	go func() {
		_ = WriteFrame(c1, Frame{StreamID: 1 + 2*(maxSkipped+1), Type: FrameOpen, Payload: []byte(`{"kind":"a"}`)})
	}()
	waitClosed(t, server)
}

func TestWindowGrantOverflowClosesSession(t *testing.T) {
	c1, c2 := net.Pipe()
	server := NewSession(c2, true)
	defer server.Close()
	go func() {
		_ = WriteFrame(c1, Frame{StreamID: 1, Type: FrameOpen, Payload: []byte(`{"kind":"shell"}`)})
		for i := 0; i < 4; i++ {
			_ = WriteFrame(c1, Frame{StreamID: 1, Type: FrameWindow, Payload: []byte{0xff, 0xff, 0xff, 0xff}})
		}
	}()
	if _, err := server.Accept(); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	waitClosed(t, server)
}

func TestClosedStreamsAreForgotten(t *testing.T) {
	c1, c2 := net.Pipe()
	client := NewSession(c1, false)
	server := NewSession(c2, true)
	defer client.Close()
	defer server.Close()
	for i := 0; i < 50; i++ {
		st, err := client.Open("x")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		peer, err := server.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if _, err := st.Write([]byte("hi")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(peer, buf); err != nil {
			t.Fatalf("Read: %v", err)
		}
		st.Close()
		peer.Close()
		if _, err := io.ReadAll(st); err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		client.mu.Lock()
		cn := len(client.streams)
		client.mu.Unlock()
		server.mu.Lock()
		sn := len(server.streams)
		server.mu.Unlock()
		if cn == 0 && sn == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("streams left: client %d server %d", cn, sn)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if client.err0() != ErrSessionClosed && client.err != nil {
		t.Fatalf("client failed: %v", client.err)
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 2, 0, 0, 2, 'h', 'i'})
	f.Add([]byte{0, 0, 0, 1, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := WriteFrame(&out, fr); err != nil {
			t.Fatalf("WriteFrame of a decoded frame: %v", err)
		}
		if !bytes.Equal(out.Bytes(), data[:out.Len()]) {
			t.Fatal("frame did not round-trip")
		}
	})
}

func FuzzSession(f *testing.F) {
	var seed bytes.Buffer
	_ = WriteFrame(&seed, Frame{StreamID: 1, Type: FrameOpen, Payload: []byte(`{"kind":"shell","args":["-l"]}`)})
	_ = WriteFrame(&seed, Frame{StreamID: 1, Type: FrameData, Payload: []byte("ls\n")})
	_ = WriteFrame(&seed, Frame{StreamID: 1, Type: FrameWindow, Payload: []byte{0, 0, 1, 0}})
	_ = WriteFrame(&seed, Frame{StreamID: 1, Type: FrameClose, Payload: []byte{0, 0, 0, 1}})
	f.Add(seed.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		c1, c2 := net.Pipe()
		server := NewSession(c2, true)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				st, err := server.Accept()
				if err != nil {
					return
				}
				go func() {
					_, _ = io.Copy(io.Discard, st)
					_ = st.Close()
				}()
			}
		}()
		go func() { _, _ = io.Copy(io.Discard, c1) }()
		_, _ = c1.Write(data)
		_ = c1.Close()
		select {
		case <-server.done:
		case <-time.After(2 * time.Second):
			t.Fatal("session did not end when the peer hung up")
		}
		wg.Wait()
		server.mu.Lock()
		for _, st := range server.streams {
			st.mu.Lock()
			if st.inbuf.Len() > DefaultWindow {
				t.Fatalf("stream buffered %d bytes past its window", st.inbuf.Len())
			}
			st.mu.Unlock()
		}
		server.mu.Unlock()
	})
}
