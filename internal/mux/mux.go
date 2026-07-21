// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package mux carries many independent byte streams over a single connection
// that is already authenticated and encrypted, so shell, file transfer and log
// tailing can share one TLS session without a second handshake. The frame is a
// fixed eight byte header, big-endian: a uint32 stream id, a one byte type, and
// a uint24 payload length. Stream id zero is the control channel and keeps the
// newline-JSON request and reply of phase one, so a phase-one peer that never
// opens a stream still works over the same connection.
package mux

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// FrameType is the one byte kind field of a frame header.
type FrameType uint8

const (
	// FrameOpen starts a stream; its payload is a JSON OpenPayload.
	FrameOpen FrameType = 1
	// FrameData carries raw stream bytes.
	FrameData FrameType = 2
	// FrameClose ends a stream; an optional payload is an exit code.
	FrameClose FrameType = 3
	// FrameWindow grants the peer more bytes to send; payload is a uint32.
	FrameWindow FrameType = 4
)

const (
	// ControlStream is reserved for the phase-one request and reply channel.
	ControlStream uint32 = 0
	// HeaderSize is the fixed frame header length in bytes.
	HeaderSize = 8
	// MaxPayload is the largest single frame payload, bounded by the uint24
	// length field. A larger write is split across frames.
	MaxPayload = 1<<24 - 1
	// DefaultWindow is the initial number of bytes a peer may send on a new
	// stream before it must wait for a window grant.
	DefaultWindow = 64 * 1024
)

// ErrFrameTooLarge is returned when a payload exceeds the uint24 length field.
var ErrFrameTooLarge = errors.New("mux: frame payload exceeds 16 MiB")

// ErrSessionClosed is returned once the session has been torn down.
var ErrSessionClosed = errors.New("mux: session closed")

// Frame is one unit on the wire.
type Frame struct {
	StreamID uint32
	Type     FrameType
	Payload  []byte
}

// OpenPayload is the JSON body of a FrameOpen: what the new stream is for.
type OpenPayload struct {
	Kind string   `json:"kind"`
	Args []string `json:"args,omitempty"`
}

// WriteFrame encodes one frame to w. Header and payload go out in a single
// logical write from the caller's side; callers that share a writer must
// serialize their WriteFrame calls (Session does this with a mutex).
func WriteFrame(w io.Writer, f Frame) error {
	n := len(f.Payload)
	if n > MaxPayload {
		return ErrFrameTooLarge
	}
	var h [HeaderSize]byte
	binary.BigEndian.PutUint32(h[0:4], f.StreamID)
	h[4] = byte(f.Type)
	h[5] = byte(n >> 16)
	h[6] = byte(n >> 8)
	h[7] = byte(n)
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	if n > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame decodes one frame from r.
func ReadFrame(r io.Reader) (Frame, error) {
	var h [HeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	f := Frame{
		StreamID: binary.BigEndian.Uint32(h[0:4]),
		Type:     FrameType(h[4]),
	}
	n := int(h[5])<<16 | int(h[6])<<8 | int(h[7])
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// Session multiplexes streams over one connection. Create one on each end with
// NewSession, then Open streams (host side) and Accept them (device side).
type Session struct {
	conn io.ReadWriteCloser

	wmu sync.Mutex // serializes frame writes

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	step    uint32
	initWin int
	err     error
	closed  bool

	accept    chan *Stream
	closeOnce sync.Once
	done      chan struct{}
}

// NewSession wraps conn. The device side passes server=true so the two ends
// draw stream ids from disjoint sets (odd for the host, even for the device)
// and never collide when both open a stream at once.
func NewSession(conn io.ReadWriteCloser, server bool) *Session {
	s := &Session{
		conn:    conn,
		streams: make(map[uint32]*Stream),
		initWin: DefaultWindow,
		accept:  make(chan *Stream, 16),
		done:    make(chan struct{}),
	}
	if server {
		s.nextID = 2
	} else {
		s.nextID = 1
	}
	s.step = 2
	go s.readLoop()
	return s
}

// SetInitialWindow overrides the per-stream initial send window. It must be
// called before any stream is opened or accepted; it exists mainly so tests can
// exercise the flow-control path with a small window.
func (s *Session) SetInitialWindow(n int) {
	s.mu.Lock()
	s.initWin = n
	s.mu.Unlock()
}

// Open starts a new stream for the given kind and arguments.
func (s *Session) Open(kind string, args ...string) (*Stream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, s.errLocked()
	}
	id := s.nextID
	s.nextID += s.step
	st := s.newStreamLocked(id, kind, args)
	s.mu.Unlock()

	body, err := json.Marshal(OpenPayload{Kind: kind, Args: args})
	if err != nil {
		return nil, err
	}
	if err := s.writeFrame(Frame{StreamID: id, Type: FrameOpen, Payload: body}); err != nil {
		return nil, err
	}
	return st, nil
}

// Accept returns the next stream the peer opened, or an error once the session
// is closed.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.done:
		return nil, s.err0()
	}
}

// Close tears down the session and every stream on it.
func (s *Session) Close() error { return s.fail(ErrSessionClosed) }

func (s *Session) newStreamLocked(id uint32, kind string, args []string) *Stream {
	st := &Stream{
		id:     id,
		s:      s,
		kind:   kind,
		args:   args,
		window: s.initWin,
	}
	st.dataReady = sync.NewCond(&st.mu)
	st.winReady = sync.NewCond(&st.mu)
	s.streams[id] = st
	return st
}

func (s *Session) writeFrame(f Frame) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return WriteFrame(s.conn, f)
}

func (s *Session) readLoop() {
	for {
		f, err := ReadFrame(s.conn)
		if err != nil {
			s.fail(err)
			return
		}
		if err := s.dispatch(f); err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *Session) dispatch(f Frame) error {
	if f.StreamID == ControlStream {
		// The control channel is handled by the phase-one code path, not
		// here; a bare mux session drops it rather than guessing.
		return nil
	}
	if f.Type == FrameOpen {
		var op OpenPayload
		if err := json.Unmarshal(f.Payload, &op); err != nil {
			return fmt.Errorf("mux: bad open payload: %w", err)
		}
		s.mu.Lock()
		if _, exists := s.streams[f.StreamID]; exists {
			s.mu.Unlock()
			return fmt.Errorf("mux: open of in-use stream %d", f.StreamID)
		}
		st := s.newStreamLocked(f.StreamID, op.Kind, op.Args)
		s.mu.Unlock()
		select {
		case s.accept <- st:
		case <-s.done:
		}
		return nil
	}

	s.mu.Lock()
	st, ok := s.streams[f.StreamID]
	s.mu.Unlock()
	if !ok {
		// A frame for a stream that was never opened is a protocol error,
		// not something to ignore: it means the peer and we disagree about
		// what is open, and continuing would mix streams. Fail closed.
		return fmt.Errorf("mux: frame for unknown stream %d", f.StreamID)
	}

	switch f.Type {
	case FrameData:
		st.deliver(f.Payload)
	case FrameClose:
		code := 0
		if len(f.Payload) == 4 {
			code = int(int32(binary.BigEndian.Uint32(f.Payload)))
		}
		st.remoteClose(code)
	case FrameWindow:
		if len(f.Payload) != 4 {
			return fmt.Errorf("mux: window frame with %d byte payload", len(f.Payload))
		}
		st.grant(int(binary.BigEndian.Uint32(f.Payload)))
	default:
		return fmt.Errorf("mux: unknown frame type %d", f.Type)
	}
	return nil
}

func (s *Session) fail(err error) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.err == nil {
			s.err = err
		}
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.mu.Unlock()
		close(s.done)
		for _, st := range streams {
			st.remoteClose(0)
		}
		s.conn.Close()
	})
	return nil
}

func (s *Session) err0() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return ErrSessionClosed
}

func (s *Session) errLocked() error {
	if s.err != nil {
		return s.err
	}
	return ErrSessionClosed
}

// Stream is one byte stream on a Session. It is an io.ReadWriteCloser: Write
// sends DATA frames bounded by the peer's advertised window, Read returns bytes
// the peer sent and grants it more window as they are consumed, Close ends it.
type Stream struct {
	id   uint32
	s    *Session
	kind string
	args []string

	mu        sync.Mutex
	inbuf     bytes.Buffer
	dataReady *sync.Cond
	winReady  *sync.Cond
	window    int
	readEnd   bool // peer sent CLOSE
	writeEnd  bool // we sent CLOSE
	exitCode  int
	haveExit  bool
}

// Kind reports what the opener said the stream is for.
func (st *Stream) Kind() string { return st.kind }

// Args reports the opener's arguments.
func (st *Stream) Args() []string { return st.args }

// ExitCode reports the code the peer sent with its CLOSE, and whether one came.
func (st *Stream) ExitCode() (int, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.exitCode, st.haveExit
}

func (st *Stream) deliver(p []byte) {
	st.mu.Lock()
	st.inbuf.Write(p)
	st.dataReady.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) remoteClose(code int) {
	st.mu.Lock()
	st.readEnd = true
	if code != 0 {
		st.exitCode = code
	}
	st.haveExit = true
	st.dataReady.Broadcast()
	st.winReady.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) grant(n int) {
	st.mu.Lock()
	st.window += n
	st.winReady.Broadcast()
	st.mu.Unlock()
}

// Read implements io.Reader. It blocks until data arrives or the stream ends,
// and grants the peer window equal to what it hands back.
func (st *Stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	for st.inbuf.Len() == 0 {
		if st.readEnd {
			st.mu.Unlock()
			return 0, io.EOF
		}
		select {
		case <-st.s.done:
			st.mu.Unlock()
			return 0, st.s.err0()
		default:
		}
		st.dataReady.Wait()
	}
	n, _ := st.inbuf.Read(p)
	st.mu.Unlock()

	if n > 0 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		_ = st.s.writeFrame(Frame{StreamID: st.id, Type: FrameWindow, Payload: b[:]})
	}
	return n, nil
}

// Write implements io.Writer. It splits p across DATA frames, each bounded by
// the peer's remaining window and the max frame size, and blocks while the
// window is empty.
func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.mu.Lock()
		for st.window == 0 {
			if st.readEnd || st.writeEnd {
				st.mu.Unlock()
				return total, ErrSessionClosed
			}
			select {
			case <-st.s.done:
				st.mu.Unlock()
				return total, st.s.err0()
			default:
			}
			st.winReady.Wait()
		}
		k := len(p)
		if k > st.window {
			k = st.window
		}
		if k > MaxPayload {
			k = MaxPayload
		}
		st.window -= k
		st.mu.Unlock()

		chunk := make([]byte, k)
		copy(chunk, p[:k])
		if err := st.s.writeFrame(Frame{StreamID: st.id, Type: FrameData, Payload: chunk}); err != nil {
			return total, err
		}
		total += k
		p = p[k:]
	}
	return total, nil
}

// Close sends a CLOSE with exit code zero.
func (st *Stream) Close() error { return st.CloseWithCode(0) }

// CloseWithCode sends a CLOSE carrying an exit code, as a shell needs.
func (st *Stream) CloseWithCode(code int) error {
	st.mu.Lock()
	if st.writeEnd {
		st.mu.Unlock()
		return nil
	}
	st.writeEnd = true
	st.mu.Unlock()

	var payload []byte
	if code != 0 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(int32(code)))
		payload = b[:]
	}
	return st.s.writeFrame(Frame{StreamID: st.id, Type: FrameClose, Payload: payload})
}
