// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package rforward is reverse tunnelling for "sdb forward -R": the device binds
// a listener and every connection to it is carried back to the host, which
// dials a host-side address. It leans on the mux being symmetric, so the device
// opens streams to the host for each accepted connection. Binding a privileged
// port on the device is mediated by the broker, like every other privileged
// action; an unprivileged port binds directly.
package rforward

import (
	"bufio"
	"io"
	"net"
	"strconv"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// Stream kinds. KindListen is host->device asking it to bind; KindConn is
// device->host, one per accepted connection, carrying the host target to dial.
const (
	KindListen = "rforward-listen"
	KindConn   = "rforward-conn"
)

// PrivilegedPort reports whether a bind address names a port below 1024.
func PrivilegedPort(bindAddr string) bool {
	_, portStr, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	return err == nil && port > 0 && port < 1024
}

// Listen runs the device side of a reverse tunnel. st is the control stream the
// host opened with args [bindAddr, hostTarget]. gate is consulted before binding
// a privileged port and must return true to allow it. The bound address is sent
// back on st as a newline-terminated line so the host learns the real port when
// it asked for :0. Each accepted connection opens a KindConn stream to the host
// carrying hostTarget, and is piped to it until either side closes.
func Listen(sess *mux.Session, st *mux.Stream, gate func() bool) error {
	args := st.Args()
	if len(args) < 2 {
		_ = st.CloseWithCode(2)
		return nil
	}
	bindAddr, hostTarget := args[0], args[1]
	if PrivilegedPort(bindAddr) && (gate == nil || !gate()) {
		_ = st.CloseWithCode(5)
		return nil
	}
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		_ = st.CloseWithCode(6)
		return err
	}
	defer ln.Close()

	if _, err := io.WriteString(st, ln.Addr().String()+"\n"); err != nil {
		return err
	}

	// Closing the control stream stops the listener.
	go func() {
		_, _ = io.Copy(io.Discard, st)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil
		}
		go func(conn net.Conn) {
			defer conn.Close()
			cs, err := sess.Open(KindConn, hostTarget)
			if err != nil {
				return
			}
			pipe(cs, conn)
			_ = cs.Close()
		}(conn)
	}
}

// HandleConn runs the host side of one reverse connection: it dials the host
// target named in the stream's args and pipes bytes both ways.
func HandleConn(st *mux.Stream) {
	if len(st.Args()) < 1 {
		_ = st.CloseWithCode(2)
		return
	}
	conn, err := net.Dial("tcp", st.Args()[0])
	if err != nil {
		_ = st.CloseWithCode(6)
		return
	}
	defer conn.Close()
	pipe(st, conn)
	_ = st.Close()
}

// ReadBoundAddr reads the device's reported listen address from the control
// stream. The host calls it right after opening the KindListen stream.
func ReadBoundAddr(st *mux.Stream) (string, error) {
	line, err := bufio.NewReader(st).ReadString('\n')
	if err != nil {
		return "", err
	}
	return line[:len(line)-1], nil
}

// pipe copies bytes both ways between a stream and a connection until either end
// closes.
func pipe(st io.ReadWriter, conn net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, st); done <- struct{}{} }()
	go func() { _, _ = io.Copy(st, conn); done <- struct{}{} }()
	<-done
}
