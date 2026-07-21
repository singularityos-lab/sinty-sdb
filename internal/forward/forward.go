// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package forward tunnels a TCP connection over a mux stream for "sdb forward".
// The host opens a stream naming a device-side address; the device dials it and
// copies bytes both ways. A privileged port (below 1024) is refused here and
// left to the ush broker, so binding a low port is a mediated action rather than
// something the bridge grants itself. The tunnel inherits the connection's
// authentication: only the paired host can drive it.
package forward

import (
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// KindForward is the mux open-kind for a tunnel.
const KindForward = "forward"

// DialTimeout bounds the device-side dial of the target address.
const DialTimeout = 5 * time.Second

// ErrPrivilegedPort is returned when the target port is below 1024, which must
// go through the broker rather than the bridge.
var ErrPrivilegedPort = errors.New("forward: privileged port requires broker mediation")

// Dial opens a tunnel stream to a device-side address of the form host:port.
func Dial(sess *mux.Session, target string) (*mux.Stream, error) {
	return sess.Open(KindForward, target)
}

// ServeForward handles a tunnel stream on the device: it dials the requested
// address and copies bytes between the stream and that connection until either
// end closes.
func ServeForward(st *mux.Stream) error {
	if len(st.Args()) < 1 {
		_ = st.CloseWithCode(2)
		return errors.New("forward: no target address")
	}
	target := st.Args()[0]
	if privileged(target) {
		_ = st.CloseWithCode(5)
		return ErrPrivilegedPort
	}
	conn, err := net.DialTimeout("tcp", target, DialTimeout)
	if err != nil {
		_ = st.CloseWithCode(6)
		return err
	}
	defer conn.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, st)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(st, conn)
		done <- struct{}{}
	}()
	<-done
	_ = st.Close()
	return nil
}

// privileged reports whether target names a port below 1024.
func privileged(target string) bool {
	_, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port > 0 && port < 1024
}
