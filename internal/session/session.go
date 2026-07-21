// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package session serves phase-two streams on a connection the daemon has
// already authenticated and paired. It is the one place that routes an accepted
// mux stream to its handler by kind, so shell, file transfer, tunnelling and
// log streaming all reach the wire through a single dispatch rather than each
// wiring itself in. Everything here runs as the daemon's own user and is
// confined; privilege is the broker's job, never this package's.
package session

import (
	"io"

	"github.com/singularityos-lab/sinty-sdb/internal/forward"
	"github.com/singularityos-lab/sinty-sdb/internal/logs"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
	"github.com/singularityos-lab/sinty-sdb/internal/transfer"
)

// Config carries what the stream handlers need: the root that confines file
// transfers, and the source that log streams read from. A nil Logs source
// refuses log streams rather than inventing one.
type Config struct {
	Root string
	Logs logs.Source
}

// Serve upgrades conn to a mux session and dispatches every stream the peer
// opens until the session ends.
func Serve(conn io.ReadWriteCloser, cfg Config) {
	s := mux.NewSession(conn, true)
	for {
		st, err := s.Accept()
		if err != nil {
			return
		}
		go dispatch(st, cfg)
	}
}

func dispatch(st *mux.Stream, cfg Config) {
	switch st.Kind() {
	case shell.StreamKind:
		_, _ = shell.ServeStream(st)
	case transfer.KindPush:
		_ = transfer.ServePush(st, cfg.Root)
	case transfer.KindPull:
		_ = transfer.ServePull(st, cfg.Root)
	case forward.KindForward:
		_ = forward.ServeForward(st)
	case logs.StreamKind:
		_ = logs.Serve(st, cfg.Logs)
	default:
		_ = st.CloseWithCode(2)
	}
}
