// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package session serves phase-two streams on a connection the daemon has
// already authenticated and paired. It is the one place that routes an accepted
// mux stream to its handler by kind, so shell, file transfer and tunnelling all
// reach the wire through a single dispatch rather than each wiring itself in.
// Everything here runs as the daemon's own user and is confined to root;
// privilege is the broker's job, never this package's.
package session

import (
	"io"

	"github.com/singularityos-lab/sinty-sdb/internal/forward"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
	"github.com/singularityos-lab/sinty-sdb/internal/transfer"
)

// Serve upgrades conn to a mux session and dispatches every stream the peer
// opens until the session ends. root confines file transfers.
func Serve(conn io.ReadWriteCloser, root string) {
	s := mux.NewSession(conn, true)
	for {
		st, err := s.Accept()
		if err != nil {
			return
		}
		go dispatch(st, root)
	}
}

func dispatch(st *mux.Stream, root string) {
	switch st.Kind() {
	case shell.StreamKind:
		_, _ = shell.ServeStream(st)
	case transfer.KindPush:
		_ = transfer.ServePush(st, root)
	case transfer.KindPull:
		_ = transfer.ServePull(st, root)
	case forward.KindForward:
		_ = forward.ServeForward(st)
	default:
		_ = st.CloseWithCode(2)
	}
}
