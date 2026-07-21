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

	"github.com/singularityos-lab/sinty-sdb/internal/broker"
	"github.com/singularityos-lab/sinty-sdb/internal/forward"
	"github.com/singularityos-lab/sinty-sdb/internal/logs"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
	"github.com/singularityos-lab/sinty-sdb/internal/transfer"
)

// Config carries what the stream handlers need: the root that confines file
// transfers, the source that log streams read from, and the elevation context
// for a root shell. A nil Logs source refuses log streams; a nil Broker means
// no root can be granted, so every shell drops to the bridge user.
type Config struct {
	Root      string
	Logs      logs.Source
	Elevation shell.Elevation
	Broker    *broker.Client
	Origin    string
	SessionID string
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
		serveShell(st, cfg)
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

// serveShell decides the credential a shell runs under. A leading RootArg is a
// request for root, which is granted only if the broker approves it; otherwise
// the shell drops to the bridge user. Fail-closed: no broker, a refused broker,
// or any broker error all leave the shell unprivileged.
func serveShell(st *mux.Stream, cfg Config) {
	args := st.Args()
	rootRequested := len(args) > 0 && args[0] == shell.RootArg
	if rootRequested {
		args = args[1:]
	}
	granted := false
	if rootRequested && cfg.Broker != nil {
		granted, _ = cfg.Broker.Elevate(broker.ActionShellRoot, "", cfg.Origin, cfg.SessionID)
	}
	cred, _ := cfg.Elevation.Credential(rootRequested, granted)
	_, _ = shell.Serve(st, args, cred)
}
