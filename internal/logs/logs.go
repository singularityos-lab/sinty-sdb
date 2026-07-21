// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package logs streams a log source to an "sdb logs" stream. It is read-only:
// it never writes, and it holds no privilege. The source is supplied by the
// daemon, so what a unit name resolves to (a bridge-user file now, sinit's
// per-unit registry later) is decided where the privilege context is known.
// Reading system logs, which can hold sensitive lines, is a privileged action
// mediated by the broker; this package carries bytes, not the decision to allow
// them.
package logs

import (
	"io"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// StreamKind is the mux open-kind for a log stream.
const StreamKind = "logs"

// Source resolves a unit name (empty for the whole system) to a readable,
// closable log stream. It is provided by the daemon.
type Source func(unit string) (io.ReadCloser, error)

// Serve streams the resolved source to st and closes it. The first argument, if
// present, names a unit.
func Serve(st *mux.Stream, src Source) error {
	if src == nil {
		_ = st.CloseWithCode(2)
		return nil
	}
	unit := ""
	if len(st.Args()) > 0 {
		unit = st.Args()[0]
	}
	rc, err := src(unit)
	if err != nil {
		_ = st.CloseWithCode(4)
		return err
	}
	defer rc.Close()
	if _, err := io.Copy(st, rc); err != nil {
		return err
	}
	return st.CloseWithCode(0)
}
