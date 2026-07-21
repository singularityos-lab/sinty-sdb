// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

//go:build linux && amd64

// Package assist is the SDB assistance tier: a bounded, non-root session for
// remote support that needs no rooting of the device. Its diagnostic tool is
// embedded in the signed daemon, materialized into RAM only for the duration of
// an authorized session (see internal/inmem), and run as the isolated bridge
// account, so it can read diagnostics without touching the owner's data, without
// root, and without leaving a privileged binary on the read-only disk. The
// authorization itself is the broker's, per action, with a remote origin.
package assist

import (
	_ "embed"
	"syscall"

	"github.com/singularityos-lab/sinty-sdb/internal/inmem"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

//go:generate sh -c "CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o probe.bin ./probe"

//go:embed probe.bin
var probe []byte

// StreamKind is the mux open-kind that routes to the assistance tier.
const StreamKind = "assist"

// Serve runs the embedded read-only diagnostic probe from RAM and streams its
// output to st. cred is the identity to run under (the isolated bridge account
// on the device; nil only in tests that cannot perform a real drop). The probe
// binary exists only in the anonymous in-memory file for the length of the run.
func Serve(st *mux.Stream, cred *syscall.Credential) error {
	cmd, cleanup, err := inmem.Command(probe, "sinty-assist-probe")
	if err != nil {
		_ = st.CloseWithCode(4)
		return err
	}
	defer cleanup()
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	cmd.Stdout = st
	cmd.Stderr = st
	if err := cmd.Run(); err != nil {
		_ = st.CloseWithCode(1)
		return err
	}
	return st.CloseWithCode(0)
}
