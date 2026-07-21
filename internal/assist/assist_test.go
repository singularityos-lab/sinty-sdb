// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

//go:build linux && amd64

package assist_test

import (
	"io"
	"net"
	"strings"
	"testing"

	"github.com/singularityos-lab/sinty-sdb/internal/assist"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// The embedded probe runs from RAM and streams its diagnostics back. A nil
// credential is used because a test process cannot perform the real drop to the
// bridge account; the device does that. This proves the embedded-tool path end
// to end: bytes in the daemon, materialized in memory, executed, output on the
// stream.
func TestServeRunsProbeFromRAM(t *testing.T) {
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	server := mux.NewSession(c2, true)
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		_ = assist.Serve(st, nil)
	}()

	st, err := client.Open(assist.StreamKind)
	if err != nil {
		t.Fatalf("open assist: %v", err)
	}
	out, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(out), "assist-probe") {
		t.Fatalf("probe output %q does not look like the diagnostic tool", out)
	}
	if code, ok := st.ExitCode(); !ok || code != 0 {
		t.Fatalf("exit (%d,%v), want (0,true)", code, ok)
	}
}
