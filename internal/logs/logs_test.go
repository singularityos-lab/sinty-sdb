// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package logs_test

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/singularityos-lab/sinty-sdb/internal/logs"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// open dials a client and device mux pair and serves one logs stream with the
// given source, returning the client's opened stream.
func open(t *testing.T, src logs.Source, unit string) *mux.Stream {
	t.Helper()
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	server := mux.NewSession(c2, true)
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		_ = logs.Serve(st, src)
	}()
	st, err := client.Open(logs.StreamKind, unit)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st
}

func TestLogsStreamsSource(t *testing.T) {
	src := func(unit string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("lines for " + unit)), nil
	}
	st := open(t, src, "netd")
	out, _ := io.ReadAll(st)
	if string(out) != "lines for netd" {
		t.Fatalf("got %q, want %q", out, "lines for netd")
	}
	if code, ok := st.ExitCode(); !ok || code != 0 {
		t.Fatalf("exit (%d,%v), want (0,true)", code, ok)
	}
}

func TestLogsNilSourceRefused(t *testing.T) {
	st := open(t, nil, "x")
	_, _ = io.ReadAll(st)
	if code, ok := st.ExitCode(); !ok || code != 2 {
		t.Fatalf("nil source exit (%d,%v), want (2,true)", code, ok)
	}
}

func TestLogsSourceErrorReported(t *testing.T) {
	src := func(string) (io.ReadCloser, error) { return nil, errors.New("no such unit") }
	st := open(t, src, "ghost")
	_, _ = io.ReadAll(st)
	if code, ok := st.ExitCode(); !ok || code != 4 {
		t.Fatalf("source error exit (%d,%v), want (4,true)", code, ok)
	}
}
