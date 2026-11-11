// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/singularityos-lab/sinty-sdb/internal/agentlink"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
)

func cmdAsk(args []string) int {
	fs := flag.NewFlagSet("sdb ask", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "sdb ask: <text...>")
		return 2
	}
	return runOnDevice(*dir, *addr, agentlink.AskArgs(fs.Args()))
}

func cmdMCP(args []string) int {
	fs := flag.NewFlagSet("sdb mcp", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return runOnDevice(*dir, *addr, agentlink.MCPArgs())
}

func runOnDevice(dir, addr string, open []string) int {
	sess, done, err := dialDevice(dir, addr)
	if err != nil {
		return fail(err)
	}
	defer done()
	st, err := sess.Open(shell.StreamKind, open...)
	if err != nil {
		return fail(err)
	}
	go func() {
		_, _ = io.Copy(st, os.Stdin)
		_ = st.Close()
	}()
	_, _ = io.Copy(os.Stdout, st)
	if code, ok := st.ExitCode(); ok {
		return code
	}
	return 0
}
