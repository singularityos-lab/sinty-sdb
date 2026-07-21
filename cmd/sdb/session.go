// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/singularityos-lab/sinty-sdb/internal/client"
	"github.com/singularityos-lab/sinty-sdb/internal/forward"
	"github.com/singularityos-lab/sinty-sdb/internal/keys"
	"github.com/singularityos-lab/sinty-sdb/internal/logs"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
	"github.com/singularityos-lab/sinty-sdb/internal/rforward"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
	"github.com/singularityos-lab/sinty-sdb/internal/transfer"
)

// dialDevice resolves the target device (the only paired one, or the one at
// addr) and opens a phase-two session to it.
func dialDevice(dir, addr string) (*mux.Session, func(), error) {
	cfg, err := configDir(dir)
	if err != nil {
		return nil, nil, err
	}
	known, err := client.OpenKnown(filepath.Join(cfg, "devices.json"))
	if err != nil {
		return nil, nil, err
	}
	var target client.Device
	if addr == "" {
		target, err = known.Only()
	} else {
		target, err = known.Lookup(addr)
	}
	if err != nil {
		return nil, nil, err
	}
	id, err := keys.LoadOrCreate(cfg, "host")
	if err != nil {
		return nil, nil, err
	}
	conn, err := client.New(id).Dial(target.Address, target.Fingerprint)
	if err != nil {
		return nil, nil, err
	}
	sess, err := client.OpenSession(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return sess, func() { sess.Close(); conn.Close() }, nil
}

func cmdShell(args []string) int {
	fs := flag.NewFlagSet("sdb shell", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	root := fs.Bool("root", false, "request a root shell (the device asks for confirmation)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sess, done, err := dialDevice(*dir, *addr)
	if err != nil {
		return fail(err)
	}
	defer done()

	open := fs.Args()
	if *root {
		open = append([]string{shell.RootArg}, open...)
	}
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

func cmdPush(args []string) int {
	fs := flag.NewFlagSet("sdb push", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "sdb push: <local> <remote>")
		return 2
	}
	sess, done, err := dialDevice(*dir, *addr)
	if err != nil {
		return fail(err)
	}
	defer done()
	if err := transfer.Push(sess, fs.Arg(0), fs.Arg(1)); err != nil {
		return fail(err)
	}
	fmt.Printf("Pushed %s -> %s\n", fs.Arg(0), fs.Arg(1))
	return 0
}

func cmdPull(args []string) int {
	fs := flag.NewFlagSet("sdb pull", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "sdb pull: <remote> <local>")
		return 2
	}
	sess, done, err := dialDevice(*dir, *addr)
	if err != nil {
		return fail(err)
	}
	defer done()
	if err := transfer.Pull(sess, fs.Arg(0), fs.Arg(1)); err != nil {
		return fail(err)
	}
	fmt.Printf("Pulled %s -> %s\n", fs.Arg(0), fs.Arg(1))
	return 0
}

func cmdLogs(args []string) int {
	fs := flag.NewFlagSet("sdb logs", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sess, done, err := dialDevice(*dir, *addr)
	if err != nil {
		return fail(err)
	}
	defer done()

	unit := ""
	if fs.NArg() > 0 {
		unit = fs.Arg(0)
	}
	st, err := sess.Open(logs.StreamKind, unit)
	if err != nil {
		return fail(err)
	}
	_, _ = io.Copy(os.Stdout, st)
	return 0
}

func cmdForward(args []string) int {
	fs := flag.NewFlagSet("sdb forward", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	reverse := fs.Bool("R", false, "reverse: the device binds and tunnels to a host address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		if *reverse {
			fmt.Fprintln(os.Stderr, "sdb forward -R: <device-bind-addr> <host-target>")
		} else {
			fmt.Fprintln(os.Stderr, "sdb forward: <local-addr> <device-addr>")
		}
		return 2
	}
	sess, done, err := dialDevice(*dir, *addr)
	if err != nil {
		return fail(err)
	}
	defer done()

	if *reverse {
		return forwardReverse(sess, fs.Arg(0), fs.Arg(1))
	}
	local, remote := fs.Arg(0), fs.Arg(1)

	ln, err := net.Listen("tcp", local)
	if err != nil {
		return fail(err)
	}
	defer ln.Close()
	fmt.Printf("Forwarding %s -> device %s (Ctrl-C to stop)\n", local, remote)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return 0
		}
		go func(conn net.Conn) {
			defer conn.Close()
			st, err := forward.Dial(sess, remote)
			if err != nil {
				return
			}
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(st, conn); done <- struct{}{} }()
			go func() { _, _ = io.Copy(conn, st); done <- struct{}{} }()
			<-done
			_ = st.Close()
		}(conn)
	}
}

// forwardReverse asks the device to bind deviceBind and tunnel every connection
// to hostTarget, which this host dials. It runs until interrupted.
func forwardReverse(sess *mux.Session, deviceBind, hostTarget string) int {
	ctrl, err := sess.Open(rforward.KindListen, deviceBind, hostTarget)
	if err != nil {
		return fail(err)
	}
	bound, err := rforward.ReadBoundAddr(ctrl)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Device listening on %s -> %s (Ctrl-C to stop)\n", bound, hostTarget)
	for {
		st, err := sess.Accept()
		if err != nil {
			return 0
		}
		if st.Kind() == rforward.KindConn {
			go rforward.HandleConn(st)
		}
	}
}

// assistKind is the mux open-kind for the assistance tier. It is duplicated as a
// literal here rather than imported from internal/assist so the host CLI stays
// free of that package's embedded device probe and its arch build tag.
const assistKind = "assist"

func cmdAssist(args []string) int {
	fs := flag.NewFlagSet("sdb assist", flag.ContinueOnError)
	dir := fs.String("config-dir", "", "override the configuration directory")
	addr := fs.String("addr", "", "device to act on (needed when several are paired)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sess, done, err := dialDevice(*dir, *addr)
	if err != nil {
		return fail(err)
	}
	defer done()

	st, err := sess.Open(assistKind)
	if err != nil {
		return fail(err)
	}
	_, _ = io.Copy(os.Stdout, st)
	if code, ok := st.ExitCode(); ok {
		return code
	}
	return 0
}
