// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package shell runs a command for an "sdb shell" stream and wires its standard
// input, output and error to that stream. It runs the command as the daemon's
// own user, never elevated: a root shell or any privileged action is mediated
// by the ush broker per action, exactly as every other privileged path is, so
// sdbd holds no privilege of its own. Without arguments it starts a plain
// non-login shell reading from the stream; a fully interactive pty is a
// follow-up that needs a pty dependency and is deliberately not pulled in here.
package shell

import (
	"io"
	"os"
	"os/exec"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// StreamKind is the mux open-kind that routes to this package.
const StreamKind = "shell"

// closer is the subset of mux.Stream this package needs, so the exit code can
// travel back to the host in the CLOSE frame.
type closer interface {
	io.ReadWriter
	CloseWithCode(code int) error
}

// Serve runs the command named by args (or a plain shell when args is empty),
// streaming stdin from st and stdout and stderr to st, then closes st with the
// command's exit code. It returns the exit code and any error starting the
// command.
func Serve(st closer, args []string) (int, error) {
	cmd := command(args)
	cmd.Stdout = st
	cmd.Stderr = st

	// Drive stdin ourselves rather than assigning cmd.Stdin = st: when Stdin
	// is a plain io.Reader, exec.Wait blocks on its internal stdin copier,
	// which never returns for a command (like echo) that exits without the
	// host ever closing its write half. With an explicit pipe, Wait returns
	// on process exit and the copier is free to end when the stream closes.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = st.CloseWithCode(127)
		return 127, err
	}
	go func() {
		_, _ = io.Copy(stdin, st)
		_ = stdin.Close()
	}()

	if err := cmd.Start(); err != nil {
		_ = st.CloseWithCode(127)
		return 127, err
	}
	err = cmd.Wait()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			code = 1
		}
	}
	_ = st.CloseWithCode(code)
	return code, nil
}

func command(args []string) *exec.Cmd {
	if len(args) == 0 {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		return exec.Command(shell)
	}
	return exec.Command(args[0], args[1:]...)
}

// ServeStream adapts a *mux.Stream to Serve, reading the command from the
// stream's open arguments. It is what the daemon calls for an accepted stream
// whose kind is StreamKind.
func ServeStream(st *mux.Stream) (int, error) {
	return Serve(st, st.Args())
}
