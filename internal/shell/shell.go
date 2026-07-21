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
	"syscall"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// StreamKind is the mux open-kind that routes to this package.
const StreamKind = "shell"

// RootArg is the first argument a host sends to ask for a root shell. sdbd runs
// as root, so a shell without this runs dropped to the bridge user; with it, the
// broker must grant before the drop is skipped.
const RootArg = "--sdb-root"

// Identity is an OS account to run a shell under. A zero UID means "not
// resolved" and is never used to drop (that would leave the shell as root).
type Identity struct {
	UID uint32
	GID uint32
}

// Access carries the identities a shell can run at: the logged-in user (the
// default) and the isolated bridge account (the fallback when no one is logged
// in, and the identity used for remote assistance). Whether root is allowed at
// all is enforced by the broker, which denies the root grant on a locked
// (not-rooted) device before ever prompting; sdbd holds no lock-state logic.
type Access struct {
	Login  Identity // the logged-in user (tier 1, default)
	Bridge Identity // isolated unprivileged account (fallback and assistance)
}

// Resolve decides which credential a shell runs under. rootRequested is whether
// the host asked for --root; rootGranted is whether the broker allowed it (the
// broker having already refused it on a non-rooted device). The rules are
// fail-closed:
//   - root (nil credential) only with a broker grant;
//   - otherwise the logged-in user;
//   - otherwise the isolated bridge account;
//   - otherwise refuse (ok=false), never silently run as the daemon's root.
func (a Access) Resolve(rootRequested, rootGranted bool) (cred *syscall.Credential, tier string, ok bool) {
	if rootRequested && rootGranted {
		return nil, "root", true
	}
	if a.Login.UID != 0 {
		return &syscall.Credential{Uid: a.Login.UID, Gid: a.Login.GID}, "user", true
	}
	if a.Bridge.UID != 0 {
		return &syscall.Credential{Uid: a.Bridge.UID, Gid: a.Bridge.GID}, "bridge", true
	}
	return nil, "", false
}

// closer is the subset of mux.Stream this package needs, so the exit code can
// travel back to the host in the CLOSE frame.
type closer interface {
	io.ReadWriter
	CloseWithCode(code int) error
}

// Serve runs the command named by args (or a plain shell when args is empty),
// streaming stdin from st and stdout and stderr to st, then closes st with the
// command's exit code. When cred is non-nil the command runs under that OS
// credential, which is how a non-root shell drops from sdbd's root to the
// bridge user. It returns the exit code and any error starting the command.
func Serve(st closer, args []string, cred *syscall.Credential) (int, error) {
	cmd := command(args)
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
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

// ServeStream adapts a *mux.Stream to Serve with no credential, running as the
// daemon's own user. Callers that must drop to the bridge user or that gate a
// root request through the broker use Serve directly with the credential from
// Elevation.Credential.
func ServeStream(st *mux.Stream) (int, error) {
	return Serve(st, st.Args(), nil)
}
