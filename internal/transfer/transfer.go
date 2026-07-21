// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package transfer moves files over a mux stream for "sdb push" and "sdb pull".
// Two rules hold regardless of direction. First, every path is confined to a
// root: a request that resolves outside it, whether by a ".." in the text or by
// a symlink, is refused, because a write that escapes the root is an attack, not
// a convenience. Second, the receiver verifies a SHA-256 the sender prepends to
// the content, so a truncated or altered transfer fails loudly instead of
// landing a corrupt file. Writing outside the bridge user's own tree is a
// privileged action mediated by the ush broker, exactly like every other
// privileged path; this package carries the bytes and the checks, not the
// privilege.
package transfer

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

// Stream kinds routed to this package.
const (
	KindPush = "push" // host writes a file to the device
	KindPull = "pull" // host reads a file from the device
)

const hashLen = sha256.Size

// ErrOutsideRoot is returned when a requested path escapes its root.
var ErrOutsideRoot = errors.New("transfer: path escapes its root")

// ErrHashMismatch is returned when received content does not match the SHA-256
// the sender prepended.
var ErrHashMismatch = errors.New("transfer: content hash mismatch")

// ConfinePath resolves rel under root and returns the absolute path only if it
// stays inside root. It rejects textual traversal by anchoring the cleaned path
// at the root, rejects a symlinked parent directory by resolving it, and rejects
// a final component that is itself a symlink.
func ConfinePath(root, rel string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	// filepath.Join cleans the result, so a ".." that walks out of the root
	// leaves the prefix and is rejected rather than silently remapped.
	full := filepath.Join(rootAbs, rel)
	if full != rootAbs && !strings.HasPrefix(full, rootAbs+string(os.PathSeparator)) {
		return "", ErrOutsideRoot
	}

	// A symlinked parent directory could point out of the root even though
	// the textual path is clean. Resolve the parent (it must exist) and check
	// again.
	parent := filepath.Dir(full)
	if resolved, err := filepath.EvalSymlinks(parent); err == nil {
		if resolved != rootAbs && !strings.HasPrefix(resolved, rootAbs+string(os.PathSeparator)) {
			return "", ErrOutsideRoot
		}
	}

	// The final component must not be a symlink: following it on write could
	// place bytes outside the root. lstat, never stat.
	if fi, err := os.Lstat(full); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", ErrOutsideRoot
		}
	}
	return full, nil
}

// writeHashed prepends the SHA-256 of data, then writes data.
func writeHashed(w io.Writer, data []byte) error {
	sum := sha256.Sum256(data)
	if _, err := w.Write(sum[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// readHashed reads the 32-byte hash prefix and the content that follows, then
// verifies the content against the hash.
func readHashed(r io.Reader) ([]byte, error) {
	var want [hashLen]byte
	if _, err := io.ReadFull(r, want[:]); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return nil, ErrHashMismatch
	}
	return data, nil
}

// ServePush handles a push stream on the device: it confines the requested path
// under root, reads hashed content from the stream, verifies it, and writes the
// file. The stream closes with 0 on success or a non-zero code on failure.
func ServePush(st *mux.Stream, root string) error {
	if len(st.Args()) < 1 {
		_ = st.CloseWithCode(2)
		return errors.New("transfer: push without a path")
	}
	dst, err := ConfinePath(root, st.Args()[0])
	if err != nil {
		_ = st.CloseWithCode(2)
		return err
	}
	data, err := readHashed(st)
	if err != nil {
		_ = st.CloseWithCode(1)
		return err
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		_ = st.CloseWithCode(3)
		return err
	}
	return st.CloseWithCode(0)
}

// ServePull handles a pull stream on the device: it confines the requested path,
// reads the file, and writes hashed content to the stream.
func ServePull(st *mux.Stream, root string) error {
	if len(st.Args()) < 1 {
		_ = st.CloseWithCode(2)
		return errors.New("transfer: pull without a path")
	}
	src, err := ConfinePath(root, st.Args()[0])
	if err != nil {
		_ = st.CloseWithCode(2)
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		_ = st.CloseWithCode(4)
		return err
	}
	if err := writeHashed(st, data); err != nil {
		return err
	}
	return st.CloseWithCode(0)
}

// Push opens a push stream and sends the local file's bytes under remote.
func Push(sess *mux.Session, localPath, remote string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	st, err := sess.Open(KindPush, remote)
	if err != nil {
		return err
	}
	if err := writeHashed(st, data); err != nil {
		return err
	}
	if err := st.Close(); err != nil {
		return err
	}
	if _, err := io.ReadAll(st); err != nil {
		return err
	}
	if code, ok := st.ExitCode(); ok && code != 0 {
		return fmt.Errorf("transfer: device refused push (code %d)", code)
	}
	return nil
}

// Pull opens a pull stream, receives hashed content and writes it to localPath.
func Pull(sess *mux.Session, remote, localPath string) error {
	st, err := sess.Open(KindPull, remote)
	if err != nil {
		return err
	}
	data, err := readHashed(st)
	if err != nil {
		return err
	}
	if code, ok := st.ExitCode(); ok && code != 0 {
		return fmt.Errorf("transfer: device refused pull (code %d)", code)
	}
	return os.WriteFile(localPath, data, 0600)
}
