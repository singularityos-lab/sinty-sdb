// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package transfer

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

func TestConfinePathRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	if _, err := ConfinePath(root, "../../etc/passwd"); err != ErrOutsideRoot {
		t.Fatalf("traversal got %v, want ErrOutsideRoot", err)
	}
	got, err := ConfinePath(root, "a/b")
	if err != nil {
		t.Fatalf("legit path: %v", err)
	}
	if got != filepath.Join(root, "a/b") {
		t.Fatalf("got %q, want %q", got, filepath.Join(root, "a/b"))
	}
}

func TestConfinePathRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink("/etc", link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := ConfinePath(root, "escape"); err != ErrOutsideRoot {
		t.Fatalf("symlink got %v, want ErrOutsideRoot", err)
	}
}

func TestHashedRoundTripAndMismatch(t *testing.T) {
	var buf bytes.Buffer
	content := []byte("payload under integrity check")
	if err := writeHashed(&buf, content); err != nil {
		t.Fatalf("writeHashed: %v", err)
	}
	got, err := readHashed(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("readHashed: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("round trip got %q, want %q", got, content)
	}

	tampered := buf.Bytes()
	tampered[len(tampered)-1] ^= 0xff
	if _, err := readHashed(bytes.NewReader(tampered)); err != ErrHashMismatch {
		t.Fatalf("tampered got %v, want ErrHashMismatch", err)
	}
}

func serve(t *testing.T, root string) *mux.Session {
	t.Helper()
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	server := mux.NewSession(c2, true)
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		for {
			st, err := server.Accept()
			if err != nil {
				return
			}
			go func(st *mux.Stream) {
				switch st.Kind() {
				case KindPush:
					_ = ServePush(st, root)
				case KindPull:
					_ = ServePull(st, root)
				default:
					_ = st.Close()
				}
			}(st)
		}
	}()
	return client
}

func TestPushPullRoundTrip(t *testing.T) {
	root := t.TempDir()
	client := serve(t, root)

	content := []byte("the quick brown fox transfers a file")
	local := filepath.Join(t.TempDir(), "src.bin")
	if err := os.WriteFile(local, content, 0600); err != nil {
		t.Fatal(err)
	}

	if err := Push(client, local, "out.bin"); err != nil {
		t.Fatalf("Push: %v", err)
	}
	onDevice, err := os.ReadFile(filepath.Join(root, "out.bin"))
	if err != nil {
		t.Fatalf("device file: %v", err)
	}
	if !bytes.Equal(onDevice, content) {
		t.Fatalf("device got %q, want %q", onDevice, content)
	}

	back := filepath.Join(t.TempDir(), "back.bin")
	if err := Pull(client, "out.bin", back); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	got, err := os.ReadFile(back)
	if err != nil {
		t.Fatalf("pulled file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("pulled got %q, want %q", got, content)
	}
}

// systemPush runs ServePushSystem(target) on the device side and returns the
// client's opened stream after writing hashed content and closing it.
func systemPush(t *testing.T, target string, content []byte) *mux.Stream {
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
		_ = ServePushSystem(st, target)
	}()
	st, err := client.Open(KindPush, target)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := writeHashed(st, content); err != nil {
		t.Fatalf("writeHashed: %v", err)
	}
	_ = st.Close()
	_, _ = io.ReadAll(st)
	return st
}

func TestServePushSystemWrites(t *testing.T) {
	target := filepath.Join(t.TempDir(), "sub", "sys.conf")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	content := []byte("an approved system write")
	st := systemPush(t, target, content)
	if code, ok := st.ExitCode(); !ok || code != 0 {
		t.Fatalf("exit (%d,%v), want (0,true)", code, ok)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("target got %q err %v, want %q", got, err, content)
	}
}

func TestServePushSystemRefusesSymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	target := filepath.Join(link, "f")
	st := systemPush(t, target, []byte("x"))
	if code, _ := st.ExitCode(); code != 2 {
		t.Fatalf("symlinked parent exit code %d, want 2", code)
	}
	if _, err := os.Stat(filepath.Join(real, "f")); err == nil {
		t.Fatal("write landed through a symlinked parent")
	}
}

func TestServePushSystemRefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "flink")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), target); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	st := systemPush(t, target, []byte("x"))
	if code, _ := st.ExitCode(); code != 3 {
		t.Fatalf("symlink target exit code %d, want 3", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "elsewhere")); err == nil {
		t.Fatal("write followed a symlink target")
	}
}

func TestPushTraversalDenied(t *testing.T) {
	root := t.TempDir()
	client := serve(t, root)

	local := filepath.Join(t.TempDir(), "src.bin")
	if err := os.WriteFile(local, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Push(client, local, "../escape.bin"); err == nil {
		t.Fatal("push outside root should be refused")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.bin")); err == nil {
		t.Fatal("a file escaped the root")
	}
}
