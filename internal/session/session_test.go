// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package session_test

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singularityos-lab/sinty-sdb/internal/assist"
	"github.com/singularityos-lab/sinty-sdb/internal/broker"
	"github.com/singularityos-lab/sinty-sdb/internal/forward"
	"github.com/singularityos-lab/sinty-sdb/internal/logs"
	"github.com/singularityos-lab/sinty-sdb/internal/mux"
	"github.com/singularityos-lab/sinty-sdb/internal/session"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
	"github.com/singularityos-lab/sinty-sdb/internal/transfer"
)

// mockBroker answers every elevation request with grant.
func mockBroker(t *testing.T, grant bool) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "broker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = bufio.NewReader(c).ReadBytes('\n')
				resp := `{"ok":false,"message":"denied"}`
				if grant {
					resp = `{"ok":true}`
				}
				_, _ = c.Write([]byte(resp + "\n"))
			}(conn)
		}
	}()
	return sock
}

func pushWithBroker(t *testing.T, grant bool) (target string, err error) {
	t.Helper()
	root := t.TempDir()
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	t.Cleanup(func() { client.Close() })
	go session.Serve(c2, session.Config{
		Root:      root,
		Broker:    broker.New(mockBroker(t, grant)),
		Origin:    "sdb:test",
		SessionID: "sess",
	})
	target = filepath.Join(t.TempDir(), "under", "system.conf")
	if e := os.MkdirAll(filepath.Dir(target), 0755); e != nil {
		t.Fatal(e)
	}
	local := filepath.Join(t.TempDir(), "src")
	if e := os.WriteFile(local, []byte("system payload"), 0600); e != nil {
		t.Fatal(e)
	}
	return target, transfer.Push(client, local, target)
}

func TestSessionShellRefusedWithoutBridgeUser(t *testing.T) {
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	t.Cleanup(func() { client.Close() })
	// No Elevation (no bridge user resolved) and no Broker: a non-root shell has
	// nothing safe to drop to, so it must be refused, never run as root.
	go session.Serve(c2, session.Config{Root: t.TempDir()})

	st, err := client.Open(shell.StreamKind, "id")
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	if _, err := io.ReadAll(st); err != nil {
		t.Fatalf("read: %v", err)
	}
	if code, ok := st.ExitCode(); !ok || code != 126 {
		t.Fatalf("shell without a bridge user closed (%d,%v), want (126,true)", code, ok)
	}
}

func TestSessionAssistRefusedWhenDenied(t *testing.T) {
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	t.Cleanup(func() { client.Close() })
	// Broker denies: the assistance tier must be refused, never run.
	go session.Serve(c2, session.Config{
		Broker: broker.New(mockBroker(t, false)),
		Access: shell.Access{Bridge: shell.Identity{UID: 990, GID: 990}},
	})
	st, err := client.Open(assist.StreamKind)
	if err != nil {
		t.Fatalf("open assist: %v", err)
	}
	_, _ = io.ReadAll(st)
	if code, ok := st.ExitCode(); !ok || code != 126 {
		t.Fatalf("denied assist closed (%d,%v), want (126,true)", code, ok)
	}
}

func TestSessionAssistRefusedWithoutBridge(t *testing.T) {
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	t.Cleanup(func() { client.Close() })
	// Broker grants, but there is no isolated bridge account to run the
	// assistant as, so it must still be refused rather than run as root.
	go session.Serve(c2, session.Config{Broker: broker.New(mockBroker(t, true))})
	st, err := client.Open(assist.StreamKind)
	if err != nil {
		t.Fatalf("open assist: %v", err)
	}
	_, _ = io.ReadAll(st)
	if code, ok := st.ExitCode(); !ok || code != 126 {
		t.Fatalf("assist without a bridge closed (%d,%v), want (126,true)", code, ok)
	}
}

func TestSessionWriteSystemGrantedWrites(t *testing.T) {
	target, err := pushWithBroker(t, true)
	if err != nil {
		t.Fatalf("granted system push failed: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "system payload" {
		t.Fatalf("target got %q, want %q", got, "system payload")
	}
}

func TestSessionWriteSystemDeniedRefused(t *testing.T) {
	target, err := pushWithBroker(t, false)
	if err == nil {
		t.Fatal("denied system push should fail")
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("a denied system write landed a file")
	}
}

// One connection, one dispatch: every phase-two command must reach its handler
// through session.Serve, or it is orphaned code that compiles but never runs.
func TestSessionDispatchesEveryKind(t *testing.T) {
	root := t.TempDir()
	c1, c2 := net.Pipe()
	client := mux.NewSession(c1, false)
	t.Cleanup(func() { client.Close() })
	logSrc := func(unit string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("log for " + unit)), nil
	}
	// A granting broker so the shell takes the elevated path (nil credential, no
	// setuid), which is the only shell path a non-root test process can run: a
	// real drop calls setgroups, which needs root and only works on the device.
	go session.Serve(c2, session.Config{
		Root:   root,
		Logs:   logSrc,
		Broker: broker.New(mockBroker(t, true)),
	})

	// shell (root path so it runs without a real setuid drop; see harness note)
	sh, err := client.Open(shell.StreamKind, shell.RootArg, "echo", "wired")
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	out, _ := io.ReadAll(sh)
	if string(out) != "wired\n" {
		t.Fatalf("shell got %q, want %q", out, "wired\n")
	}

	// push then pull
	content := []byte("dispatched through the session")
	local := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(local, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := transfer.Push(client, local, "f"); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "f")); !bytes.Equal(got, content) {
		t.Fatalf("push landed %q, want %q", got, content)
	}
	back := filepath.Join(t.TempDir(), "back")
	if err := transfer.Pull(client, "f", back); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got, _ := os.ReadFile(back); !bytes.Equal(got, content) {
		t.Fatalf("pull got %q, want %q", got, content)
	}

	// forward
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
		conn.Close()
	}()
	fw, err := forward.Dial(client, ln.Addr().String())
	if err != nil {
		t.Fatalf("open forward: %v", err)
	}
	if _, err := fw.Write([]byte("echo")); err != nil {
		t.Fatalf("forward write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(fw, buf); err != nil {
		t.Fatalf("forward read: %v", err)
	}
	if string(buf) != "echo" {
		t.Fatalf("forward got %q, want %q", buf, "echo")
	}
	_ = fw.Close()

	// logs
	lg, err := client.Open(logs.StreamKind, "sdbd")
	if err != nil {
		t.Fatalf("open logs: %v", err)
	}
	logOut, _ := io.ReadAll(lg)
	if string(logOut) != "log for sdbd" {
		t.Fatalf("logs got %q, want %q", logOut, "log for sdbd")
	}
}
