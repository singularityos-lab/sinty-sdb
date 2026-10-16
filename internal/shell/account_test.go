// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type pipeStream struct {
	mu  sync.Mutex
	out bytes.Buffer
}

func newPipeStream() *pipeStream { return &pipeStream{} }

func (p *pipeStream) Read([]byte) (int, error) { return 0, io.EOF }

func (p *pipeStream) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.Write(b)
}

func (p *pipeStream) CloseWithCode(int) error { return nil }

func TestLookupAccountReadsHomeAndShell(t *testing.T) {
	passwd := filepath.Join(t.TempDir(), "passwd")
	data := "root:x:0:0:root:/root:/bin/sh\nprova:x:1001:1002:Prova Test:/var/home/prova:/usr/bin/ush\n"
	if err := os.WriteFile(passwd, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	a, ok := lookupAccount(passwd, 1001)
	if !ok || a.name != "prova" || a.home != "/var/home/prova" || a.shell != "/usr/bin/ush" {
		t.Fatalf("got %+v ok=%v", a, ok)
	}
	if _, ok := lookupAccount(passwd, 4242); ok {
		t.Fatal("an unknown uid must not resolve")
	}
}

func TestPtyArgRoundTrip(t *testing.T) {
	s := Size{Cols: 132, Rows: 43}
	got, ok := ParsePtyArg(s.Arg())
	if !ok || got != s {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	for _, bad := range []string{"--sdb-pty=", "--sdb-pty=80", "--sdb-pty=0x24", "--sdb-pty=80x99999", "ls"} {
		if _, ok := ParsePtyArg(bad); ok {
			t.Fatalf("%q must not parse", bad)
		}
	}
}

func TestServePTYRunsInHome(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no pty support")
	}
	st := newPipeStream()
	done := make(chan int, 1)
	go func() {
		code, _ := ServePTY(st, []string{"/bin/sh", "-c", "test -t 0 && pwd"}, nil, Size{Cols: 80, Rows: 24})
		done <- code
	}()
	code := <-done
	home, _ := os.UserHomeDir()
	if code != 0 || !strings.Contains(st.out.String(), "/") {
		t.Fatalf("exit %d, output %q (home %s)", code, st.out.String(), home)
	}
}
