// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package daemon

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/client"
)

func fakeProc(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"uptime":          "3725.40 100.00\n",
		"loadavg":         "9.50 7.25 4.00 3/812 9999\n",
		"meminfo":         "MemTotal:        3700000 kB\nMemFree:           20000 kB\nMemAvailable:      51200 kB\nSwapTotal:       3700000 kB\nSwapFree:        1652000 kB\n",
		"pressure/memory": "some avg10=88.00 avg60=70.00 avg300=40.00 total=1\nfull avg10=61.00 avg60=50.00 avg300=20.00 total=1\n",
		"101/stat":        "101 (WPEWebProcess) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 340000 0 0\n",
		"202/stat":        "202 (singularity shell) D 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 51200 0 0\n",
		"self/stat":       "garbage\n",
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDiagnoseReadsPressureMemoryAndBlockedProcesses(t *testing.T) {
	r := Rescue{Proc: fakeProc(t)}
	report := r.Diagnose()
	page := int64(os.Getpagesize() / 1024)
	for _, want := range []string{
		"uptime   1h2m5s",
		"load     9.50 7.25 4.00",
		"memory   50 MiB available of 3613 MiB",
		"swap     2000 MiB used of 3613 MiB",
		"pressure memory some avg10=88.00 avg60=70.00",
		"pressure memory full avg10=61.00 avg60=50.00",
		"blocked  1 processes in uninterruptible sleep",
		"202 singularity shell",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report misses %q:\n%s", want, report)
		}
	}
	first := strings.Index(report, "WPEWebProcess")
	second := strings.LastIndex(report, "singularity shell")
	if first < 0 || second < first {
		t.Errorf("largest processes are not ordered by memory:\n%s", report)
	}
	wpe := fmt.Sprintf("%6d MiB  101 WPEWebProcess", 340000*page/1024)
	if !strings.Contains(report, wpe) {
		t.Errorf("report misses %q:\n%s", wpe, report)
	}
}

func TestForcedRestartSendsSyncRemountReboot(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "sysrq-trigger")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no fifo support: %v", err)
	}
	var mu sync.Mutex
	var keys []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			f, err := os.Open(fifo)
			if err != nil {
				return
			}
			data, _ := io.ReadAll(f)
			f.Close()
			mu.Lock()
			keys = append(keys, string(data))
			mu.Unlock()
		}
	}()
	kernel := false
	r := Rescue{Sysrq: fifo, Kernel: func() error { kernel = true; return nil }, Grace: time.Millisecond, Pause: 2 * time.Millisecond}
	r.Restart(true, func(string, ...any) {})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the forced restart never reached sysrq")
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(keys, "") != "sub" {
		t.Fatalf("sysrq got %q, want s, u, b", keys)
	}
	if kernel {
		t.Fatal("the kernel call ran although sysrq worked")
	}
}

func TestForcedRestartFallsBackToTheKernelCall(t *testing.T) {
	called := make(chan struct{})
	r := Rescue{
		Sysrq:  filepath.Join(t.TempDir(), "missing", "sysrq-trigger"),
		Kernel: func() error { close(called); return nil },
		Grace:  time.Millisecond,
		Pause:  time.Millisecond,
	}
	r.Restart(true, func(string, ...any) {})
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("no kernel restart without sysrq")
	}
}

func TestNormalRestartAsksInit(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "rebooted")
	r := Rescue{
		Reboot:  []string{"sh", "-c", "echo init > " + marker},
		Kernel:  func() error { t.Error("a normal restart used the kernel call"); return nil },
		Sysrq:   filepath.Join(t.TempDir(), "sysrq-trigger"),
		Grace:   time.Millisecond,
		Timeout: 5 * time.Second,
	}
	r.Restart(false, func(string, ...any) {})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if data, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(data)) == "init" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the reboot command never ran")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(r.Sysrq); err == nil {
		t.Fatal("a normal restart touched sysrq")
	}
}

func TestRescueNeedsAPairedHost(t *testing.T) {
	h := newHarness(t)
	rebooted := make(chan struct{}, 1)
	h.srv.rescue = Rescue{
		Proc:   fakeProc(t),
		Sysrq:  filepath.Join(t.TempDir(), "missing", "sysrq-trigger"),
		Kernel: func() error { rebooted <- struct{}{}; return nil },
		Grace:  time.Millisecond,
	}
	host := newHost(t)

	stranger, err := host.Dial(h.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := client.Diagnose(stranger); err == nil {
		t.Fatal("an unpaired host read the health report")
	}
	stranger.Close()
	stranger, err = host.Dial(h.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := client.Reboot(stranger, true); err == nil {
		t.Fatal("an unpaired host rebooted the device")
	}
	stranger.Close()
	select {
	case <-rebooted:
		t.Fatal("the device restarted for an unpaired host")
	case <-time.After(100 * time.Millisecond):
	}

	code := h.startPairing(t)
	conn, err := host.Dial(h.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := client.PairBegin(conn, "laptop"); err != nil {
		t.Fatalf("pair begin: %v", err)
	}
	if err := client.PairSubmit(conn, "laptop", code); err != nil {
		t.Fatalf("pair submit: %v", err)
	}
	conn.Close()

	paired, err := host.Dial(h.addr, h.srv.Fingerprint())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer paired.Close()
	report, err := client.Diagnose(paired)
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if !strings.Contains(report, "pressure memory full avg10=61.00") {
		t.Fatalf("unexpected report:\n%s", report)
	}
	if err := client.Reboot(paired, true); err != nil {
		t.Fatalf("reboot: %v", err)
	}
	select {
	case <-rebooted:
	case <-time.After(5 * time.Second):
		t.Fatal("a paired host could not restart the device")
	}
}
