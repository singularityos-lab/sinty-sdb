package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchGatesStopsWhenMarkerDisappears(t *testing.T) {
	dir := t.TempDir()
	gate := filepath.Join(dir, "dev.enabled")
	optIn := filepath.Join(dir, "enabled")
	for _, path := range []string{gate, optIn} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{}, 1)
	stop := func() {
		stopped <- struct{}{}
		cancel()
	}
	go watchGates(ctx, stop, 5*time.Millisecond, gate, optIn)

	select {
	case <-stopped:
		t.Fatal("watcher stopped while both markers existed")
	case <-time.After(20 * time.Millisecond):
	}
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop after the development marker was removed")
	}
}
