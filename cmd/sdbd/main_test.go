package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchGatesStopsWhenOptInDisappears(t *testing.T) {
	dir := t.TempDir()
	optIn := filepath.Join(dir, "enabled")
	if err := os.WriteFile(optIn, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{}, 1)
	stop := func() {
		stopped <- struct{}{}
		cancel()
	}
	go watchGates(ctx, stop, 5*time.Millisecond, optIn)

	select {
	case <-stopped:
		t.Fatal("watcher stopped while the opt-in marker existed")
	case <-time.After(20 * time.Millisecond):
	}
	if err := os.Remove(optIn); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop after the opt-in marker was removed")
	}
}
