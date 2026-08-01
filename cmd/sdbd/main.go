// Command sdbd is the device side of the Sinty Debug Bridge. It serves the
// network channel development hosts pair with, and a local socket the Settings
// and recovery UIs drive that pairing from.
//
// It is off by default and starts only after the owner enables it in Settings.
// The opt-in marker is persistent device policy, not an image-build marker, so
// a release image can expose the control without opening a listener by default.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/daemon"
	"github.com/singularityos-lab/sinty-sdb/internal/keys"
	"github.com/singularityos-lab/sinty-sdb/internal/keystore"
	"github.com/singularityos-lab/sinty-sdb/internal/pairing"
	"github.com/singularityos-lab/sinty-sdb/internal/protocol"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("sdbd", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/sinty-sdb", "directory holding the device identity and keystore")
	socket := fs.String("socket", "/run/sinty-sdb.sock", "unix socket for the local control API")
	listen := fs.String("listen", "", "TCP address to serve (default all interfaces on the SDB port)")
	optIn := fs.String("opt-in", "/var/lib/sinty-sdb/enabled", "per-bridge marker the owner turns on to allow the bridge to run")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Absent means off, so a fresh image carries no listener until the owner asks.
	if _, err := os.Stat(*optIn); err != nil {
		fmt.Fprintf(os.Stderr, "sdbd: the debug bridge has not been turned on (%s)\n", *optIn)
		return 1
	}

	addr := *listen
	if addr == "" {
		addr = net.JoinHostPort("", strconv.Itoa(protocol.DefaultPort))
	}

	id, err := keys.LoadOrCreate(*stateDir, "device")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sdbd:", err)
		return 1
	}
	store, err := keystore.Open(filepath.Join(*stateDir, "keystore.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "sdbd:", err)
		fmt.Fprintln(os.Stderr, "sdbd: refusing to serve with an unreadable keystore")
		return 1
	}
	root := filepath.Join(*stateDir, "files")
	if err := os.MkdirAll(root, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "sdbd:", err)
		return 1
	}
	if err := os.Chmod(root, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "sdbd:", err)
		return 1
	}
	srv, err := daemon.New(daemon.Config{
		Identity: id,
		Store:    store,
		Pairing:  pairing.NewManager(),
		Root:     root,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sdbd:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go watchGates(ctx, stop, time.Second, *optIn)

	fmt.Fprintf(os.Stderr, "sdbd: device key %s\n", keys.Display(id.Fingerprint()))

	errs := make(chan error, 2)
	go func() { errs <- srv.ServeControl(ctx, *socket) }()
	go func() { errs <- srv.ListenAndServe(ctx, addr) }()

	err = <-errs
	stop()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		fmt.Fprintln(os.Stderr, "sdbd:", err)
		return 1
	}
	return 0
}

func watchGates(ctx context.Context, stop context.CancelFunc, interval time.Duration, paths ...string) {
	check := func() bool {
		for _, path := range paths {
			if _, err := os.Stat(path); err != nil {
				stop()
				return false
			}
		}
		return true
	}
	if !check() {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !check() {
				return
			}
		}
	}
}
