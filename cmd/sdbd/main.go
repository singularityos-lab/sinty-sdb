// Command sdbd is the device side of the Sinty Debug Bridge. It serves the
// network channel development hosts pair with, and a local socket the Settings
// and recovery UIs drive that pairing from.
//
// It exists only on a development image. The marker at /etc/atom/dev.enabled is
// the first level of the permission model, and the strongest one: where the
// marker is absent sdbd does not run at all, so there is no port to defend
// rather than a port defended well.
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
	gate := fs.String("gate", "/etc/atom/dev.enabled", "development marker that must exist for sdbd to run")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if _, err := os.Stat(*gate); err != nil {
		fmt.Fprintf(os.Stderr, "sdbd: the debug bridge is available only on a development image (%s)\n", *gate)
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
	srv, err := daemon.New(daemon.Config{Identity: id, Store: store, Pairing: pairing.NewManager()})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sdbd:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
