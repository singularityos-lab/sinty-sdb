// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package daemon is sdbd, the device side of SDB.
//
// It runs two listeners. The TCP one speaks TLS to development hosts and is the
// only surface reachable from the network. The unix one is a local control API
// the Settings and recovery UIs use to drive pairing and manage the keyring; it
// is never exposed off the machine.
//
// The daemon holds no privilege of its own. Phase 1 stops at deciding who may
// talk to it; anything that would need root belongs to a later phase and goes
// through the ush broker, which approves per action and leaves a receipt.
package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/broker"
	"github.com/singularityos-lab/sinty-sdb/internal/keys"
	"github.com/singularityos-lab/sinty-sdb/internal/keystore"
	"github.com/singularityos-lab/sinty-sdb/internal/logs"
	"github.com/singularityos-lab/sinty-sdb/internal/pairing"
	"github.com/singularityos-lab/sinty-sdb/internal/protocol"
	"github.com/singularityos-lab/sinty-sdb/internal/session"
	"github.com/singularityos-lab/sinty-sdb/internal/shell"
	"github.com/singularityos-lab/sinty-sdb/internal/transfer"
)

// The bridge user: a dedicated unprivileged system account with no privileged
// groups, so a non-root bridge session is isolated from the owner's encrypted
// home and from the seat and GPU. Root is reachable only through the broker.
const (
	bridgeUID = 103
	bridgeGID = 103
	// fallbackBrokerUID is the primary user on a single-user Sinty install,
	// used only when no active session runtime dir carries a broker socket.
	fallbackBrokerUID = 1000
)

// resolveBrokerSocket finds the ush broker's socket. The broker runs in the
// graphical user's session, so the socket lives under that user's runtime dir.
// sdbd runs as root and cannot assume a uid, so it honours an explicit override,
// then looks for a live broker socket under /run/user/<uid>, and falls back to
// the single-user primary. A wrong path denies every elevation, which is safe.
func resolveBrokerSocket() string {
	if s := os.Getenv("USH_BROKER_SOCK"); s != "" {
		return s
	}
	if entries, err := os.ReadDir("/run/user"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join("/run/user", e.Name(), "ush", "broker.sock")
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return fmt.Sprintf("/run/user/%d/ush/broker.sock", fallbackBrokerUID)
}

// Config configures a Server.
type Config struct {
	Identity *keys.Identity
	Store    *keystore.Store
	Pairing  *pairing.Manager
	Log      *slog.Logger
}

// Server is the device daemon.
type Server struct {
	id    *keys.Identity
	store *keystore.Store
	pair  *pairing.Manager
	log   *slog.Logger

	mu   sync.Mutex
	live map[net.Conn]struct{}
}

// New builds a Server. Every dependency is required: a nil keystore would mean
// a daemon with no notion of who is trusted, which must never be reachable.
func New(cfg Config) (*Server, error) {
	if cfg.Identity == nil {
		return nil, errors.New("sdbd: no device identity")
	}
	if cfg.Store == nil {
		return nil, errors.New("sdbd: no keystore")
	}
	if cfg.Pairing == nil {
		return nil, errors.New("sdbd: no pairing manager")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		id:    cfg.Identity,
		store: cfg.Store,
		pair:  cfg.Pairing,
		log:   log,
		live:  make(map[net.Conn]struct{}),
	}, nil
}

// track registers a live connection so shutdown can close it, and returns the
// function that unregisters it.
func (s *Server) track(c net.Conn) func() {
	s.mu.Lock()
	s.live[c] = struct{}{}
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.live, c)
		s.mu.Unlock()
	}
}

// dropLive closes every connection still open. Closing the listener alone only
// refuses new peers: an already-connected host would keep its session until it
// chose to leave, so disabling the bridge would not actually end access.
func (s *Server) dropLive() int {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.live))
	for c := range s.live {
		conns = append(conns, c)
	}
	s.live = make(map[net.Conn]struct{})
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return len(conns)
}

// Fingerprint returns the device's own key fingerprint.
func (s *Server) Fingerprint() string { return s.id.Fingerprint() }

// ListenAndServe accepts TLS connections on addr until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		if n := s.dropLive(); n > 0 {
			s.log.Info("closed live sessions on shutdown", "count", n)
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// handle runs one connection: TLS handshake, then framed requests until the
// peer goes away or asks for something it may not have.
func (s *Server) handle(raw net.Conn) {
	defer raw.Close()
	defer s.track(raw)()

	var peer string
	tlsConn := tls.Server(raw, protocol.ServerTLS(s.id, &peer))
	_ = tlsConn.SetDeadline(time.Now().Add(protocol.CallTimeout))
	if err := tlsConn.Handshake(); err != nil {
		s.log.Warn("sdb handshake refused", "err", err.Error())
		return
	}
	if peer == "" {
		return
	}

	host, trusted := s.store.Trusted(peer)
	if trusted {
		if err := s.store.Touch(peer); err != nil {
			s.log.Warn("sdb could not stamp host use", "label", host.Label, "err", err.Error())
		}
		s.log.Info("sdb connection from paired host", "label", host.Label)
	} else {
		s.log.Info("sdb connection from unpaired host", "fingerprint", keys.Display(peer))
	}

	c := protocol.NewConn(tlsConn, peer)
	for {
		_ = c.SetDeadline(time.Now().Add(protocol.PairingTimeout))
		req, err := c.ReadRequest()
		if err != nil {
			return
		}
		if req.Op == protocol.OpSession {
			if !trusted {
				_ = c.WriteResponse(refuse(errors.New("this host is not paired with the device")))
				return
			}
			_ = c.WriteResponse(protocol.Response{OK: true, Fingerprint: s.id.Fingerprint()})
			s.log.Info("sdb phase-two session opened", "peer", keys.Display(c.Peer))
			root := sessionRoot()
			session.Serve(c.Upgrade(), session.Config{
				Root:      root,
				Logs:      sessionLogs(root),
				Elevation: shell.Elevation{BridgeUID: bridgeUID, BridgeGID: bridgeGID},
				Broker:    broker.New(resolveBrokerSocket()),
				Origin:    "sdb:" + host.Label,
				SessionID: keys.Display(c.Peer),
			})
			return
		}
		resp := s.dispatch(c.Peer, trusted, req)
		if err := c.WriteResponse(resp); err != nil {
			return
		}
		if req.Op == protocol.OpPairSubmit && resp.OK {
			trusted = true
		}
	}
}

// dispatch decides one request. An unpaired peer can do nothing except pair,
// and only while a pairing window is open. There is no first-connection grace
// and no fallback: an unknown key that is not pairing is refused.
func (s *Server) dispatch(peer string, trusted bool, req protocol.Request) protocol.Response {
	switch req.Op {
	case protocol.OpPairBegin:
		if trusted {
			return protocol.Response{OK: true, Fingerprint: s.id.Fingerprint()}
		}
		if err := s.pair.Begin(peer, req.Label); err != nil {
			return refuse(err)
		}
		return protocol.Response{OK: true, Fingerprint: s.id.Fingerprint()}

	case protocol.OpPairSubmit:
		if err := s.pair.Submit(peer, req.Code); err != nil {
			return refuse(err)
		}
		label := s.labelFor(req.Label)
		if err := s.store.Add(label, peer); err != nil {
			return refuse(err)
		}
		s.log.Info("sdb host paired", "label", label, "fingerprint", keys.Display(peer))
		return protocol.Response{OK: true, Fingerprint: s.id.Fingerprint()}

	case protocol.OpHello:
		if !trusted {
			return refuse(errors.New("this host is not paired with the device"))
		}
		return protocol.Response{OK: true, Fingerprint: s.id.Fingerprint()}

	case protocol.OpHostsList:
		if !trusted {
			return refuse(errors.New("this host is not paired with the device"))
		}
		return protocol.Response{OK: true, Hosts: s.store.List()}

	case protocol.OpHostsRevoke:
		if !trusted {
			return refuse(errors.New("this host is not paired with the device"))
		}
		if err := s.store.Remove(req.Label); err != nil {
			return refuse(err)
		}
		s.log.Info("sdb host revoked", "label", req.Label)
		return protocol.Response{OK: true}

	default:
		return refuse(fmt.Errorf("unknown request %q", req.Op))
	}
}

// sessionRoot confines phase-two file transfers to the bridge user's home.
// Writing outside it is a privileged action mediated by the broker, so the
// confinement root is the home directory, never the filesystem root.
func sessionRoot() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	return "/var/lib/sinty-sdb"
}

// sessionLogs streams a log file confined to the bridge user's home. Reading
// system logs, which requires no unit name, is a privileged action left to the
// broker rather than served here; the real per-unit sinit registry is wired in
// separately.
func sessionLogs(root string) logs.Source {
	return func(unit string) (io.ReadCloser, error) {
		if unit == "" {
			return nil, errors.New("system log streaming requires broker mediation")
		}
		p, err := transfer.ConfinePath(root, unit)
		if err != nil {
			return nil, err
		}
		return os.Open(p)
	}
}

// labelFor keeps a label usable even if the host sent none.
func (s *Server) labelFor(label string) string {
	if label == "" {
		return "unnamed-host"
	}
	return label
}

func refuse(err error) protocol.Response {
	return protocol.Response{OK: false, Error: err.Error()}
}
