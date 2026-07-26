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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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

// bridgeUser is the dedicated unprivileged account a non-root bridge shell drops
// to: no privileged groups, so it is isolated from the owner's encrypted home and
// from the seat and GPU. It is resolved by NAME, never by a hardcoded uid: a
// fixed number silently collides with another system account (uid 103 is tss and
// gid 103 is pipewire on the base image), which would drop the shell to the wrong
// identity. Root is reachable only through the broker.
const bridgeUser = "sdb"

// fallbackBrokerUID is the primary user on a single-user Sinty install, used only
// when no active session runtime dir carries a broker socket.
const fallbackBrokerUID = 1000

// resolveBridge looks up the isolated bridge account by name. A missing account
// resolves to the zero identity, which the tier rules treat as "no bridge" and,
// combined with no logged-in user, refuse the shell rather than leave it as root.
func resolveBridge() shell.Identity {
	return lookupIdentity(bridgeUser)
}

// resolveLoginUser finds the logged-in user a default shell drops to: the
// regular user (uid >= 1000) with an active runtime dir, highest uid winning on
// the rare multi-user box. A single-user Sinty resolves to its one user. If no
// one is logged in it returns the zero identity, so the shell falls back to the
// isolated bridge account.
func resolveLoginUser() shell.Identity {
	best := shell.Identity{}
	entries, err := os.ReadDir("/run/user")
	if err != nil {
		return best
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		uid, err := strconv.Atoi(e.Name())
		if err != nil || uid < 1000 {
			continue
		}
		u, err := user.LookupId(e.Name())
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(u.Gid)
		if err != nil {
			continue
		}
		if uint32(uid) > best.UID {
			best = shell.Identity{UID: uint32(uid), GID: uint32(gid)}
		}
	}
	return best
}

// lookupIdentity resolves a system account name to its uid/gid, or the zero
// identity if it is absent or maps to uid 0.
func lookupIdentity(name string) shell.Identity {
	u, err := user.Lookup(name)
	if err != nil {
		return shell.Identity{}
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid <= 0 {
		return shell.Identity{}
	}
	return shell.Identity{UID: uint32(uid), GID: uint32(gid)}
}

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
	Root     string
	Log      *slog.Logger
}

// Server is the device daemon.
type Server struct {
	id    *keys.Identity
	store *keystore.Store
	pair  *pairing.Manager
	root  string
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
	if !filepath.IsAbs(cfg.Root) {
		return nil, errors.New("sdbd: session root must be absolute")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		id:    cfg.Identity,
		store: cfg.Store,
		pair:  cfg.Pairing,
		root:  cfg.Root,
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
			session.Serve(c.Upgrade(), session.Config{
				Root:      s.root,
				Logs:      sessionLogs(s.root),
				Access:    shell.Access{Login: resolveLoginUser(), Bridge: resolveBridge()},
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
		// Host-initiated: opening the window here (not requiring a prior local
		// Start) is what makes `sdb pair` alone raise the code on the device. The
		// code is logged for a headless device and surfaced to the local UI via
		// /pairing/state; it is never returned to the host over the wire.
		code, expires, err := s.pair.Open(peer, req.Label)
		if err != nil {
			return refuse(err)
		}
		s.log.Info("sdb pairing code (read it off the device screen)",
			"code", code, "label", req.Label,
			"fingerprint", keys.Display(peer), "expires", expires)
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

// sessionLogs resolves a log request. A path-like name reads a file confined to
// the transfer root; a bare unit name reads sinit's captured logs through
// atomctl, which sdbd (running as root) is authorized to do. The connection is
// already pairing-gated, which is the trust boundary for reading a paired host's
// device logs.
func sessionLogs(root string) logs.Source {
	return func(unit string) (io.ReadCloser, error) {
		if unit == "" {
			return nil, errors.New("naming a unit or a log path is required")
		}
		if strings.ContainsRune(unit, '/') {
			p, err := transfer.ConfinePath(root, unit)
			if err != nil {
				return nil, err
			}
			return os.Open(p)
		}
		out, err := exec.Command("/usr/bin/atomctl", "logs", unit).Output()
		if err != nil {
			return nil, fmt.Errorf("read unit logs: %w", err)
		}
		return io.NopCloser(bytes.NewReader(out)), nil
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
