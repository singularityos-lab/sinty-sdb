// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package keystore is the device's trusted host keyring: which host keys may
// connect, under what label, and when each was last used.
//
// The whole package is written to fail closed. An absent file means zero
// trusted hosts. A file that will not parse is an error the caller must
// propagate, not an empty set to carry on with. The distinction matters: an
// empty set that is silently substituted for a damaged file turns corruption
// into "trust nobody" only by luck, and the same reflex elsewhere turns it into
// "trust anybody".
package keystore

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when no entry carries the requested label.
var ErrNotFound = errors.New("no such paired host")

const formatVersion = 1

// Host is one trusted development machine.
type Host struct {
	Label       string    `json:"label"`
	Fingerprint string    `json:"fingerprint"`
	PairedAt    time.Time `json:"paired_at"`
	LastUsed    time.Time `json:"last_used"`
}

type file struct {
	Version int    `json:"version"`
	Hosts   []Host `json:"hosts"`
}

// Store is a keystore backed by a single JSON file, safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	path  string
	hosts []Host
	now   func() time.Time
}

// Open reads the keystore at path. A missing file yields an empty, usable
// store. Anything else that goes wrong is an error.
func Open(path string) (*Store, error) {
	s := &Store{path: path, now: time.Now}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read keystore: %w", err)
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse keystore %s: %w", path, err)
	}
	if f.Version != formatVersion {
		return nil, fmt.Errorf("parse keystore %s: unsupported version %d", path, f.Version)
	}
	for _, h := range f.Hosts {
		if h.Label == "" || h.Fingerprint == "" {
			return nil, fmt.Errorf("parse keystore %s: entry with empty label or fingerprint", path)
		}
	}
	s.hosts = f.Hosts
	return s, nil
}

// SetClock overrides the time source, for tests.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// List returns the trusted hosts, ordered by label.
func (s *Store) List() []Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Host, len(s.hosts))
	copy(out, s.hosts)
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// Trusted reports whether the fingerprint belongs to a paired host. The
// comparison is constant time: a fingerprint is public, but an attacker who can
// measure how far the comparison got can walk one nibble at a time towards a
// value the store will accept.
func (s *Store) Trusted(fingerprint string) (Host, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := []byte(strings.ToLower(fingerprint))
	found := Host{}
	ok := false
	for _, h := range s.hosts {
		have := []byte(strings.ToLower(h.Fingerprint))
		if len(have) == len(want) && subtle.ConstantTimeCompare(have, want) == 1 {
			found, ok = h, true
		}
	}
	return found, ok
}

// Add records a newly paired host. A label already in use is replaced, so
// re-pairing the same machine does not leave a stale key behind that would
// still be accepted.
func (s *Store) Add(label, fingerprint string) error {
	_, err := s.AddHost(label, fingerprint)
	return err
}

// AddHost records a newly paired host and returns entries displaced by its
// label or fingerprint.
func (s *Store) AddHost(label, fingerprint string) ([]Host, error) {
	if label == "" {
		return nil, errors.New("add host: empty label")
	}
	if fingerprint == "" {
		return nil, errors.New("add host: empty fingerprint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	next := make([]Host, 0, len(s.hosts)+1)
	displaced := make([]Host, 0)
	for _, h := range s.hosts {
		if h.Label != label && !strings.EqualFold(h.Fingerprint, fingerprint) {
			next = append(next, h)
		} else {
			displaced = append(displaced, h)
		}
	}
	next = append(next, Host{
		Label:       label,
		Fingerprint: strings.ToLower(fingerprint),
		PairedAt:    now,
		LastUsed:    time.Time{},
	})
	previous := s.hosts
	s.hosts = next
	if err := s.save(); err != nil {
		s.hosts = previous
		return nil, err
	}
	return displaced, nil
}

// Remove revokes the host carrying the label.
func (s *Store) Remove(label string) error {
	_, err := s.RemoveHost(label)
	return err
}

// RemoveHost revokes the host carrying the label and returns the removed key so
// the daemon can terminate sessions authenticated with it.
func (s *Store) RemoveHost(label string) (Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]Host, 0, len(s.hosts))
	removed := Host{}
	for _, h := range s.hosts {
		if h.Label != label {
			next = append(next, h)
		} else {
			removed = h
		}
	}
	if len(next) == len(s.hosts) {
		return Host{}, ErrNotFound
	}
	previous := s.hosts
	s.hosts = next
	if err := s.save(); err != nil {
		s.hosts = previous
		return Host{}, err
	}
	return removed, nil
}

// Touch stamps a fingerprint as used now, so the user can tell a live pairing
// from one forgotten years ago.
func (s *Store) Touch(fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.hosts {
		if strings.EqualFold(s.hosts[i].Fingerprint, fingerprint) {
			previous := s.hosts[i].LastUsed
			s.hosts[i].LastUsed = s.now()
			if err := s.save(); err != nil {
				s.hosts[i].LastUsed = previous
				return err
			}
			return nil
		}
	}
	return ErrNotFound
}

// save rewrites the file through a temporary sibling, so an interrupted write
// cannot leave a half-file that the next Open would reject.
func (s *Store) save() error {
	data, err := json.MarshalIndent(file{Version: formatVersion, Hosts: s.hosts}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode keystore: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create keystore directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".keystore-*")
	if err != nil {
		return fmt.Errorf("write keystore: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("write keystore: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write keystore: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write keystore: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write keystore: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("write keystore: %w", err)
	}
	return nil
}
