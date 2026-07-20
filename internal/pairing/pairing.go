// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package pairing implements level 1 of the permission model: the short-lived
// on-screen code that proves a human is standing in front of the device.
//
// The code is what replaces the USB cable. Everything here exists to keep that
// claim honest: it lives about two minutes, it works once, and wrong guesses
// cost progressively more time so an attacker on the same network cannot walk
// the space of six digit codes before it expires.
package pairing

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// DefaultTTL is how long a pairing code stays valid.
const DefaultTTL = 2 * time.Minute

// codeDigits is the length of the on-screen code.
const codeDigits = 6

// maxAttempts is how many wrong codes a session survives. The session is
// destroyed on the last one, not merely locked: a code that has been guessed at
// five times has been under attack and is no longer worth defending.
const maxAttempts = 5

var (
	// ErrNoSession means no pairing window is open. It is also what a consumed
	// or destroyed session reports, so a reused code is indistinguishable from
	// a code that never existed.
	ErrNoSession = errors.New("no pairing session is open")
	// ErrExpired means the code outlived its TTL.
	ErrExpired = errors.New("the pairing code has expired")
	// ErrBadCode means the code did not match.
	ErrBadCode = errors.New("wrong pairing code")
	// ErrLocked means too many wrong attempts, too recently.
	ErrLocked = errors.New("too many wrong attempts, pairing is temporarily locked")
	// ErrNoAttempt means a code was submitted without the key having been
	// presented first, so no fingerprint was ever shown for the user to check.
	ErrNoAttempt = errors.New("no pairing attempt is in progress")
)

// State is what a UI needs to render the pairing screen.
type State struct {
	Active             bool      `json:"active"`
	Code               string    `json:"code,omitempty"`
	ExpiresAt          time.Time `json:"expires_at,omitzero"`
	PendingFingerprint string    `json:"pending_fingerprint,omitempty"`
	PendingLabel       string    `json:"pending_label,omitempty"`
	Attempts           int       `json:"attempts"`
	LockedUntil        time.Time `json:"locked_until,omitzero"`
}

type session struct {
	code        string
	expiresAt   time.Time
	attempts    int
	lockedUntil time.Time
	fingerprint string
	label       string
}

// Manager owns at most one pairing session at a time.
type Manager struct {
	mu  sync.Mutex
	s   *session
	now func() time.Time
	ttl time.Duration
}

// NewManager returns a manager with no session open.
func NewManager() *Manager {
	return &Manager{now: time.Now, ttl: DefaultTTL}
}

// SetClock overrides the time source, for tests.
func (m *Manager) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// SetTTL overrides the code lifetime.
func (m *Manager) SetTTL(ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ttl = ttl
}

// Start opens a pairing window and returns the code to show on screen. Any
// session already open is discarded, so there is never more than one live code.
func (m *Manager) Start() (string, time.Time, error) {
	code, err := generateCode()
	if err != nil {
		return "", time.Time{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	expires := m.now().Add(m.ttl)
	m.s = &session{code: code, expiresAt: expires}
	return code, expires, nil
}

// Cancel closes the pairing window.
func (m *Manager) Cancel() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.s = nil
}

// State reports the session for the UI, expiring it first so a stale code is
// never rendered.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	if m.s == nil {
		return State{}
	}
	return State{
		Active:             true,
		Code:               m.s.code,
		ExpiresAt:          m.s.expiresAt,
		PendingFingerprint: m.s.fingerprint,
		PendingLabel:       m.s.label,
		Attempts:           m.s.attempts,
		LockedUntil:        m.s.lockedUntil,
	}
}

// Begin records the key a host is offering, so the device can show its
// fingerprint before any code is typed. This ordering is the whole point of the
// fingerprint: shown after the code was accepted it would prove nothing.
func (m *Manager) Begin(fingerprint, label string) error {
	if fingerprint == "" || label == "" {
		return ErrNoAttempt
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	if m.s == nil {
		return ErrNoSession
	}
	if locked, err := m.lockCheck(); locked {
		return err
	}
	m.s.fingerprint = fingerprint
	m.s.label = label
	return nil
}

// Submit checks a code offered by the host whose key is pending. On success the
// session is consumed, so the same code cannot be presented twice.
func (m *Manager) Submit(fingerprint, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	if m.s == nil {
		return ErrNoSession
	}
	if locked, err := m.lockCheck(); locked {
		return err
	}
	if m.s.fingerprint == "" {
		return ErrNoAttempt
	}
	if subtle.ConstantTimeCompare([]byte(m.s.fingerprint), []byte(fingerprint)) != 1 {
		return ErrNoAttempt
	}
	if subtle.ConstantTimeCompare([]byte(m.s.code), []byte(code)) != 1 {
		m.s.attempts++
		if m.s.attempts >= maxAttempts {
			m.s = nil
			return ErrLocked
		}
		m.s.lockedUntil = m.now().Add(backoff(m.s.attempts))
		return ErrBadCode
	}
	m.s = nil
	return nil
}

// PendingFingerprint returns the key currently offered, if any.
func (m *Manager) PendingFingerprint() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	if m.s == nil {
		return ""
	}
	return m.s.fingerprint
}

// sweep drops an expired session. Callers must hold the lock.
func (m *Manager) sweep() {
	if m.s != nil && !m.now().Before(m.s.expiresAt) {
		m.s = nil
	}
}

// lockCheck reports whether the session is inside its backoff window. Callers
// must hold the lock and must have swept first.
func (m *Manager) lockCheck() (bool, error) {
	if m.s.lockedUntil.IsZero() || !m.now().Before(m.s.lockedUntil) {
		return false, nil
	}
	wait := m.s.lockedUntil.Sub(m.now()).Round(time.Second)
	return true, fmt.Errorf("%w, retry in %s", ErrLocked, wait)
}

// backoff is the wait imposed after n wrong attempts. It doubles every time so
// the cost of guessing grows past what fits inside the code's lifetime.
func backoff(attempts int) time.Duration {
	d := time.Second << (attempts - 1)
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// generateCode draws a uniform code from crypto/rand. A predictable code is a
// code an attacker never has to see on the screen.
func generateCode() (string, error) {
	limit := big.NewInt(1)
	for range codeDigits {
		limit.Mul(limit, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", fmt.Errorf("generate pairing code: %w", err)
	}
	return fmt.Sprintf("%0*d", codeDigits, n), nil
}
