// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package protocol carries the SDB wire format: newline-delimited JSON frames
// over TLS 1.3, one request and one reply per frame, the same shape the ush
// broker uses on its control socket.
//
// The transport is stdlib crypto/tls with self-signed certificates on both
// ends and no certificate authority anywhere. Both sides skip the library's
// chain verification and pin the peer's public key fingerprint instead. That
// choice is deliberate: a CA would mean shipping issuance and revocation
// machinery into the recovery image, which has to stay small, in exchange for a
// weaker guarantee than the pin already gives.
package protocol

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/keys"
	"github.com/singularityos-lab/sinty-sdb/internal/keystore"
)

// DefaultPort is the TCP port sdbd listens on.
const DefaultPort = 5555

// Operations understood on an open connection.
const (
	OpPairBegin   = "pair-begin"
	OpPairSubmit  = "pair-submit"
	OpHello       = "hello"
	OpHostsList   = "hosts-list"
	OpHostsRevoke = "hosts-revoke"
)

// Deadlines bounding a connection. Pairing waits on a human typing a code, so
// it gets a longer window than the machine-to-machine calls.
const (
	DialTimeout    = 10 * time.Second
	CallTimeout    = 20 * time.Second
	PairingTimeout = 3 * time.Minute
)

// Request is one call from host to device.
type Request struct {
	Op    string `json:"op"`
	Label string `json:"label,omitempty"`
	Code  string `json:"code,omitempty"`
}

// Response is the device's reply. Error carries a message meant for the person
// running the CLI, so it never contains a code or a key.
type Response struct {
	OK          bool            `json:"ok"`
	Error       string          `json:"error,omitempty"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Hosts       []keystore.Host `json:"hosts,omitempty"`
}

// Conn is a framed connection over TLS.
type Conn struct {
	net  net.Conn
	r    *bufio.Reader
	Peer string
}

// NewConn wraps an established connection, recording the peer fingerprint.
func NewConn(c net.Conn, peer string) *Conn {
	return &Conn{net: c, r: bufio.NewReader(c), Peer: peer}
}

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.net.Close() }

// SetDeadline bounds the next exchange.
func (c *Conn) SetDeadline(t time.Time) error { return c.net.SetDeadline(t) }

// WriteRequest sends one request frame.
func (c *Conn) WriteRequest(req Request) error { return c.write(req) }

// WriteResponse sends one reply frame.
func (c *Conn) WriteResponse(resp Response) error { return c.write(resp) }

func (c *Conn) write(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.net.Write(append(data, '\n'))
	return err
}

// ReadRequest reads one request frame. A frame that will not parse is an error,
// never a zero-valued request: an unparsable request must be refused, and a
// zero Op would quietly become an unknown-op refusal that hides the real cause.
func (c *Conn) ReadRequest() (Request, error) {
	var req Request
	err := c.read(&req)
	return req, err
}

// ReadResponse reads one reply frame.
func (c *Conn) ReadResponse() (Response, error) {
	var resp Response
	err := c.read(&resp)
	return resp, err
}

func (c *Conn) read(v any) error {
	line, err := c.r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("unparsable frame: %w", err)
	}
	return nil
}

// ServerTLS builds the device-side TLS configuration. It always asks for a
// client certificate and always records the peer fingerprint; deciding whether
// that fingerprint may proceed is the daemon's job, because a pairing
// connection and an ordinary one answer that question differently.
func ServerTLS(id *keys.Identity, peer *string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			fp, err := peerFingerprint(rawCerts)
			if err != nil {
				return err
			}
			*peer = fp
			return nil
		},
	}
}

// ClientTLS builds the host-side configuration. When want is non-empty the
// device's key must match it, which is what makes a paired connection immune to
// a machine in the middle. When want is empty the caller is pairing and has not
// been told the device key yet, so it is accepted and reported back for the
// user to compare against the screen.
func ClientTLS(id *keys.Identity, want string, got *string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		MinVersion:   tls.VersionTLS13,
		// The chain is self-signed by design; the pin below is the check.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			fp, err := peerFingerprint(rawCerts)
			if err != nil {
				return err
			}
			*got = fp
			if want != "" && !constantTimeEqual(want, fp) {
				return errors.New("device key does not match the one recorded at pairing")
			}
			return nil
		},
	}
}

func constantTimeEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func peerFingerprint(rawCerts [][]byte) (string, error) {
	if len(rawCerts) == 0 {
		return "", errors.New("peer presented no certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return "", fmt.Errorf("peer certificate: %w", err)
	}
	return keys.FingerprintOf(cert), nil
}
