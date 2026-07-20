// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package client is the host side of SDB: it dials a device, pairs with it
// once, and afterwards proves who it is with nothing but its key.
package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/keys"
	"github.com/singularityos-lab/sinty-sdb/internal/keystore"
	"github.com/singularityos-lab/sinty-sdb/internal/protocol"
)

// Client dials devices with one host identity.
type Client struct {
	id *keys.Identity
}

// New returns a client using the given host identity.
func New(id *keys.Identity) *Client { return &Client{id: id} }

// Fingerprint returns the host's own key fingerprint, the value the device
// shows on screen for the user to compare.
func (c *Client) Fingerprint() string { return c.id.Fingerprint() }

// Dial opens a connection to addr. When wantDevice is non-empty the device must
// present exactly that key, which is what makes every connection after pairing
// immune to a machine in the middle.
func (c *Client) Dial(addr, wantDevice string) (*protocol.Conn, error) {
	addr = normalise(addr)
	var got string
	raw, err := net.DialTimeout("tcp", addr, protocol.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	conn := tls.Client(raw, protocol.ClientTLS(c.id, wantDevice, &got))
	_ = conn.SetDeadline(time.Now().Add(protocol.CallTimeout))
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("secure channel to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return protocol.NewConn(conn, got), nil
}

// call sends one request and returns the reply, turning a refusal into an
// error so no caller can mistake one for a success.
func call(conn *protocol.Conn, req protocol.Request, timeout time.Duration) (protocol.Response, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.WriteRequest(req); err != nil {
		return protocol.Response{}, err
	}
	resp, err := conn.ReadResponse()
	if err != nil {
		return protocol.Response{}, err
	}
	if !resp.OK {
		if resp.Error == "" {
			return resp, errors.New("the device refused the request")
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// PairBegin presents this host's key and returns the device key fingerprint.
// The device is now showing that same fingerprint next to the code, which is
// what the user compares before typing anything.
func PairBegin(conn *protocol.Conn, label string) (string, error) {
	resp, err := call(conn, protocol.Request{Op: protocol.OpPairBegin, Label: label}, protocol.CallTimeout)
	if err != nil {
		return "", err
	}
	if resp.Fingerprint != conn.Peer {
		return "", errors.New("the device reported a key other than the one it presented")
	}
	return resp.Fingerprint, nil
}

// PairSubmit sends the code read off the device screen.
func PairSubmit(conn *protocol.Conn, label, code string) error {
	_, err := call(conn, protocol.Request{Op: protocol.OpPairSubmit, Label: label, Code: code}, protocol.CallTimeout)
	return err
}

// Hello checks that a paired connection is accepted.
func Hello(conn *protocol.Conn) error {
	_, err := call(conn, protocol.Request{Op: protocol.OpHello}, protocol.CallTimeout)
	return err
}

// ListHosts returns the devices's paired hosts.
func ListHosts(conn *protocol.Conn) ([]keystore.Host, error) {
	resp, err := call(conn, protocol.Request{Op: protocol.OpHostsList}, protocol.CallTimeout)
	if err != nil {
		return nil, err
	}
	return resp.Hosts, nil
}

// Revoke removes a paired host from the device's keyring.
func Revoke(conn *protocol.Conn, label string) error {
	_, err := call(conn, protocol.Request{Op: protocol.OpHostsRevoke, Label: label}, protocol.CallTimeout)
	return err
}

// normalise appends the default port when the address carries none.
func normalise(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, strconv.Itoa(protocol.DefaultPort))
}
