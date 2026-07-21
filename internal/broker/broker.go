// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package broker is the sdbd side of privilege elevation. sdbd holds no
// privilege of its own: when a phase-two action needs root (a root shell, a
// write outside the bridge user's tree, binding a low port) it asks the ush
// broker, per action, and proceeds only if a human confirms on the device. The
// request is one newline-delimited JSON object per connection on the broker's
// private socket. Anything other than an explicit grant, including any transport
// error, is a denial: the gate fails closed.
package broker

import (
	"bufio"
	"encoding/json"
	"net"
	"time"
)

// Method is the broker method name for an elevation request.
const Method = "SdbElevate"

// Actions the broker mediates.
const (
	ActionShellRoot          = "shell-root"
	ActionWriteSystem        = "write-system"
	ActionBindPrivilegedPort = "bind-privileged-port"
	ActionAssist             = "assist"
)

// CallTimeout bounds a single elevation exchange. It leaves room for a human to
// answer the on-device prompt.
const CallTimeout = 2 * time.Minute

// Request is what sdbd sends the broker. Detail carries the path for a system
// write or the port for a bind, and is empty for a root shell.
type Request struct {
	Method  string `json:"method"`
	Action  string `json:"action"`
	Detail  string `json:"detail,omitempty"`
	Origin  string `json:"origin"`
	Session string `json:"session"`
}

// Response is the broker's decision. OK is true only after a human granted the
// action on the device.
type Response struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// Client asks a broker socket for elevation.
type Client struct {
	socket  string
	timeout time.Duration
}

// New returns a client for the broker socket at path.
func New(socket string) *Client {
	return &Client{socket: socket, timeout: CallTimeout}
}

// Elevate asks the broker to allow action on detail for the paired origin. It
// returns whether the action was granted and the broker's message. Any error is
// reported as a denial with the error text, never as a grant.
func (c *Client) Elevate(action, detail, origin, session string) (bool, string) {
	conn, err := net.DialTimeout("unix", c.socket, c.timeout)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	req := Request{
		Method:  Method,
		Action:  action,
		Detail:  detail,
		Origin:  origin,
		Session: session,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return false, err.Error()
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return false, err.Error()
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return false, err.Error()
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return false, err.Error()
	}
	return resp.OK, resp.Message
}
