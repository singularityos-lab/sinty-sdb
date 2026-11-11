// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package agentlink builds the commands that reach Sinty AI on a paired device.
// Both run through the ordinary user shell stream, so they act as the logged-in
// user and every action the agent takes is confirmed on the device itself.
package agentlink

const session = `export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"; `

const askScript = session + `command -v sinty >/dev/null || { echo "Sinty AI is not installed on this device" >&2; exit 127; }; exec sinty ask "$@"`

const mcpScript = session + `s="$XDG_RUNTIME_DIR/sinty-agent/mcp.sock"
b=/usr/libexec/sinty-agent-bridge
[ -x "$b" ] || b=$(command -v sinty-agent-bridge) || { echo "Sinty AI is not installed on this device" >&2; exit 127; }
if [ ! -S "$s" ]; then
  dbus-send --session --type=method_call --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.StartServiceByName string:dev.sinty.Agent uint32:0 >/dev/null 2>&1 ||
    gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.StartServiceByName dev.sinty.Agent 0 >/dev/null 2>&1
  i=0
  while [ ! -S "$s" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
fi
[ -S "$s" ] || { echo "Sinty AI is not running on this device" >&2; exit 1; }
exec "$b" "$s"`

// AskArgs is the device command that asks Sinty AI one question and prints the answer.
func AskArgs(words []string) []string {
	return append([]string{"/bin/sh", "-c", askScript, "sdb-ask"}, words...)
}

// MCPArgs is the device command that joins standard input and output to the
// agent's MCP socket, so a local MCP client can use the device's Sinty tools.
func MCPArgs() []string {
	return []string{"/bin/sh", "-c", mcpScript, "sdb-mcp"}
}
