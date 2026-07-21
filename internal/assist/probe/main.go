// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Command assist-probe is the read-only diagnostic tool for the SDB assistance
// tier. It reads only world-readable system state and prints it: no writes, no
// configuration changes, no privileged access. It is built static, embedded in
// sdbd, and executed from RAM during an authorized assistance session, so it
// never sits on the device's disk.
package main

import (
	"fmt"
	"os"
)

func cat(label, path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	fmt.Printf("== %s (%s) ==\n%s\n", label, path, b)
}

func main() {
	fmt.Println("sinty assist-probe: read-only diagnostics")
	cat("kernel", "/proc/version")
	cat("uptime", "/proc/uptime")
	cat("loadavg", "/proc/loadavg")
	cat("meminfo", "/proc/meminfo")
}
