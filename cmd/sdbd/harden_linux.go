// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const mclOnFault = 4

func harden() {
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0); err != nil {
		fmt.Fprintln(os.Stderr, "sdbd: could not leave the OOM killer's reach:", err)
	}
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE | mclOnFault); err != nil {
		fmt.Fprintln(os.Stderr, "sdbd: could not keep the daemon in memory:", err)
		return
	}
	if err := lockExecutable(); err != nil {
		fmt.Fprintln(os.Stderr, "sdbd: could not load the daemon's code into memory:", err)
	}
}

func lockExecutable() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || fields[5] != exe || strings.HasPrefix(fields[1], "---") {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_MLOCK, uintptr(start), uintptr(end-start), 0); errno != 0 {
			return errno
		}
	}
	return sc.Err()
}
