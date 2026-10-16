// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const PtyArg = "--sdb-pty="

type Size struct {
	Cols uint16
	Rows uint16
}

func (s Size) Arg() string {
	return fmt.Sprintf("%s%dx%d", PtyArg, s.Cols, s.Rows)
}

func ParsePtyArg(arg string) (Size, bool) {
	if !strings.HasPrefix(arg, PtyArg) {
		return Size{}, false
	}
	cols, rows, ok := strings.Cut(strings.TrimPrefix(arg, PtyArg), "x")
	if !ok {
		return Size{}, false
	}
	c, err1 := strconv.ParseUint(cols, 10, 16)
	r, err2 := strconv.ParseUint(rows, 10, 16)
	if err1 != nil || err2 != nil || c == 0 || r == 0 {
		return Size{}, false
	}
	return Size{Cols: uint16(c), Rows: uint16(r)}, true
}

func ioctl(fd uintptr, req uintptr, arg uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); errno != 0 {
		return errno
	}
	return nil
}

func openPTY(size Size) (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	unlock := int32(0)
	if err = ioctl(master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); err != nil {
		master.Close()
		return nil, nil, err
	}
	var n uint32
	if err = ioctl(master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	ws := [4]uint16{size.Rows, size.Cols, 0, 0}
	_ = ioctl(master.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
	return master, slave, nil
}
