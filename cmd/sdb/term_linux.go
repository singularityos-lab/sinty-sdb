// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package main

import (
	"syscall"
	"unsafe"

	"github.com/singularityos-lab/sinty-sdb/internal/shell"
)

func termios(fd uintptr) (syscall.Termios, bool) {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return t, errno == 0
}

func isTerminal(fd uintptr) bool {
	_, ok := termios(fd)
	return ok
}

func termSize(fd uintptr) shell.Size {
	var ws [4]uint16
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws))); errno != 0 || ws[0] == 0 || ws[1] == 0 {
		return shell.Size{Cols: 80, Rows: 24}
	}
	return shell.Size{Cols: ws[1], Rows: ws[0]}
}

func makeRaw(fd uintptr) func() {
	old, ok := termios(fd)
	if !ok {
		return func() {}
	}
	raw := old
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&raw)))
	return func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
	}
}
