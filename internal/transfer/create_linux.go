// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package transfer

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	sysOpenat2         = 437
	resolveNoMagiclink = 0x02
	resolveNoSymlinks  = 0x04
	atFdcwd            = -100
)

type openHow struct {
	flags   uint64
	mode    uint64
	resolve uint64
}

func createNoSymlinks(path string) (*os.File, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	how := openHow{
		flags:   uint64(os.O_WRONLY | os.O_CREATE | os.O_TRUNC | syscall.O_CLOEXEC | syscall.O_NOFOLLOW),
		mode:    0o644,
		resolve: resolveNoSymlinks | resolveNoMagiclink,
	}
	dirfd := atFdcwd
	for {
		fd, _, errno := syscall.Syscall6(sysOpenat2, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
		switch {
		case errno == 0:
			return os.NewFile(fd, path), nil
		case errno == syscall.EINTR || errno == syscall.EAGAIN:
			continue
		case errno == syscall.ELOOP || errno == syscall.EXDEV:
			return nil, ErrOutsideRoot
		case errno == syscall.ENOSYS:
			return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)
		default:
			return nil, &os.PathError{Op: "openat2", Path: path, Err: errno}
		}
	}
}
