// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package transfer

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

func setfsid(uid, gid int) {
	syscall.RawSyscall(syscall.SYS_SETFSGID, uintptr(gid), 0, 0)
	syscall.RawSyscall(syscall.SYS_SETFSUID, uintptr(uid), 0, 0)
}

func ServePushAs(st *mux.Stream, absPath string, uid, gid uint32) error {
	clean := filepath.Clean(absPath)
	if !filepath.IsAbs(clean) {
		_ = st.CloseWithCode(2)
		return ErrOutsideRoot
	}
	data, err := readHashed(st)
	if err != nil {
		_ = st.CloseWithCode(1)
		return err
	}
	runtime.LockOSThread()
	setfsid(int(uid), int(gid))
	f, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)
	if err == nil {
		_, err = f.Write(data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	setfsid(0, 0)
	runtime.UnlockOSThread()
	if err != nil {
		_ = st.CloseWithCode(3)
		return err
	}
	return st.CloseWithCode(0)
}
