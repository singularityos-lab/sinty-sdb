//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package transfer

import (
	"errors"

	"github.com/singularityos-lab/sinty-sdb/internal/mux"
)

func ServePushAs(st *mux.Stream, absPath string, uid, gid uint32) error {
	_ = st.CloseWithCode(2)
	return errors.New("transfer: user push is only supported on Linux")
}
