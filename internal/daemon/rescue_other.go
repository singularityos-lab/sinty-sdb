// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

//go:build !linux

package daemon

import "errors"

func kernelRestart() error {
	return errors.New("a forced restart is only supported on Linux")
}
