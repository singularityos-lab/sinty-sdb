//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import (
	"errors"
	"os"
)

func openPTY(Size) (*os.File, *os.File, error) {
	return nil, nil, errors.New("pseudo terminals are only served on Linux")
}
