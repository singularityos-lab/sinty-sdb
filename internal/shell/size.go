// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import (
	"fmt"
	"strconv"
	"strings"
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
