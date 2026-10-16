// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type account struct {
	name  string
	home  string
	shell string
}

func lookupAccount(passwd string, uid uint32) (account, bool) {
	f, err := os.Open(passwd)
	if err != nil {
		return account{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		id, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || uint32(id) != uid {
			continue
		}
		return account{name: fields[0], home: fields[5], shell: fields[6]}, true
	}
	return account{}, false
}

func accountFor(cred *syscall.Credential) account {
	uid := uint32(os.Getuid())
	if cred != nil {
		uid = cred.Uid
	}
	a, ok := lookupAccount("/etc/passwd", uid)
	if !ok {
		a = account{name: strconv.FormatUint(uint64(uid), 10), home: "/"}
	}
	if a.home == "" {
		a.home = "/"
	}
	if a.shell == "" || strings.HasSuffix(a.shell, "nologin") || strings.HasSuffix(a.shell, "/false") {
		a.shell = os.Getenv("SHELL")
	}
	if a.shell == "" {
		a.shell = "/bin/sh"
	}
	return a
}

func (a account) env(term string) []string {
	env := []string{
		"HOME=" + a.home,
		"USER=" + a.name,
		"LOGNAME=" + a.name,
		"SHELL=" + a.shell,
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
	}
	if lang := os.Getenv("LANG"); lang != "" {
		env = append(env, "LANG="+lang)
	}
	if term != "" {
		env = append(env, "TERM="+term)
	}
	return env
}

func (a account) workdir() string {
	if st, err := os.Stat(a.home); err == nil && st.IsDir() {
		return a.home
	}
	return "/"
}
