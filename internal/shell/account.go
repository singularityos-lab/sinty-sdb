// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type account struct {
	name    string
	home    string
	shell   string
	runtime string
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
	a.runtime = runtimeDir("/run/user", uid)
	return a
}

// runtimeDir returns the account's runtime directory under root when it
// exists and belongs to uid, so a shell joins the user's running session.
func runtimeDir(root string, uid uint32) string {
	p := filepath.Join(root, strconv.FormatUint(uint64(uid), 10))
	st, err := os.Stat(p)
	if err != nil || !st.IsDir() {
		return ""
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || s.Uid != uid {
		return ""
	}
	return p
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
	if a.runtime != "" {
		env = append(env, "XDG_RUNTIME_DIR="+a.runtime)
	}
	return env
}

func (a account) workdir() string {
	if st, err := os.Stat(a.home); err == nil && st.IsDir() {
		return a.home
	}
	return "/"
}
