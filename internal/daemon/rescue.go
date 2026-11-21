// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package daemon

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Rescue struct {
	Proc    string
	Sysrq   string
	Reboot  []string
	Kernel  func() error
	Grace   time.Duration
	Pause   time.Duration
	Timeout time.Duration
}

func DefaultRescue() Rescue {
	return Rescue{
		Proc:    "/proc",
		Sysrq:   "/proc/sysrq-trigger",
		Reboot:  []string{"/usr/bin/reboot"},
		Kernel:  kernelRestart,
		Grace:   500 * time.Millisecond,
		Pause:   2 * time.Second,
		Timeout: 30 * time.Second,
	}
}

func (r Rescue) Diagnose() string {
	var b strings.Builder
	if up := r.read("uptime"); up != "" {
		if secs, err := strconv.ParseFloat(strings.Fields(up)[0], 64); err == nil {
			fmt.Fprintf(&b, "uptime   %s\n", (time.Duration(secs) * time.Second).String())
		}
	}
	if load := r.read("loadavg"); load != "" {
		fmt.Fprintf(&b, "load     %s\n", strings.Join(strings.Fields(load)[:3], " "))
	}
	mem := r.meminfo()
	fmt.Fprintf(&b, "memory   %d MiB available of %d MiB\n", mem["MemAvailable"]/1024, mem["MemTotal"]/1024)
	if mem["SwapTotal"] > 0 {
		fmt.Fprintf(&b, "swap     %d MiB used of %d MiB\n", (mem["SwapTotal"]-mem["SwapFree"])/1024, mem["SwapTotal"]/1024)
	} else {
		fmt.Fprintln(&b, "swap     none")
	}
	for _, kind := range []string{"memory", "io", "cpu"} {
		if p := r.read(filepath.Join("pressure", kind)); p != "" {
			for _, line := range strings.Split(strings.TrimSpace(p), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					fmt.Fprintf(&b, "pressure %-6s %-4s %s %s\n", kind, fields[0], fields[1], fields[2])
				}
			}
		}
	}
	procs, stuck := r.processes()
	fmt.Fprintf(&b, "blocked  %d processes in uninterruptible sleep\n", len(stuck))
	for _, p := range stuck {
		fmt.Fprintf(&b, "         %d %s\n", p.pid, p.name)
	}
	fmt.Fprintln(&b, "largest")
	for _, p := range procs {
		fmt.Fprintf(&b, "         %6d MiB  %d %s\n", p.rss/1024, p.pid, p.name)
	}
	return b.String()
}

func (r Rescue) Restart(force bool, logf func(string, ...any)) {
	go func() {
		time.Sleep(r.Grace)
		if !force {
			ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
			defer cancel()
			if err := exec.CommandContext(ctx, r.Reboot[0], r.Reboot[1:]...).Run(); err != nil {
				logf("sdb reboot through init failed", "err", err.Error())
			}
			return
		}
		if err := r.trigger("s"); err == nil {
			time.Sleep(r.Pause)
			_ = r.trigger("u")
			time.Sleep(r.Pause / 2)
			if err := r.trigger("b"); err == nil {
				return
			}
		}
		logf("sdb sysrq unavailable, restarting through the kernel call")
		if err := r.Kernel(); err != nil {
			logf("sdb forced reboot failed", "err", err.Error())
		}
	}()
}

func (r Rescue) trigger(key string) error {
	f, err := os.OpenFile(r.Sysrq, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(key)
	return err
}

func (r Rescue) read(name string) string {
	data, err := os.ReadFile(filepath.Join(r.Proc, name))
	if err != nil {
		return ""
	}
	return string(data)
}

func (r Rescue) meminfo() map[string]int64 {
	out := map[string]int64{}
	f, err := os.Open(filepath.Join(r.Proc, "meminfo"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			out[strings.TrimSuffix(fields[0], ":")] = v
		}
	}
	return out
}

type process struct {
	pid  int
	name string
	rss  int64
}

func (r Rescue) processes() ([]process, []process) {
	entries, err := os.ReadDir(r.Proc)
	if err != nil {
		return nil, nil
	}
	page := int64(os.Getpagesize() / 1024)
	var all, stuck []process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat := r.read(filepath.Join(e.Name(), "stat"))
		open, end := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
		if open < 0 || end < open {
			continue
		}
		rest := strings.Fields(stat[end+1:])
		if len(rest) < 22 {
			continue
		}
		p := process{pid: pid, name: stat[open+1 : end]}
		if pages, err := strconv.ParseInt(rest[21], 10, 64); err == nil {
			p.rss = pages * page
		}
		if rest[0] == "D" {
			stuck = append(stuck, p)
		}
		all = append(all, p)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].rss > all[j].rss })
	if len(all) > 5 {
		all = all[:5]
	}
	return all, stuck
}
