// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// known.go records, host side, which devices this machine has paired with and
// what key each one presented. It is the mirror of the device's keystore, and
// it fails closed the same way: a file that will not parse is an error, not an
// empty list, because an empty list would drop the pins that keep a later
// connection from being answered by somebody else.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ErrUnknownDevice is returned when no record matches.
var ErrUnknownDevice = errors.New("no paired device matches")

const knownVersion = 1

// Device is one device this host has paired with.
type Device struct {
	Address     string    `json:"address"`
	Fingerprint string    `json:"fingerprint"`
	Label       string    `json:"label"`
	PairedAt    time.Time `json:"paired_at"`
}

type knownFile struct {
	Version int      `json:"version"`
	Devices []Device `json:"devices"`
}

// Known is the host's record of paired devices.
type Known struct {
	path    string
	devices []Device
}

// OpenKnown reads the record at path. A missing file yields an empty record.
func OpenKnown(path string) (*Known, error) {
	k := &Known{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read known devices: %w", err)
	}
	var f knownFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse known devices %s: %w", path, err)
	}
	if f.Version != knownVersion {
		return nil, fmt.Errorf("parse known devices %s: unsupported version %d", path, f.Version)
	}
	k.devices = f.Devices
	return k, nil
}

// List returns the paired devices, ordered by address.
func (k *Known) List() []Device {
	out := make([]Device, len(k.devices))
	copy(out, k.devices)
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// Lookup returns the record for an address.
func (k *Known) Lookup(addr string) (Device, error) {
	addr = normalise(addr)
	for _, d := range k.devices {
		if d.Address == addr {
			return d, nil
		}
	}
	return Device{}, ErrUnknownDevice
}

// Only returns the single paired device, so the CLI can act without an address
// in the common case of one device. With none or several it refuses rather than
// picking one, because guessing which device to talk to is how the wrong device
// gets a command.
func (k *Known) Only() (Device, error) {
	switch len(k.devices) {
	case 0:
		return Device{}, ErrUnknownDevice
	case 1:
		return k.devices[0], nil
	default:
		return Device{}, errors.New("several devices are paired, name one with -addr")
	}
}

// Add records a pairing, replacing any earlier record for the same address.
func (k *Known) Add(d Device) error {
	d.Address = normalise(d.Address)
	next := make([]Device, 0, len(k.devices)+1)
	for _, e := range k.devices {
		if e.Address != d.Address {
			next = append(next, e)
		}
	}
	k.devices = append(next, d)
	return k.save()
}

func (k *Known) save() error {
	data, err := json.MarshalIndent(knownFile{Version: knownVersion, Devices: k.devices}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode known devices: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(k.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".devices-*")
	if err != nil {
		return fmt.Errorf("write known devices: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write known devices: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write known devices: %w", err)
	}
	if err := os.Rename(tmpName, k.path); err != nil {
		return fmt.Errorf("write known devices: %w", err)
	}
	return nil
}
