// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import "testing"

// The one invariant that must never break: a shell is elevated only when root
// was requested AND granted. Every other case, above all a root request that
// was refused, must come back not elevated.
func TestCredentialFailsClosed(t *testing.T) {
	e := Elevation{BridgeUID: 103, BridgeGID: 103}
	cases := []struct {
		rootRequested bool
		granted       bool
		wantElevated  bool
	}{
		{false, false, false},
		{false, true, false}, // grant with no request must not elevate
		{true, false, false}, // refused root must not elevate (fail-closed)
		{true, true, true},   // requested and granted
	}
	for _, c := range cases {
		cred, elevated := e.Credential(c.rootRequested, c.granted)
		if elevated != c.wantElevated {
			t.Fatalf("Credential(root=%v,granted=%v) elevated=%v, want %v",
				c.rootRequested, c.granted, elevated, c.wantElevated)
		}
		if elevated && cred != nil {
			t.Fatalf("elevated shell must keep root (nil credential), got %+v", cred)
		}
		if !elevated && cred == nil {
			t.Fatalf("non-elevated shell must drop to the bridge user, got nil credential")
		}
		if !elevated && cred.Uid != 103 {
			t.Fatalf("non-elevated shell dropped to uid %d, want 103", cred.Uid)
		}
	}
}

// With no bridge user configured a non-elevated shell must not attempt a drop
// to uid 0, which would silently keep root.
func TestCredentialNoBridgeDoesNotKeepRootByDropping(t *testing.T) {
	cred, elevated := Elevation{}.Credential(true, false)
	if elevated {
		t.Fatal("refused root must not elevate")
	}
	if cred != nil && cred.Uid == 0 {
		t.Fatal("must not drop to uid 0 when no bridge user is configured")
	}
}
