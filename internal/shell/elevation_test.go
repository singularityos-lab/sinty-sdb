// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import "testing"

// The tiers, and the one invariant that must never break: a shell is root only
// when root was requested AND the broker granted it. Every other case falls to
// the logged-in user, then the isolated bridge, then refusal, never the daemon's
// own root.
func TestAccessResolveTiers(t *testing.T) {
	login := Identity{UID: 1000, GID: 1000}
	bridge := Identity{UID: 990, GID: 990}
	full := Access{Login: login, Bridge: bridge}

	cases := []struct {
		name        string
		access      Access
		rootReq     bool
		rootGranted bool
		wantTier    string
		wantUID     uint32 // 0 means nil credential (kept root)
		wantOK      bool
	}{
		{"default drops to login", full, false, false, "user", 1000, true},
		{"grant without request stays user", full, false, true, "user", 1000, true},
		{"refused root falls to user, not root", full, true, false, "user", 1000, true},
		{"requested and granted is root", full, true, true, "root", 0, true},
		{"no login falls to bridge", Access{Bridge: bridge}, false, false, "bridge", 990, true},
		{"refused root with no login falls to bridge", Access{Bridge: bridge}, true, false, "bridge", 990, true},
		{"nothing to drop to is refused", Access{}, false, false, "", 0, false},
		{"refused root with nothing is refused, not root", Access{}, true, false, "", 0, false},
	}
	for _, c := range cases {
		cred, tier, ok := c.access.Resolve(c.rootReq, c.rootGranted)
		if ok != c.wantOK {
			t.Fatalf("%s: ok=%v, want %v", c.name, ok, c.wantOK)
		}
		if tier != c.wantTier {
			t.Fatalf("%s: tier=%q, want %q", c.name, tier, c.wantTier)
		}
		if c.wantUID == 0 {
			if ok && cred != nil {
				t.Fatalf("%s: want nil credential (root/refuse), got %+v", c.name, cred)
			}
		} else {
			if cred == nil || cred.Uid != c.wantUID {
				t.Fatalf("%s: credential %+v, want uid %d", c.name, cred, c.wantUID)
			}
		}
	}
}
