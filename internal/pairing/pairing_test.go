package pairing

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	hostFP  = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899"
	otherFP = "0011223344556677889900112233445566778899001122334455667788990011"
)

// testClock is a hand-driven clock, so expiry and backoff are proved rather
// than waited for.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestManager() (*Manager, *testClock) {
	clk := &testClock{t: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)}
	m := NewManager()
	m.SetClock(clk.now)
	return m, clk
}

func startPaired(t *testing.T) (*Manager, *testClock, string) {
	t.Helper()
	m, clk := newTestManager()
	code, _, err := m.Start()
	if err != nil {
		t.Fatalf("start pairing: %v", err)
	}
	if err := m.Begin(hostFP, "laptop"); err != nil {
		t.Fatalf("begin pairing: %v", err)
	}
	return m, clk, code
}

func TestCodeShape(t *testing.T) {
	m, _ := newTestManager()
	seen := map[string]bool{}
	for i := range 64 {
		code, expires, err := m.Start()
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if len(code) != codeDigits {
			t.Fatalf("code %q is %d digits, want %d", code, len(code), codeDigits)
		}
		if strings.Trim(code, "0123456789") != "" {
			t.Fatalf("code %q is not numeric", code)
		}
		if expires.IsZero() {
			t.Fatal("code has no expiry")
		}
		seen[code] = true
	}
	// Not a randomness test, only a guard against a constant or a counter.
	if len(seen) < 32 {
		t.Fatalf("64 codes produced only %d distinct values", len(seen))
	}
}

func TestSubmitRefusals(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T) (m *Manager, fingerprint, code string)
		want    error
	}{
		{
			name: "wrong code is refused",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m, _, code := startPaired(t)
				return m, hostFP, wrongCode(code)
			},
			want: ErrBadCode,
		},
		{
			name: "expired code is refused",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m, clk, code := startPaired(t)
				clk.advance(DefaultTTL + time.Second)
				return m, hostFP, code
			},
			want: ErrNoSession,
		},
		{
			name: "code expiring exactly on its deadline is refused",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m, clk, code := startPaired(t)
				clk.advance(DefaultTTL)
				return m, hostFP, code
			},
			want: ErrNoSession,
		},
		{
			name: "correct code offered a second time is refused",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m, _, code := startPaired(t)
				if err := m.Submit(hostFP, code); err != nil {
					t.Fatalf("first submit should succeed: %v", err)
				}
				return m, hostFP, code
			},
			want: ErrNoSession,
		},
		{
			name: "code submitted with no session open is refused",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m, _ := newTestManager()
				return m, hostFP, "000000"
			},
			want: ErrNoSession,
		},
		{
			name: "code submitted without presenting a key first is refused",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m, _ := newTestManager()
				code, _, err := m.Start()
				if err != nil {
					t.Fatalf("start pairing: %v", err)
				}
				return m, hostFP, code
			},
			want: ErrNoAttempt,
		},
		{
			name: "correct code from a key other than the pending one is refused",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m, _, code := startPaired(t)
				return m, otherFP, code
			},
			want: ErrNoAttempt,
		},
		{
			name: "cancelled session refuses its own code",
			prepare: func(t *testing.T) (*Manager, string, string) {
				m, _, code := startPaired(t)
				m.Cancel()
				return m, hostFP, code
			},
			want: ErrNoSession,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, fp, code := tc.prepare(t)
			err := m.Submit(fp, code)
			if !errors.Is(err, tc.want) {
				t.Fatalf("submit returned %v, want %v", err, tc.want)
			}
			t.Logf("refused as required: %v", err)
		})
	}
}

func TestHappyPathAccepts(t *testing.T) {
	m, _, code := startPaired(t)
	if err := m.Submit(hostFP, code); err != nil {
		t.Fatalf("the correct code should be accepted: %v", err)
	}
	if st := m.State(); st.Active {
		t.Fatal("the session should be consumed once the code is accepted")
	}
}

func TestRateLimitTriggersAndBacksOff(t *testing.T) {
	m, clk, code := startPaired(t)
	bad := wrongCode(code)

	// First wrong attempt: refused, and a lock window opens.
	if err := m.Submit(hostFP, bad); !errors.Is(err, ErrBadCode) {
		t.Fatalf("first wrong attempt returned %v, want %v", err, ErrBadCode)
	}
	err := m.Submit(hostFP, code)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("the correct code during the lock window returned %v, want %v", err, ErrLocked)
	}
	t.Logf("locked out even with the right code: %v", err)

	// The lock is what makes guessing expensive: prove it grows.
	var windows []time.Duration
	for attempt := 1; attempt <= 3; attempt++ {
		st := m.State()
		if st.LockedUntil.IsZero() {
			t.Fatalf("attempt %d left no lock window", attempt)
		}
		windows = append(windows, st.LockedUntil.Sub(clk.t))
		clk.advance(st.LockedUntil.Sub(clk.t))
		if err := m.Submit(hostFP, bad); !errors.Is(err, ErrBadCode) {
			t.Fatalf("attempt %d returned %v, want %v", attempt+1, err, ErrBadCode)
		}
	}
	t.Logf("backoff windows after successive wrong codes: %v", windows)
	for i := 1; i < len(windows); i++ {
		if windows[i] <= windows[i-1] {
			t.Fatalf("backoff did not grow: %v", windows)
		}
	}

	// The fifth wrong attempt destroys the session outright.
	st := m.State()
	clk.advance(st.LockedUntil.Sub(clk.t))
	if err := m.Submit(hostFP, bad); !errors.Is(err, ErrLocked) {
		t.Fatalf("final attempt returned %v, want %v", err, ErrLocked)
	}
	if err := m.Submit(hostFP, code); !errors.Is(err, ErrNoSession) {
		t.Fatalf("after the attempt limit the correct code returned %v, want %v", err, ErrNoSession)
	}
	t.Log("attempt limit reached: the session is gone and the correct code no longer works")
}

func TestBeginRefusals(t *testing.T) {
	t.Run("no session open", func(t *testing.T) {
		m, _ := newTestManager()
		if err := m.Begin(hostFP, "laptop"); !errors.Is(err, ErrNoSession) {
			t.Fatalf("begin returned %v, want %v", err, ErrNoSession)
		}
	})
	t.Run("expired session", func(t *testing.T) {
		m, clk := newTestManager()
		if _, _, err := m.Start(); err != nil {
			t.Fatal(err)
		}
		clk.advance(DefaultTTL + time.Second)
		if err := m.Begin(hostFP, "laptop"); !errors.Is(err, ErrNoSession) {
			t.Fatalf("begin returned %v, want %v", err, ErrNoSession)
		}
	})
	t.Run("during a lock window", func(t *testing.T) {
		m, _, code := startPaired(t)
		if err := m.Submit(hostFP, wrongCode(code)); !errors.Is(err, ErrBadCode) {
			t.Fatal("expected a refusal")
		}
		if err := m.Begin(otherFP, "another"); !errors.Is(err, ErrLocked) {
			t.Fatalf("begin returned %v, want %v", err, ErrLocked)
		}
	})
}

func TestStateExposesWhatAUINeeds(t *testing.T) {
	m, _, code := startPaired(t)
	st := m.State()
	if !st.Active {
		t.Fatal("state should report an open session")
	}
	if st.Code != code {
		t.Fatal("state should carry the code for the screen")
	}
	if st.PendingFingerprint != hostFP {
		t.Fatalf("state carries fingerprint %q, want the offered host key", st.PendingFingerprint)
	}
	if st.PendingLabel != "laptop" {
		t.Fatalf("state carries label %q, want laptop", st.PendingLabel)
	}
}

func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}
