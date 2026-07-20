package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fpA = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899"
const fpB = "0011223344556677889900112233445566778899001122334455667788990011"

func TestAbsentKeystoreTrustsNobody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("an absent keystore should open empty: %v", err)
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("an absent keystore listed %d hosts", len(got))
	}
	for _, fp := range []string{fpA, fpB, ""} {
		if _, ok := s.Trusted(fp); ok {
			t.Fatalf("an absent keystore trusted %q", fp)
		}
	}
	t.Log("absent keystore: zero hosts, every fingerprint refused")
}

func TestDamagedKeystoreIsAnErrorNotAnEmptySet(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"truncated json", `{"version":1,"hosts":[{"label":"a",`},
		{"not json at all", "\x00\x01binary rubbish"},
		{"empty file", ""},
		{"wrong version", `{"version":99,"hosts":[]}`},
		{"entry with no fingerprint", `{"version":1,"hosts":[{"label":"a","fingerprint":""}]}`},
		{"entry with no label", `{"version":1,"hosts":[{"label":"","fingerprint":"` + fpA + `"}]}`},
		{"hosts is not a list", `{"version":1,"hosts":"everyone"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "keystore.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := Open(path)
			if err == nil {
				t.Fatalf("a damaged keystore opened cleanly with %d hosts", len(s.List()))
			}
			if s != nil {
				t.Fatal("a damaged keystore returned a usable store")
			}
			t.Logf("refused to open: %v", err)
		})
	}
}

func TestUnreadableKeystoreIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, file permissions do not deny reads")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"hosts":[]}`), 0o000); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err == nil {
		t.Fatalf("an unreadable keystore opened cleanly with %d hosts", len(s.List()))
	}
	t.Logf("refused to open: %v", err)
}

func TestAddTrustAndRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return clock })

	if err := s.Add("laptop", fpA); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, ok := s.Trusted(fpA); !ok {
		t.Fatal("a paired key should be trusted")
	}
	if _, ok := s.Trusted(fpB); ok {
		t.Fatal("an unpaired key must never be trusted")
	}

	// The record must survive a reopen, or trust would evaporate on reboot.
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	h, ok := reopened.Trusted(fpA)
	if !ok {
		t.Fatal("the pairing did not survive a reopen")
	}
	if h.Label != "laptop" || !h.PairedAt.Equal(clock) {
		t.Fatalf("reopened entry is %+v", h)
	}
	if !h.LastUsed.IsZero() {
		t.Fatal("a host that never connected should carry no last-used time")
	}

	clock = clock.Add(time.Hour)
	reopened.SetClock(func() time.Time { return clock })
	if err := reopened.Touch(fpA); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if got := reopened.List()[0].LastUsed; !got.Equal(clock) {
		t.Fatalf("last used is %v, want %v", got, clock)
	}

	if err := reopened.Remove("laptop"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, ok := reopened.Trusted(fpA); ok {
		t.Fatal("a revoked key must no longer be trusted")
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Trusted(fpA); ok {
		t.Fatal("the revocation did not survive a reopen")
	}
	t.Log("revocation is durable: the key is refused after reopening the file")
}

func TestRemoveUnknownLabel(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "keystore.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("never-paired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove returned %v, want %v", err, ErrNotFound)
	}
}

func TestRepairingReplacesTheOldEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add("laptop", fpA); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("laptop", fpB); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 1 {
		t.Fatalf("re-pairing left %d entries, want 1", len(s.List()))
	}
	if _, ok := s.Trusted(fpA); ok {
		t.Fatal("the superseded key must no longer be trusted")
	}
	if _, ok := s.Trusted(fpB); !ok {
		t.Fatal("the new key should be trusted")
	}
}

func TestAddRejectsEmptyFields(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "keystore.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add("", fpA); err == nil {
		t.Fatal("an empty label should be refused")
	}
	if err := s.Add("laptop", ""); err == nil {
		t.Fatal("an empty fingerprint should be refused")
	}
	if _, ok := s.Trusted(""); ok {
		t.Fatal("an empty fingerprint must never be trusted")
	}
}
