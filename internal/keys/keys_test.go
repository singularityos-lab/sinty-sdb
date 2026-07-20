package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityIsStableAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir, "device")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := LoadOrCreate(dir, "device")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatal("reloading the identity produced a different key, which would silently void every pairing")
	}
	if len(first.Fingerprint()) != 64 {
		t.Fatalf("fingerprint %q is not a sha-256 hex digest", first.Fingerprint())
	}
}

func TestDistinctIdentitiesDiffer(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir(), "host")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(t.TempDir(), "host")
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("two separate identities share a fingerprint")
	}
}

func TestPrivateKeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir, "device"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("private key is mode %o, want 600", perm)
	}
}

func TestDamagedIdentityIsAnErrorNotAFreshKey(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, "device")
	if err != nil {
		t.Fatal(err)
	}
	original := id.Fingerprint()
	if err := os.WriteFile(filepath.Join(dir, "device.key"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreate(dir, "device")
	if err == nil {
		t.Fatalf("a damaged identity was replaced with a fresh one (%s, was %s)", again.Fingerprint(), original)
	}
	t.Logf("refused to load: %v", err)
}

func TestDisplayGroupsTheWholeFingerprint(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	got := Display(fp)
	if strings.ReplaceAll(got, " ", "") != strings.ToUpper(fp) {
		t.Fatalf("display dropped part of the fingerprint: %q", got)
	}
	if !strings.Contains(got, " ") {
		t.Fatal("display should group the fingerprint for reading")
	}
}
