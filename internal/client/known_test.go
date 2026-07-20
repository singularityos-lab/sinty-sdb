package client

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const deviceFP = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899"

func TestAbsentRecordKnowsNoDevices(t *testing.T) {
	k, err := OpenKnown(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatalf("an absent record should open empty: %v", err)
	}
	if len(k.List()) != 0 {
		t.Fatal("an absent record listed devices")
	}
	if _, err := k.Only(); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("only returned %v, want %v", err, ErrUnknownDevice)
	}
	if _, err := k.Lookup("192.0.2.1:5555"); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("lookup returned %v, want %v", err, ErrUnknownDevice)
	}
}

func TestDamagedRecordIsAnErrorNotAnEmptyList(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"truncated json", `{"version":1,"devices":[{`},
		{"not json at all", "rubbish"},
		{"empty file", ""},
		{"wrong version", `{"version":42,"devices":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "devices.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			k, err := OpenKnown(path)
			if err == nil {
				t.Fatalf("a damaged record opened cleanly with %d devices", len(k.List()))
			}
			t.Logf("refused to open: %v", err)
		})
	}
}

func TestAddLookupAndOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	k, err := OpenKnown(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Add(Device{Address: "192.0.2.10", Fingerprint: deviceFP, Label: "laptop", PairedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// The address is normalised on the way in, so a bare host still resolves.
	reopened, err := OpenKnown(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := reopened.Lookup("192.0.2.10")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if d.Fingerprint != deviceFP {
		t.Fatal("the pinned device key did not survive a reopen")
	}
	if d.Address != "192.0.2.10:5555" {
		t.Fatalf("address stored as %q, want the default port appended", d.Address)
	}
	if _, err := reopened.Only(); err != nil {
		t.Fatalf("only: %v", err)
	}

	// With two devices the CLI must refuse to guess which one is meant.
	if err := reopened.Add(Device{Address: "192.0.2.11", Fingerprint: deviceFP, Label: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Only(); err == nil {
		t.Fatal("only should refuse when several devices are paired")
	} else {
		t.Logf("refused to guess: %v", err)
	}
}

func TestRepairingReplacesTheAddressRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	k, err := OpenKnown(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Add(Device{Address: "192.0.2.10", Fingerprint: deviceFP}); err != nil {
		t.Fatal(err)
	}
	other := "0011223344556677889900112233445566778899001122334455667788990011"
	if err := k.Add(Device{Address: "192.0.2.10:5555", Fingerprint: other}); err != nil {
		t.Fatal(err)
	}
	if len(k.List()) != 1 {
		t.Fatalf("re-pairing left %d records, want 1", len(k.List()))
	}
	d, err := k.Lookup("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if d.Fingerprint != other {
		t.Fatal("the record still pins the superseded device key")
	}
}
