package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestControlContract pins the shape the pairing UI renders against.
func TestControlContract(t *testing.T) {
	h := newHarness(t)

	t.Run("device", func(t *testing.T) {
		rec := h.control(t, http.MethodGet, "/device", nil)
		body := decode(t, rec.Body.Bytes())
		for _, k := range []string{"fingerprint", "fingerprint_display"} {
			if _, ok := body[k]; !ok {
				t.Errorf("device response missing %q (got %v)", k, body)
			}
		}
		if body["fingerprint"] != h.srv.Fingerprint() {
			t.Error("device response does not carry the daemon's own key")
		}
	})

	t.Run("idle pairing state", func(t *testing.T) {
		rec := h.control(t, http.MethodGet, "/pairing/state", nil)
		body := decode(t, rec.Body.Bytes())
		for _, k := range []string{
			"active", "code", "expires_at", "pending_fingerprint",
			"pending_fingerprint_display", "pending_label", "attempts", "locked_until",
		} {
			if _, ok := body[k]; !ok {
				t.Errorf("pairing state missing %q (got %v)", k, body)
			}
		}
		if body["active"] != false {
			t.Error("a fresh daemon should report no open pairing window")
		}
		if body["code"] != "" {
			t.Error("a fresh daemon should expose no code")
		}
	})

	t.Run("started pairing state carries the code", func(t *testing.T) {
		code := h.startPairing(t)
		rec := h.control(t, http.MethodGet, "/pairing/state", nil)
		body := decode(t, rec.Body.Bytes())
		if body["active"] != true {
			t.Fatal("pairing state should be active after start")
		}
		if body["code"] != code {
			t.Fatalf("pairing state carries code %v, want the one start returned", body["code"])
		}
	})

	t.Run("cancel closes the window", func(t *testing.T) {
		h.startPairing(t)
		if rec := h.control(t, http.MethodPost, "/pairing/cancel", nil); rec.Code != http.StatusOK {
			t.Fatalf("cancel returned %d", rec.Code)
		}
		body := decode(t, h.control(t, http.MethodGet, "/pairing/state", nil).Body.Bytes())
		if body["active"] != false {
			t.Fatal("the window should be closed after cancel")
		}
	})

	t.Run("hosts on a fresh device", func(t *testing.T) {
		rec := h.control(t, http.MethodGet, "/hosts", nil)
		body := decode(t, rec.Body.Bytes())
		hosts, ok := body["hosts"].([]any)
		if !ok {
			t.Fatalf("hosts response is %v", body)
		}
		if len(hosts) != 0 {
			t.Fatalf("a fresh device lists %d hosts", len(hosts))
		}
	})

	t.Run("revoking a label that is not there", func(t *testing.T) {
		rec := h.control(t, http.MethodPost, "/hosts/revoke", strings.NewReader(`{"label":"nobody"}`))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("revoke of an unknown label returned %d, want 404", rec.Code)
		}
	})

	t.Run("unparsable revoke body", func(t *testing.T) {
		rec := h.control(t, http.MethodPost, "/hosts/revoke", strings.NewReader(`{not json`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("an unparsable body returned %d, want 400", rec.Code)
		}
	})
}

func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return body
}
