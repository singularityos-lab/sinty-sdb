package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-sdb/internal/client"
	"github.com/singularityos-lab/sinty-sdb/internal/keys"
	"github.com/singularityos-lab/sinty-sdb/internal/keystore"
	"github.com/singularityos-lab/sinty-sdb/internal/pairing"
	"github.com/singularityos-lab/sinty-sdb/internal/protocol"
	"github.com/singularityos-lab/sinty-sdb/internal/transfer"
)

// harness is a live device daemon on a loopback port, plus the pieces a test
// needs to reach inside it.
type harness struct {
	srv   *Server
	addr  string
	store *keystore.Store
	pair  *pairing.Manager
	root  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	id, err := keys.LoadOrCreate(dir, "device")
	if err != nil {
		t.Fatalf("device identity: %v", err)
	}
	store, err := keystore.Open(filepath.Join(dir, "keystore.json"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	pm := pairing.NewManager()
	root := filepath.Join(dir, "files")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Identity: id,
		Store:    store,
		Pairing:  pm,
		Root:     root,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("daemon: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()
	return &harness{srv: srv, addr: ln.Addr().String(), store: store, pair: pm, root: root}
}

// newHost builds a host identity in its own directory.
func newHost(t *testing.T) *client.Client {
	t.Helper()
	id, err := keys.LoadOrCreate(t.TempDir(), "host")
	if err != nil {
		t.Fatalf("host identity: %v", err)
	}
	return client.New(id)
}

// startPairing opens a window on the device and returns the code its screen
// would show, read back through the local control API exactly as a UI would.
func (h *harness) startPairing(t *testing.T) string {
	t.Helper()
	rec := h.control(t, http.MethodPost, "/pairing/start", nil)
	var body struct {
		OK   bool   `json:"ok"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode pairing start: %v", err)
	}
	if !body.OK || body.Code == "" {
		t.Fatalf("pairing start returned %s", rec.Body.String())
	}
	return body.Code
}

func (h *harness) control(t *testing.T, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	rec := httptest.NewRecorder()
	h.srv.ControlHandler().ServeHTTP(rec, req)
	return rec
}

// TestPairThenConnectByKeyAlone walks the whole level 1 and level 2 path.
func TestPairThenConnectByKeyAlone(t *testing.T) {
	h := newHarness(t)
	host := newHost(t)
	code := h.startPairing(t)

	conn, err := host.Dial(h.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	deviceFP, err := client.PairBegin(conn, "laptop")
	if err != nil {
		t.Fatalf("pair begin: %v", err)
	}
	if deviceFP != h.srv.Fingerprint() {
		t.Fatal("the device reported a key other than its own")
	}

	// The device must be showing this host's fingerprint before any code is
	// typed, so the user can compare it. Read it back the way a UI would.
	if got := h.pair.PendingFingerprint(); got != host.Fingerprint() {
		t.Fatalf("device shows fingerprint %q, want the host's own", got)
	}
	t.Logf("device screen shows host key %s", keys.Display(host.Fingerprint()))

	if err := client.PairSubmit(conn, "laptop", code); err != nil {
		t.Fatalf("pair submit: %v", err)
	}
	conn.Close()

	if _, ok := h.store.Trusted(host.Fingerprint()); !ok {
		t.Fatal("the host key was not persisted to the keystore")
	}

	// Level 2: a fresh connection carrying no code at all, pinned to the device
	// key learned during pairing.
	conn2, err := host.Dial(h.addr, deviceFP)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer conn2.Close()
	if err := client.Hello(conn2); err != nil {
		t.Fatalf("a paired host should be accepted by key alone: %v", err)
	}
	hosts, err := client.ListHosts(conn2)
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Label != "laptop" {
		t.Fatalf("device lists %+v, want one host labelled laptop", hosts)
	}
	if hosts[0].LastUsed.IsZero() {
		t.Fatal("connecting should stamp the host as used")
	}
	t.Log("paired host accepted with no code, keystore stamped")
}

// TestUnknownKeyIsRefused is the level 2 negative proof: a host that never
// paired gets nothing, and there is no first-connection grace to fall back on.
func TestUnknownKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	stranger := newHost(t)

	cases := []struct {
		name string
		call func(*protocol.Conn) error
	}{
		{"hello", client.Hello},
		{"list paired hosts", func(c *protocol.Conn) error { _, err := client.ListHosts(c); return err }},
		{"revoke a host", func(c *protocol.Conn) error { return client.Revoke(c, "laptop") }},
		{"submit a code without an open window", func(c *protocol.Conn) error {
			return client.PairSubmit(c, "stranger", "000000")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := stranger.Dial(h.addr, "")
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			err = tc.call(conn)
			if err == nil {
				t.Fatal("an unpaired host was allowed through")
			}
			t.Logf("refused: %v", err)
		})
	}
	if len(h.store.List()) != 0 {
		t.Fatal("a refused host left an entry in the keystore")
	}

	// Host-initiated pairing: PairBegin now OPENS a window (the code shows on the
	// device screen) instead of refusing, but opening a window is not pairing. No
	// key is stored until a correct on-screen code is submitted, so triggering a
	// window over the wire grants nothing by itself.
	t.Run("host-initiated PairBegin opens a window but does not pair", func(t *testing.T) {
		conn, err := stranger.Dial(h.addr, "")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		if _, err := client.PairBegin(conn, "stranger"); err != nil {
			t.Fatalf("host-initiated PairBegin should open a window: %v", err)
		}
		if err := client.PairSubmit(conn, "stranger", "000000"); err == nil {
			t.Fatal("a wrong code paired the host")
		}
		if len(h.store.List()) != 0 {
			t.Fatal("opening a window without the correct code stored the host")
		}
	})
}

// TestPairingRefusalsOverTheWire proves the code rules hold through the real
// transport, not only inside the pairing package.
func TestPairingRefusalsOverTheWire(t *testing.T) {
	t.Run("wrong code is refused and nothing is stored", func(t *testing.T) {
		h := newHarness(t)
		host := newHost(t)
		code := h.startPairing(t)

		conn, err := host.Dial(h.addr, "")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		if _, err := client.PairBegin(conn, "laptop"); err != nil {
			t.Fatalf("pair begin: %v", err)
		}
		err = client.PairSubmit(conn, "laptop", wrongCode(code))
		if err == nil {
			t.Fatal("a wrong code was accepted")
		}
		t.Logf("refused: %v", err)
		if _, ok := h.store.Trusted(host.Fingerprint()); ok {
			t.Fatal("a wrong code still stored the host key")
		}
		if len(h.store.List()) != 0 {
			t.Fatal("a wrong code left an entry in the keystore")
		}
	})

	t.Run("expired code is refused", func(t *testing.T) {
		h := newHarness(t)
		host := newHost(t)
		// A window that is already over by the time the host arrives.
		h.pair.SetTTL(time.Millisecond)
		code := h.startPairing(t)
		time.Sleep(20 * time.Millisecond)

		conn, err := host.Dial(h.addr, "")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		// The expired window is gone; a host-initiated PairBegin opens a FRESH one
		// with a new code shown on the device. The OLD (expired) code must not pair.
		if _, err := client.PairBegin(conn, "laptop"); err != nil {
			t.Fatalf("host-initiated PairBegin should open a fresh window: %v", err)
		}
		err = client.PairSubmit(conn, "laptop", code)
		if err == nil {
			t.Fatal("an expired code was accepted")
		}
		t.Logf("refused: %v", err)
		if len(h.store.List()) != 0 {
			t.Fatal("an expired code left an entry in the keystore")
		}
	})

	t.Run("a code that worked once is refused the second time", func(t *testing.T) {
		h := newHarness(t)
		first := newHost(t)
		second := newHost(t)
		code := h.startPairing(t)

		conn, err := first.Dial(h.addr, "")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if _, err := client.PairBegin(conn, "laptop"); err != nil {
			t.Fatalf("pair begin: %v", err)
		}
		if err := client.PairSubmit(conn, "laptop", code); err != nil {
			t.Fatalf("first pairing should succeed: %v", err)
		}
		conn.Close()

		// A second machine that somehow learned the code gets nowhere.
		conn2, err := second.Dial(h.addr, "")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn2.Close()
		// host2's PairBegin opens a fresh window (new code on the device); host1's
		// already-consumed code must not pair host2.
		if _, err := client.PairBegin(conn2, "second"); err != nil {
			t.Fatalf("host-initiated PairBegin should open a fresh window: %v", err)
		}
		if err := client.PairSubmit(conn2, "second", code); err == nil {
			t.Fatal("a consumed code was accepted a second time")
		} else {
			t.Logf("refused: %v", err)
		}
		if _, ok := h.store.Trusted(second.Fingerprint()); ok {
			t.Fatal("the reused code paired a second host")
		}
		if len(h.store.List()) != 1 {
			t.Fatalf("keystore holds %d hosts, want only the first", len(h.store.List()))
		}
	})

	t.Run("rate limiting triggers over the wire", func(t *testing.T) {
		h := newHarness(t)
		host := newHost(t)
		code := h.startPairing(t)

		conn, err := host.Dial(h.addr, "")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		if _, err := client.PairBegin(conn, "laptop"); err != nil {
			t.Fatalf("pair begin: %v", err)
		}
		if err := client.PairSubmit(conn, "laptop", wrongCode(code)); err == nil {
			t.Fatal("a wrong code was accepted")
		}
		// The next attempt, right or wrong, is inside the backoff window.
		err = client.PairSubmit(conn, "laptop", code)
		if err == nil {
			t.Fatal("the correct code was accepted during the lock window")
		}
		if !strings.Contains(err.Error(), "locked") {
			t.Fatalf("expected a lockout, got: %v", err)
		}
		t.Logf("locked out: %v", err)
		if len(h.store.List()) != 0 {
			t.Fatal("a locked-out attempt left an entry in the keystore")
		}
	})
}

// TestPinnedDeviceKeyRejectsAnImpostor proves the host side of the pin: a
// device answering on the right address with the wrong key is refused before a
// single frame is exchanged.
func TestPinnedDeviceKeyRejectsAnImpostor(t *testing.T) {
	real := newHarness(t)
	impostor := newHarness(t)
	host := newHost(t)

	code := real.startPairing(t)
	conn, err := host.Dial(real.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	deviceFP, err := client.PairBegin(conn, "laptop")
	if err != nil {
		t.Fatalf("pair begin: %v", err)
	}
	if err := client.PairSubmit(conn, "laptop", code); err != nil {
		t.Fatalf("pair submit: %v", err)
	}
	conn.Close()

	if _, err := host.Dial(impostor.addr, deviceFP); err == nil {
		t.Fatal("a device presenting a different key was accepted")
	} else {
		t.Logf("refused: %v", err)
	}
}

// TestRevocationEndsAccess proves trust can actually be taken back.
func TestRevocationEndsAccess(t *testing.T) {
	h := newHarness(t)
	host := newHost(t)
	code := h.startPairing(t)

	conn, err := host.Dial(h.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := client.PairBegin(conn, "laptop"); err != nil {
		t.Fatalf("pair begin: %v", err)
	}
	if err := client.PairSubmit(conn, "laptop", code); err != nil {
		t.Fatalf("pair submit: %v", err)
	}
	conn.Close()

	body := strings.NewReader(`{"label":"laptop"}`)
	rec := h.control(t, http.MethodPost, "/hosts/revoke", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke returned %d: %s", rec.Code, rec.Body.String())
	}

	conn2, err := host.Dial(h.addr, h.srv.Fingerprint())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn2.Close()
	if err := client.Hello(conn2); err == nil {
		t.Fatal("a revoked host was still accepted")
	} else {
		t.Logf("revoked host refused: %v", err)
	}
}

// TestUnknownRequestIsRefused covers the unparsable and unexpected input rule.
func TestUnknownRequestIsRefused(t *testing.T) {
	h := newHarness(t)
	host := newHost(t)
	conn, err := host.Dial(h.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.WriteRequest(protocol.Request{Op: "flash-everything"}); err != nil {
		t.Fatal(err)
	}
	resp, err := conn.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatal("an unknown request was accepted")
	}
	t.Logf("refused: %s", resp.Error)
}

func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// A live session must end when the daemon is stopped. Closing the listener only
// refuses new peers, so without this an already-connected host would keep its
// session and disabling the bridge would not actually end access.
func TestShutdownDropsLiveConnections(t *testing.T) {
	dir := t.TempDir()
	id, err := keys.LoadOrCreate(dir, "device")
	if err != nil {
		t.Fatalf("device identity: %v", err)
	}
	store, err := keystore.Open(filepath.Join(dir, "keystore.json"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	srv, err := New(Config{
		Identity: id,
		Store:    store,
		Pairing:  pairing.NewManager(),
		Root:     filepath.Join(dir, "files"),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("daemon: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for the daemon to have registered the session, so the control below
	// is about shutdown and not about a race with accept.
	var seen bool
	for i := 0; i < 200; i++ {
		srv.mu.Lock()
		seen = len(srv.live) == 1
		srv.mu.Unlock()
		if seen {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !seen {
		t.Fatal("daemon never registered the live session")
	}

	// Control: while the daemon is up the session stays open, so a read blocks
	// rather than returning. Without this the test would pass even if the
	// connection had never been alive.
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := conn.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("live session should have stayed open, read returned %v", err)
	}

	cancel()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("session survived shutdown, read returned %v", err)
	}
	srv.mu.Lock()
	remaining := len(srv.live)
	srv.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("daemon still tracks %d session(s) after shutdown", remaining)
	}
}

// TestPhaseTwoSessionUpgrade proves the OpSession handoff end to end over real
// TLS: a paired host upgrades the control connection to a mux session and the
// device's dispatch receives its streams. An unknown stream kind is used so the
// path is proven without dropping privileges or touching the filesystem: the
// device must close it with the unknown-kind code, which only happens if the
// upgrade and dispatch both ran.
func TestPhaseTwoSessionUpgrade(t *testing.T) {
	h := newHarness(t)
	host := newHost(t)
	code := h.startPairing(t)

	conn, err := host.Dial(h.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	deviceFP, err := client.PairBegin(conn, "laptop")
	if err != nil {
		t.Fatalf("pair begin: %v", err)
	}
	if err := client.PairSubmit(conn, "laptop", code); err != nil {
		t.Fatalf("pair submit: %v", err)
	}
	conn.Close()

	conn2, err := host.Dial(h.addr, deviceFP)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer conn2.Close()

	sess, err := client.OpenSession(conn2)
	if err != nil {
		t.Fatalf("a paired host should be able to open a phase-two session: %v", err)
	}
	st, err := sess.Open("no-such-kind")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := io.ReadAll(st); err != nil {
		t.Fatalf("read: %v", err)
	}
	if code, ok := st.ExitCode(); !ok || code != 2 {
		t.Fatalf("unknown kind closed with (%d,%v), want (2,true); dispatch not reached", code, ok)
	}

	out := filepath.Join(t.TempDir(), "device.key")
	if err := transfer.Pull(sess, "device.key", out); err == nil {
		t.Fatal("relative pull exposed the device identity")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("refused pull left output behind: %v", err)
	}

	if err := os.WriteFile(filepath.Join(h.root, "hello.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = filepath.Join(t.TempDir(), "hello.txt")
	if err := transfer.Pull(sess, "hello.txt", out); err != nil {
		t.Fatalf("pull from the transfer root: %v", err)
	}
	if got, err := os.ReadFile(out); err != nil || string(got) != "hello" {
		t.Fatalf("pulled %q, %v", got, err)
	}
	t.Log("paired host upgraded to a mux session and the device dispatched its stream")
}

// TestPhaseTwoSessionRefusedForUnpaired proves an unpaired host cannot open a
// session: the upgrade request is refused before any stream can be opened.
func TestPhaseTwoSessionRefusedForUnpaired(t *testing.T) {
	h := newHarness(t)
	stranger := newHost(t)

	conn, err := stranger.Dial(h.addr, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := client.OpenSession(conn); err == nil {
		t.Fatal("an unpaired host must not open a phase-two session")
	}
}
