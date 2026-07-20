// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// control.go exposes the daemon to local UIs over a unix socket, using the same
// HTTP-and-JSON shape the recovery agent serves to its Cairo UI.
//
// This is where the pairing code and the offered host fingerprint leave the
// daemon, and the only place they do. The socket is local and mode 0660, so
// reaching it already means being on the device; the network listener never
// discloses either value.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"

	"github.com/singularityos-lab/sinty-sdb/internal/keys"
	"github.com/singularityos-lab/sinty-sdb/internal/keystore"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ControlHandler builds the local API routes (split from ServeControl so it is
// testable without a socket).
func (s *Server) ControlHandler() http.Handler {
	mux := http.NewServeMux()

	// GET /device returns {"fingerprint","fingerprint_display"}
	mux.HandleFunc("GET /device", func(w http.ResponseWriter, r *http.Request) {
		fp := s.id.Fingerprint()
		writeJSON(w, http.StatusOK, map[string]any{
			"fingerprint":         fp,
			"fingerprint_display": keys.Display(fp),
		})
	})

	// POST /pairing/start returns {"ok","code","expires_at"}
	mux.HandleFunc("POST /pairing/start", func(w http.ResponseWriter, r *http.Request) {
		code, expires, err := s.pair.Start()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"code":       code,
			"expires_at": expires,
		})
	})

	// GET /pairing/state returns {"active","code","expires_at","pending_fingerprint",
	//   "pending_fingerprint_display","pending_label","attempts","locked_until"}
	mux.HandleFunc("GET /pairing/state", func(w http.ResponseWriter, r *http.Request) {
		st := s.pair.State()
		body := map[string]any{
			"active":                      st.Active,
			"code":                        st.Code,
			"pending_fingerprint":         st.PendingFingerprint,
			"pending_fingerprint_display": keys.Display(st.PendingFingerprint),
			"pending_label":               st.PendingLabel,
			"attempts":                    st.Attempts,
		}
		// A zero time must be absent rather than sent as a year-1 stamp: a strict
		// reader would take that for a real deadline. The omitzero tags on the
		// struct do not apply here because the body is built as a map.
		if !st.ExpiresAt.IsZero() {
			body["expires_at"] = st.ExpiresAt
		}
		if !st.LockedUntil.IsZero() {
			body["locked_until"] = st.LockedUntil
		}
		writeJSON(w, http.StatusOK, body)
	})

	// POST /pairing/cancel returns {"ok"}
	mux.HandleFunc("POST /pairing/cancel", func(w http.ResponseWriter, r *http.Request) {
		s.pair.Cancel()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// GET /hosts returns {"hosts":[{"label","fingerprint","fingerprint_display","paired_at","last_used"}]}
	mux.HandleFunc("GET /hosts", func(w http.ResponseWriter, r *http.Request) {
		hosts := s.store.List()
		out := make([]map[string]any, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, map[string]any{
				"label":               h.Label,
				"fingerprint":         h.Fingerprint,
				"fingerprint_display": keys.Display(h.Fingerprint),
				"paired_at":           h.PairedAt,
				"last_used":           h.LastUsed,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
	})

	// POST /hosts/revoke {"label"} returns {"ok","error"}
	mux.HandleFunc("POST /hosts/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Label string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := s.store.Remove(req.Label); err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, keystore.ErrNotFound) {
				code = http.StatusNotFound
			}
			writeJSON(w, code, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.log.Info("sdb host revoked", "label", req.Label)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	return mux
}

// ServeControl exposes the local API on a unix socket until ctx is cancelled.
func (s *Server) ServeControl(ctx context.Context, socketPath string) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(socketPath, 0o660)

	srv := &http.Server{Handler: s.ControlHandler()}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
