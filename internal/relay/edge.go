package relay

import (
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// edge wraps the router with the checks every request passes before a handler runs: security headers,
// the mandatory nonce under /v1, canonical paths only, and the declared body length with its reservation
// against the global budget for buffered bodies.
func (r *Relay) edge(mux *http.ServeMux) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "default-src 'none'")
		if status, e, refused := edgeRefusal(mux, req); refused {
			r.fail(w, req, status, e)
			return
		}
		if req.Method == http.MethodPost || req.Method == http.MethodDelete {
			if !r.reserveBody(req.ContentLength) {
				r.Metrics.Inc("hlp_body_budget_refused_total")
				r.fail(w, req, http.StatusServiceUnavailable, errBody{Error: "overloaded", RetryAfter: jitter(2 * time.Second)})
				return
			}
			defer r.releaseBody(req.ContentLength)
		}
		mux.ServeHTTP(w, req)
	}
}

// edgeRefusal decides the refusals that need nothing but the request line and the headers.
func edgeRefusal(mux *http.ServeMux, req *http.Request) (int, errBody, bool) {
	p := req.URL.Path
	// Every /v1 request carries a nonce so that its signed response cannot be replayed onto another request
	// (spec/statements.md, hl-relay-resp-v2). Only the public monitoring endpoints may omit it. Checked
	// before routing, so even a 404 under /v1 is bound to a nonce.
	if p == "/v1" || strings.HasPrefix(p, "/v1/") {
		if _, err := wire.ParseNonce(req.Header.Get("HL-Nonce")); err != nil {
			return http.StatusBadRequest, errBody{Error: "nonce_required"}, true
		}
	}
	// Only canonical paths are routed. ServeMux would answer a path like /v1//push with an unsigned
	// redirect; every answer here must be signed, so such paths are a plain signed 404.
	if path.Clean(p) != p {
		return http.StatusNotFound, errBody{Error: "not_found"}, true
	}
	if _, pattern := mux.Handler(req); pattern == "" {
		return http.StatusNotFound, errBody{Error: "not_found"}, true
	}
	// The body length must be declared and within the largest limit before any body byte is read.
	if req.Method == http.MethodPost || req.Method == http.MethodDelete {
		switch {
		case req.ContentLength < 0:
			return http.StatusLengthRequired, errBody{Error: "length_required"}, true
		case req.ContentLength > maxPushBody:
			return http.StatusRequestEntityTooLarge, errBody{Error: "too_large"}, true
		}
	}
	return 0, errBody{}, false
}
