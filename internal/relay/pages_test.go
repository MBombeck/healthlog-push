package relay

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MBombeck/healthlog-push/internal/notice"
)

const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"

func TestPrefersHTML(t *testing.T) {
	for accept, want := range map[string]bool{
		"":                                     false,
		"*/*":                                  false,
		"text/*":                               false,
		"text/plain":                           false,
		"application/json":                     false,
		"text/html":                            true,
		"TEXT/HTML":                            true,
		"application/xhtml+xml":                true,
		browserAccept:                          true,
		"text/html;q=0":                        false,
		"text/html;q=0.0, */*":                 false,
		"text/html;q=abc":                      false,
		"text/html;q=2":                        false,
		"text/html, text/plain":                false,
		"text/plain;q=0.5, text/html":          true,
		"text/plain, text/html;q=0.9":          false,
		"text/html ; q=0.8 , text/plain;q=0.7": true,
		"text/htmlx, text/html-ish":            false,
	} {
		var h []string
		if accept != "" {
			h = []string{accept}
		}
		if got := prefersHTML(h); got != want {
			t.Errorf("Accept %q: HTML %v, want %v", accept, got, want)
		}
	}
	if !prefersHTML([]string{"application/json", "text/html"}) {
		t.Error("an Accept header split over two lines is not read as a whole")
	}
}

// TestHumanPagesNegotiate: a browser gets HTML, every other client gets the plain text exactly as before,
// and both carry Vary: Accept. The .txt paths always answer plain text.
func TestHumanPagesNegotiate(t *testing.T) {
	h := newHarness(t)
	get := func(path, accept string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, http.NoBody)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, b
	}
	pages := map[string]string{"/privacy": notice.Privacy, "/terms": notice.Terms, "/": notice.Index}
	for path, text := range pages {
		for _, accept := range []string{"", "*/*", "text/plain", "application/json", "text/html;q=0", "text/plain, text/html"} {
			resp, body := get(path, accept)
			if resp.StatusCode != http.StatusOK || string(body) != text {
				t.Errorf("%s Accept %q: status %d, body differs from the text", path, accept, resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Errorf("%s Accept %q: Content-Type %q", path, accept, ct)
			}
			if resp.Header.Get("Vary") != "Accept" || resp.Header.Get("Content-Security-Policy") != "default-src 'none'" {
				t.Errorf("%s Accept %q: Vary %q, CSP %q", path, accept, resp.Header.Get("Vary"), resp.Header.Get("Content-Security-Policy"))
			}
		}
		for _, accept := range []string{browserAccept, "text/html"} {
			resp, body := get(path, accept)
			if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "<!doctype html>") {
				t.Errorf("%s Accept %q: status %d, no HTML", path, accept, resp.StatusCode)
			}
			for k, want := range map[string]string{
				"Content-Type":              "text/html; charset=utf-8",
				"Content-Security-Policy":   notice.HTMLPolicy,
				"Strict-Transport-Security": "max-age=31536000",
				"X-Content-Type-Options":    "nosniff",
				"Cache-Control":             "no-store",
				"Vary":                      "Accept",
				"X-Frame-Options":           "DENY",
				"Referrer-Policy":           "no-referrer",
			} {
				if got := resp.Header.Values(k); len(got) != 1 || got[0] != want {
					t.Errorf("%s HTML: %s %q, want %q", path, k, got, want)
				}
			}
			if resp.Header.Get("HL-Relay-Signature") != "" {
				t.Errorf("%s HTML is signed; only the JSON replies are", path)
			}
		}
	}
	for path, text := range map[string]string{"/privacy.txt": notice.Privacy, "/terms.txt": notice.Terms} {
		resp, body := get(path, browserAccept)
		if resp.StatusCode != http.StatusOK || string(body) != text || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("%s: status %d, Content-Type %q, body equal %v", path, resp.StatusCode, resp.Header.Get("Content-Type"), string(body) == text)
		}
	}
	// HEAD follows the same choice and sends no body.
	req, _ := http.NewRequest(http.MethodHead, h.srv.URL+"/privacy", http.NoBody)
	req.Header.Set("Accept", browserAccept)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("HEAD /privacy: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}
