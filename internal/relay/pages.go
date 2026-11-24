package relay

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/MBombeck/healthlog-push/internal/notice"
)

// humanPage serves a page people read in a browser: HTML to a client that asks for text/html, and to
// every other client (curl, a HealthLog server, a script that checks the text) the plain text, byte for
// byte as before. The HTML is rendered from the same text when the handler is built.
func humanPage(text string, page []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Vary", "Accept")
		if !prefersHTML(req.Header.Values("Accept")) {
			h.Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, text)
			return
		}
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", notice.HTMLPolicy)
		_, _ = w.Write(page)
	}
}

// mustPage panics on a notice text outside the markdown subset the renderer supports. The tests render
// every served text, so this cannot happen in a released build.
func mustPage(page []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return page
}

// prefersHTML reports whether the Accept header names text/html (or application/xhtml+xml) with a quality
// above zero and above the quality it gives text/plain. A wildcard alone, no header, or equal preference
// keeps the plain text, so only a client that asks for HTML gets it.
func prefersHTML(accept []string) bool {
	wantHTML, plain := 0.0, 0.0
	for _, v := range accept {
		for _, part := range strings.Split(v, ",") {
			media, params, _ := strings.Cut(part, ";")
			q := 1.0
			for _, p := range strings.Split(params, ";") {
				k, val, ok := strings.Cut(strings.TrimSpace(p), "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
					f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
					if err != nil || f < 0 || f > 1 {
						f = 0
					}
					q = f
				}
			}
			switch strings.ToLower(strings.TrimSpace(media)) {
			case "text/html", "application/xhtml+xml":
				wantHTML = max(wantHTML, q)
			case "text/plain":
				plain = max(plain, q)
			}
		}
	}
	return wantHTML > 0 && wantHTML > plain
}
