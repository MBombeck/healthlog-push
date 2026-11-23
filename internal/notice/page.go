package notice

import (
	"crypto/sha256"
	"encoding/base64"
	"html"
	"regexp"
	"strings"
)

// Repository is the source repository linked from every page.
const Repository = "https://github.com/MBombeck/healthlog-push"

// style is the only style of the HTML pages. It is inline, and HTMLPolicy allows exactly this text by its
// hash, so the pages load nothing: no font, no script, no image, no other stylesheet.
const style = `
:root{color-scheme:light dark;--bg:#fbfbf8;--fg:#1d1f21;--muted:#5d6166;--rule:#e2e2dc;--link:#1f5fa8;--code:#f0f0ea}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--fg:#e4e4e0;--muted:#9a9ea4;--rule:#2c2e31;--link:#8ab8ef;--code:#222427}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:1.0625rem/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
header,main,footer{max-width:42rem;margin:0 auto;padding:0 1rem}
header{display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;align-items:baseline;justify-content:space-between;padding-top:1.25rem;padding-bottom:.75rem;border-bottom:1px solid var(--rule)}
header a{color:var(--muted);text-decoration:none;font-size:.9375rem}
header a.home{color:var(--fg);font-weight:600;letter-spacing:.01em}
header nav{display:flex;gap:1rem}
header a:hover{text-decoration:underline}
main{padding-top:1.5rem;padding-bottom:2rem}
h1{font-size:1.625rem;line-height:1.25;margin:.5rem 0 1rem}
h2{font-size:1.1875rem;line-height:1.3;margin:2.25rem 0 .5rem}
h3{font-size:1.0625rem;margin:1.75rem 0 .5rem}
p,ul,ol,pre{margin:0 0 1rem}
ul,ol{padding-left:1.5rem}
li{margin:.4rem 0}
a{color:var(--link);overflow-wrap:anywhere}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.875em}
code{background:var(--code);padding:.1em .3em;border-radius:3px;white-space:nowrap}
pre{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.6}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1.25rem;margin:1.5rem 0}
dt{color:var(--muted)}
dd{margin:0;overflow-wrap:anywhere}
@media (max-width:30rem){dl{grid-template-columns:1fr;gap:0}dd{margin-bottom:.6rem}}
footer{padding-top:1rem;padding-bottom:2.5rem;border-top:1px solid var(--rule);color:var(--muted);font-size:.875rem}
footer p{margin:0;display:flex;flex-wrap:wrap;gap:.25rem 1.25rem}
footer a{color:var(--muted)}
`

// HTMLPolicy is the Content-Security-Policy of the HTML pages: nothing may load, and the only style is the
// inline one above, allowed by its SHA-256 hash.
var HTMLPolicy = func() string {
	sum := sha256.Sum256([]byte(style))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

// HTMLPage wraps an HTML fragment in the page layout: a header with the relay's name and the two notices,
// the fragment, and a footer with the relay version, the plain-text version (when textURL is not empty)
// and the source repository. title and version are escaped here; body must already be safe HTML.
func HTMLPage(title, body, textURL, version string) []byte {
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<title>`)
	b.WriteString(html.EscapeString(title))
	b.WriteString("</title>\n<style>" + style + "</style>\n</head>\n<body>\n")
	b.WriteString(`<header><a class="home" href="/">HealthLog Push Relay</a><nav><a href="/privacy">Privacy</a><a href="/terms">Terms</a></nav></header>` + "\n")
	b.WriteString("<main>\n" + body + "</main>\n<footer><p><span>Relay version " + html.EscapeString(version) + "</span>")
	if textURL != "" {
		b.WriteString(`<a href="` + html.EscapeString(textURL) + `">Plain text</a>`)
	}
	b.WriteString(`<a href="` + Repository + `">Source code</a></p></footer>` + "\n</body>\n</html>\n")
	return []byte(b.String())
}

// MarkdownPage renders a notice text as a complete HTML page. It fails on markdown outside the supported
// subset; the tests render every served text, so a failure here cannot reach a release.
func MarkdownPage(src, textURL, version string) ([]byte, error) {
	body, title, err := RenderMarkdown(src)
	if err != nil {
		return nil, err
	}
	return HTMLPage(title, body, textURL, version), nil
}

// indexLinkRe matches the addresses in the index: https URLs, relay paths and e-mail addresses.
var indexLinkRe = regexp.MustCompile(`https://[a-zA-Z0-9./_-]+|/[a-z.][a-z0-9./_-]*|[a-z]+@healthlog\.dev`)

// IndexPage renders the index as an HTML page: its heading, its description and its "Label: value"
// lines as a list of terms, with every address as a link.
func IndexPage(version string) []byte {
	title, rest, _ := strings.Cut(Index, "\n")
	intro, entries, _ := strings.Cut(strings.TrimLeft(rest, "\n"), "\n\n")
	var b strings.Builder
	b.WriteString("<h1>" + html.EscapeString(title) + "</h1>\n<p>" + html.EscapeString(intro) + "</p>\n<dl>\n")
	for _, line := range strings.Split(strings.TrimSpace(entries), "\n") {
		label, value, _ := strings.Cut(line, ":")
		b.WriteString("<dt>" + html.EscapeString(label) + "</dt><dd>" + linkAddresses(strings.TrimSpace(value)) + "</dd>\n")
	}
	b.WriteString("</dl>\n")
	return HTMLPage(title, b.String(), "", version)
}

// linkAddresses escapes s and turns its https URLs, relay paths and e-mail addresses into links. The
// matched addresses consist only of characters that need no escaping in an attribute.
func linkAddresses(s string) string {
	return indexLinkRe.ReplaceAllStringFunc(html.EscapeString(s), func(m string) string {
		href := m
		if strings.Contains(m, "@") {
			href = "mailto:" + m
		}
		return `<a href="` + href + `">` + m + "</a>"
	})
}
