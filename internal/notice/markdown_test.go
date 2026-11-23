package notice

import (
	"crypto/sha256"
	"encoding/base64"
	"html"
	"regexp"
	"strings"
	"testing"
)

func TestRenderMarkdownSubset(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"heading and paragraph", "# Title\n\nOne line\nand the next.\n",
			"<h1 id=\"title\">Title</h1>\n<p>One line\nand the next.</p>\n"},
		{"section heading", "# T\n\n## 1. Who is responsible\n",
			"<h1 id=\"t\">T</h1>\n<h2 id=\"1-who-is-responsible\">1. Who is responsible</h2>\n"},
		{"repeated heading ids", "# T\n\n## A\n\n## A\n",
			"<h1 id=\"t\">T</h1>\n<h2 id=\"a\">A</h2>\n<h2 id=\"a-2\">A</h2>\n"},
		{"bullet list with continuation", "# T\n\n- one\n  more\n- two\n\nafter\n",
			"<h1 id=\"t\">T</h1>\n<ul>\n<li>one\nmore</li>\n<li>two</li>\n</ul>\n<p>after</p>\n"},
		{"loose ordered list keeps its numbers", "# T\n\n1. one\n   more\n\n2. two\n\n10. ten\n",
			"<h1 id=\"t\">T</h1>\n<ol>\n<li value=\"1\">one\nmore</li>\n<li value=\"2\">two</li>\n<li value=\"10\">ten</li>\n</ol>\n"},
		{"code bold and link", "# T\n\n`a<b>` **bold `x`** [docs/x.md](https://example.org/x?a=1&b=2)\n",
			"<h1 id=\"t\">T</h1>\n<p><code>a&lt;b&gt;</code> <strong>bold <code>x</code></strong> <a href=\"https://example.org/x?a=1&amp;b=2\">docs/x.md</a></p>\n"},
		{"bare URL drops sentence punctuation", "# T\n\nSee (https://example.org/a, b) and https://example.org/b.\n",
			"<h1 id=\"t\">T</h1>\n<p>See (<a href=\"https://example.org/a\">https://example.org/a</a>, b) and <a href=\"https://example.org/b\">https://example.org/b</a>.</p>\n"},
		{"URL keeps balanced parentheses", "# T\n\n(https://example.org/a_(b))\n",
			"<h1 id=\"t\">T</h1>\n<p>(<a href=\"https://example.org/a_(b)\">https://example.org/a_(b)</a>)</p>\n"},
		{"e-mail address", "# T\n\nWrite to privacy@healthlog.dev. Not x.privacy@healthlog\n",
			"<h1 id=\"t\">T</h1>\n<p>Write to <a href=\"mailto:privacy@healthlog.dev\">privacy@healthlog.dev</a>. Not x.privacy@healthlog</p>\n"},
		{"no link inside a link", "# T\n\n[https://a.example](https://b.example)\n",
			"<h1 id=\"t\">T</h1>\n<p><a href=\"https://b.example\">https://a.example</a></p>\n"},
		{"unclosed markup stays text", "# T\n\n`open **open [x](\n",
			"<h1 id=\"t\">T</h1>\n<p>`open **open [x](</p>\n"},
	}
	for _, c := range cases {
		got, _, err := RenderMarkdown(c.src)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// TestRenderMarkdownEscapes: nothing in a text becomes markup except the subset, and only https and mailto
// targets become links.
func TestRenderMarkdownEscapes(t *testing.T) {
	src := "# A <b>&amp; \"title\"\n\n" +
		"Text with <script>alert(1)</script> & 'quotes' \"too\" <img src=x onerror=alert(1)>.\n\n" +
		"[click](javascript:alert(1)) [x](http://plain.example) [y](https://ok.example\"onmouseover=\"alert(1))\n\n" +
		"- `<script>` and **<i>bold</i>**\n"
	body, title, err := RenderMarkdown(src)
	if err != nil {
		t.Fatal(err)
	}
	if title != "A <b>&amp; \"title\"" {
		t.Errorf("title %q", title)
	}
	tags := strings.Join(regexp.MustCompile(`<[^>]*>`).FindAllString(body, -1), "")
	for _, bad := range []string{"<script", "<img", "<b>", "<i>", "javascript:", `href="http://`, "onerror", "onmouseover"} {
		if strings.Contains(tags, bad) {
			t.Errorf("rendered markup contains %q:\n%s", bad, body)
		}
	}
	if n := strings.Count(body, "<a "); n != 1 {
		t.Errorf("%d links, want only the https one:\n%s", n, body)
	}
	// Every tag in the output is one the renderer writes.
	for _, tag := range regexp.MustCompile(`<(/?[a-z0-9]+)`).FindAllStringSubmatch(body, -1) {
		switch strings.TrimPrefix(tag[1], "/") {
		case "h1", "p", "ul", "li", "code", "strong", "a":
		default:
			t.Errorf("unexpected tag %s", tag[1])
		}
	}
	page := HTMLPage(title, body, "/x.txt\"><script>", "v1\"<script>")
	if strings.Contains(string(page), "<script") {
		t.Error("the layout does not escape title, text link or version")
	}
}

func TestRenderMarkdownRejectsOutsideSubset(t *testing.T) {
	for _, src := range []string{
		"# T\n\n<div>raw</div>\n",
		"# T\n\n| a | b |\n|---|---|\n",
		"# T\n\n```\ncode\n```\n",
		"# T\n\n> quote\n",
		"# T\n\n* star item\n",
		"# T\n\n+ plus item\n",
		"# T\n\n---\n",
		"# T\n\n#### deep\n",
		"# T\n\n  ## indented heading\n",
		"# T\n\n#nospace\n",
		"# T\n\n    indented code\n",
		"# T\n\n\ttab\n",
		"# T\n\n- item\n  - nested\n",
		"# T\n\n- item\n\n  second paragraph\n",
		"Setext\n===\n",
		"## no title\n",
	} {
		if _, _, err := RenderMarkdown(src); err == nil {
			t.Errorf("accepted %q", src)
		}
	}
}

// words returns the letter and digit runs of s.
func words(s string) []string { return regexp.MustCompile(`[\p{L}\p{N}]+`).FindAllString(s, -1) }

var (
	mainRe   = regexp.MustCompile(`(?s)<main>(.*)</main>`)
	anchorRe = regexp.MustCompile(`<a href="([^"]*)">(.*?)</a>`)
	valueRe  = regexp.MustCompile(`<li value="(\d+)">`)
	tagRe    = regexp.MustCompile(`<[^>]*>`)
)

// pageWords returns the words a reader of the page's main part gets: the text, the number of each ordered
// list item, and the target of each link whose text is not the target itself.
func pageWords(t *testing.T, page []byte) []string {
	t.Helper()
	m := mainRe.FindSubmatch(page)
	if m == nil {
		t.Fatal("no <main>")
	}
	s := valueRe.ReplaceAllString(string(m[1]), "$1. ")
	s = anchorRe.ReplaceAllStringFunc(s, func(a string) string {
		p := anchorRe.FindStringSubmatch(a)
		target, text := html.UnescapeString(strings.TrimPrefix(p[1], "mailto:")), html.UnescapeString(tagRe.ReplaceAllString(p[2], ""))
		if target == text {
			return p[2]
		}
		return p[2] + " " + p[1]
	})
	return words(html.UnescapeString(tagRe.ReplaceAllString(s, " ")))
}

// TestServedPagesMatchTheirText is the drift test: the HTML page of each notice is rendered from the same
// embedded text that plain-text clients receive, and a reader of the page gets every word of that text,
// in order, and no other word. There is no generated file that could fall behind the source.
func TestServedPagesMatchTheirText(t *testing.T) {
	for name, src := range map[string]string{"privacy": Privacy, "terms": Terms} {
		page, err := MarkdownPage(src, "/"+name+".txt", "v9.9.9")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The source's own markup: heading and bullet markers, code and bold markers, link brackets.
		got, want := pageWords(t, page), words(src)
		if len(want) < 300 {
			t.Fatalf("%s: only %d words in the source", name, len(want))
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			for i := range min(len(got), len(want)) {
				if got[i] != want[i] {
					t.Fatalf("%s: word %d is %q on the page, %q in the text (%d vs %d words)", name, i, got[i], want[i], len(got), len(want))
				}
			}
			t.Fatalf("%s: %d words on the page, %d in the text", name, len(got), len(want))
		}
		for _, want := range []string{`href="/` + name + `.txt"`, "Relay version v9.9.9", `href="` + Repository + `"`, "HealthLog Push Relay"} {
			if !strings.Contains(string(page), want) {
				t.Errorf("%s: page lacks %s", name, want)
			}
		}
	}
	idx := IndexPage("v9.9.9")
	if got, want := strings.Join(pageWords(t, idx), " "), strings.Join(words(Index), " "); got != want {
		t.Errorf("index page words differ from the index text:\n page %s\n text %s", got, want)
	}
	if n := strings.Count(string(idx), "<a href="); n < 12 {
		t.Errorf("index page has %d links", n)
	}
}

// TestPagesLoadNothing: the policy allows exactly the inline style, by its hash, and the pages contain
// no script, no external resource and no inline handler.
func TestPagesLoadNothing(t *testing.T) {
	pages := [][]byte{IndexPage("v1")}
	for _, src := range []string{Privacy, Terms} {
		p, err := MarkdownPage(src, "/x.txt", "v1")
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, p)
	}
	for _, p := range pages {
		s := string(p)
		m := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(s, -1)
		if len(m) != 1 {
			t.Fatalf("%d style elements", len(m))
		}
		sum := sha256.Sum256([]byte(m[0][1]))
		if want := "style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(HTMLPolicy, want) {
			t.Errorf("policy %q does not allow the page's style", HTMLPolicy)
		}
		for _, bad := range []string{"<script", "<link", "<img", "<iframe", " src=", "url(", "@import", " style="} {
			if strings.Contains(s, bad) {
				t.Errorf("page contains %q", bad)
			}
		}
		if regexp.MustCompile(`<[^>]*\son[a-z]+=`).MatchString(s) {
			t.Error("page has an inline event handler")
		}
	}
	if !strings.HasPrefix(HTMLPolicy, "default-src 'none'; ") || strings.Contains(HTMLPolicy, "script") ||
		strings.Contains(HTMLPolicy, "unsafe") {
		t.Errorf("policy %q", HTMLPolicy)
	}
}
