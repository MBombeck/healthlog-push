package notice

import (
	"errors"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
)

// The renderer turns the small markdown subset of the notice texts into HTML: ATX headings, paragraphs,
// lists with "- " and "N. " markers and continuation lines, code spans, bold, links to https or mailto
// targets, and bare https URLs and e-mail addresses. Every character of the source is escaped. Anything
// outside the subset (raw HTML, tables, code fences, block quotes, other list markers, thematic breaks) is
// an error rather than a guess, so a new construct in a notice text fails the tests instead of rendering
// as something the text did not say.

var (
	headingRe = regexp.MustCompile(`^(#{1,3}) (\S.*)$`)
	bulletRe  = regexp.MustCompile(`^- (\S.*)$`)
	orderedRe = regexp.MustCompile(`^(\d{1,3})\. (\S.*)$`)
	emailRe   = regexp.MustCompile(`^[a-z0-9._-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}`)
	urlRe     = regexp.MustCompile(`^https://[^\s<>"'` + "`" + `]+`)
	linkURLRe = regexp.MustCompile(`^(https://|mailto:)[^\s<>"'` + "`" + `]+$`)
)

// unsupported lists line starts outside the subset.
var unsupported = []string{"<", ">", "|", "```", "~~~", "* ", "+ ", "---", "***", "___", "===", "####", "\t"}

type mdBlock struct {
	kind  string // "h1".."h3", "p", "ul", "ol"
	lines []string
	items [][]string // list items, each a list of lines
	nums  []int      // ordered list numbers
}

// RenderMarkdown renders src (the subset described above) as an HTML fragment, and returns the text of
// its first level-one heading as the title.
func RenderMarkdown(src string) (body, title string, err error) {
	blocks, err := parseBlocks(src)
	if err != nil {
		return "", "", err
	}
	var b strings.Builder
	ids := map[string]int{}
	for _, bl := range blocks {
		switch bl.kind {
		case "h1", "h2", "h3":
			text := bl.lines[0]
			if bl.kind == "h1" && title == "" {
				title = text
			}
			id := slug(text)
			ids[id]++
			if n := ids[id]; n > 1 {
				id += "-" + strconv.Itoa(n)
			}
			fmt.Fprintf(&b, "<%s id=\"%s\">%s</%s>\n", bl.kind, id, inline(text), bl.kind)
		case "p":
			fmt.Fprintf(&b, "<p>%s</p>\n", inline(strings.Join(bl.lines, "\n")))
		case "ul", "ol":
			b.WriteString("<" + bl.kind + ">\n")
			for i, it := range bl.items {
				if bl.kind == "ol" {
					fmt.Fprintf(&b, "<li value=\"%d\">%s</li>\n", bl.nums[i], inline(strings.Join(it, "\n")))
				} else {
					fmt.Fprintf(&b, "<li>%s</li>\n", inline(strings.Join(it, "\n")))
				}
			}
			b.WriteString("</" + bl.kind + ">\n")
		}
	}
	if title == "" {
		return "", "", errors.New("markdown: no level-one heading")
	}
	return b.String(), title, nil
}

// parser collects blocks line by line.
type parser struct {
	blocks []mdBlock
	cur    *mdBlock // the open paragraph or list
	blank  bool     // a blank line since the last content line
}

func parseBlocks(src string) ([]mdBlock, error) {
	var p parser
	for n, raw := range strings.Split(src, "\n") {
		if err := p.line(n+1, strings.TrimRight(raw, " ")); err != nil {
			return nil, err
		}
	}
	p.flush()
	return p.blocks, nil
}

func (p *parser) flush() {
	if p.cur != nil {
		p.blocks = append(p.blocks, *p.cur)
		p.cur = nil
	}
}

func (p *parser) inList() bool { return p.cur != nil && (p.cur.kind == "ul" || p.cur.kind == "ol") }

func (p *parser) line(n int, line string) error {
	if line == "" {
		p.blank = true
		if !p.inList() {
			p.flush()
		}
		return nil
	}
	trimmed := strings.TrimLeft(line, " ")
	indented := len(trimmed) < len(line)
	if err := checkLine(n, line, trimmed, indented); err != nil {
		return err
	}
	defer func() { p.blank = false }()
	if m := headingRe.FindStringSubmatch(line); m != nil {
		p.flush()
		p.blocks = append(p.blocks, mdBlock{kind: "h" + strconv.Itoa(len(m[1])), lines: []string{strings.TrimSpace(m[2])}})
		return nil
	}
	if m := bulletRe.FindStringSubmatch(line); m != nil {
		p.item("ul", m[1], 0)
		return nil
	}
	if m := orderedRe.FindStringSubmatch(line); m != nil {
		num, _ := strconv.Atoi(m[1])
		p.item("ol", m[2], num)
		return nil
	}
	switch {
	case p.inList() && !p.blank:
		last := len(p.cur.items) - 1
		p.cur.items[last] = append(p.cur.items[last], trimmed)
	case p.inList() && indented:
		// After a blank line an unindented line ends the list; an indented one would be a second
		// paragraph inside the item, which is outside the subset.
		return fmt.Errorf("markdown line %d: a list item with more than one paragraph", n)
	case p.cur != nil && !p.inList(): // a paragraph continues
		p.cur.lines = append(p.cur.lines, trimmed)
	case indented:
		return fmt.Errorf("markdown line %d: an indented code block is outside the supported subset", n)
	default:
		p.flush()
		p.cur = &mdBlock{kind: "p", lines: []string{trimmed}}
	}
	return nil
}

// item adds a list item, opening a list of that kind if needed.
func (p *parser) item(kind, text string, num int) {
	if p.cur == nil || p.cur.kind != kind {
		p.flush()
		p.cur = &mdBlock{kind: kind}
	}
	p.cur.items = append(p.cur.items, []string{text})
	p.cur.nums = append(p.cur.nums, num)
}

// checkLine refuses a line that starts a construct outside the subset.
func checkLine(n int, line, trimmed string, indented bool) error {
	for _, u := range unsupported {
		if strings.HasPrefix(trimmed, u) || strings.HasPrefix(line, u) {
			return fmt.Errorf("markdown line %d: %q is outside the supported subset", n, u)
		}
	}
	if strings.HasPrefix(trimmed, "#") && !headingRe.MatchString(line) {
		return fmt.Errorf("markdown line %d: malformed or indented heading", n)
	}
	if indented && (bulletRe.MatchString(trimmed) || orderedRe.MatchString(trimmed)) {
		return fmt.Errorf("markdown line %d: a nested list is outside the supported subset", n)
	}
	return nil
}

// inline renders the inline subset of s, escaping every character it does not turn into markup.
func inline(s string) string { return render(s, true) }

// render is inline; links false keeps addresses as text, inside the text of a link.
func render(s string, links bool) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		switch {
		case rest[0] == '`':
			if end := strings.IndexByte(rest[1:], '`'); end >= 0 {
				b.WriteString("<code>" + html.EscapeString(rest[1:1+end]) + "</code>")
				i += end + 2
				continue
			}
		case strings.HasPrefix(rest, "**"):
			if end := strings.Index(rest[2:], "**"); end > 0 {
				b.WriteString("<strong>" + render(rest[2:2+end], links) + "</strong>")
				i += end + 4
				continue
			}
		case links && rest[0] == '[':
			if text, target, n, ok := link(rest); ok {
				b.WriteString(`<a href="` + html.EscapeString(target) + `">` + render(text, false) + "</a>")
				i += n
				continue
			}
		case links && wordStart(s, i) && urlRe.MatchString(rest):
			u := trimURL(urlRe.FindString(rest))
			b.WriteString(`<a href="` + html.EscapeString(u) + `">` + html.EscapeString(u) + "</a>")
			i += len(u)
			continue
		case links && wordStart(s, i) && emailRe.MatchString(rest):
			e := emailRe.FindString(rest)
			b.WriteString(`<a href="mailto:` + html.EscapeString(e) + `">` + html.EscapeString(e) + "</a>")
			i += len(e)
			continue
		}
		b.WriteString(html.EscapeString(rest[:1]))
		i++
	}
	return b.String()
}

// link parses "[text](target)" at the start of s. Only https and mailto targets are links; anything else
// stays literal text.
func link(s string) (text, target string, n int, ok bool) {
	mid := strings.Index(s, "](")
	if mid < 2 || strings.ContainsAny(s[1:mid], "[]\n") {
		return "", "", 0, false
	}
	end := strings.IndexByte(s[mid+2:], ')')
	if end < 0 {
		return "", "", 0, false
	}
	target = s[mid+2 : mid+2+end]
	if !linkURLRe.MatchString(target) {
		return "", "", 0, false
	}
	return s[1:mid], target, mid + 3 + end, true
}

// wordStart reports whether position i of s does not continue a word, so that an address inside a longer
// token is not turned into a link.
func wordStart(s string, i int) bool {
	if i == 0 {
		return true
	}
	return strings.IndexByte(wordBytes, s[i-1]) < 0
}

// wordBytes are the bytes that continue an address token.
const wordBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/@"

// trimURL drops sentence punctuation after a bare URL, and a closing parenthesis that has no opening one
// in the URL.
func trimURL(u string) string {
	for u != "" {
		last := u[len(u)-1]
		switch {
		case strings.IndexByte(".,;:!?", last) >= 0:
			u = u[:len(u)-1]
		case last == ')' && strings.Count(u, "(") < strings.Count(u, ")"):
			u = u[:len(u)-1]
		default:
			return u
		}
	}
	return u
}

// slug turns a heading into a fragment identifier: lowercase letters, digits and single hyphens.
func slug(s string) string {
	var b strings.Builder
	hyphen := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if hyphen && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			hyphen = false
		} else {
			hyphen = true
		}
	}
	if b.Len() == 0 {
		return "section"
	}
	return b.String()
}
