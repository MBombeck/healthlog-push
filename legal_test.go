package healthlogpush_test

import (
	"bytes"
	"os"
	"regexp"
	"testing"
)

// TestLegalTextsInSync: the privacy notice and the terms have one source, internal/notice/*.md, which the
// relay serves at /privacy and /terms. docs/privacy.md and docs/terms.md are byte-identical copies for
// readers of the repository; scripts/sync-notice.sh refreshes them. There must never be two versions.
func TestLegalTextsInSync(t *testing.T) {
	for _, name := range []string{"privacy.md", "terms.md"} {
		src, err := os.ReadFile("internal/notice/" + name)
		if err != nil {
			t.Fatal(err)
		}
		cp, err := os.ReadFile("docs/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if len(src) < 500 || !bytes.Equal(src, cp) {
			t.Errorf("docs/%s differs from internal/notice/%s; run scripts/sync-notice.sh", name, name)
		}
	}
}

// TestInvariantsNameRealTests: every test SECURITY-INVARIANTS.md cites exists in the named file, so the
// audit map cannot point at a renamed or deleted test.
func TestInvariantsNameRealTests(t *testing.T) {
	doc, err := os.ReadFile("SECURITY-INVARIANTS.md")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)` \\(([^)]+_test\\.go)\\)").FindAllStringSubmatch(string(doc), -1)
	if len(refs) < 50 {
		t.Fatalf("only %d test references found; the matcher is broken", len(refs))
	}
	for _, m := range refs {
		src, err := os.ReadFile(m[2])
		if err != nil {
			t.Errorf("%s: %v", m[1], err)
			continue
		}
		if !bytes.Contains(src, []byte("func "+m[1]+"(")) {
			t.Errorf("%s not found in %s", m[1], m[2])
		}
	}
}
