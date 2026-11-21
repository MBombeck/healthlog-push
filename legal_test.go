package healthlogpush_test

import (
	"bytes"
	"os"
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
