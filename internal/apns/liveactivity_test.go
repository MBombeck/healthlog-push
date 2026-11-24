package apns

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

func dueContentState() *wire.ContentState {
	status, format := "due", "AUTO"
	var target int64 = 1795000600
	f := false
	return &wire.ContentState{Status: &status, CountdownTarget: &target, Confirmed: &f, PendingConfirm: &f,
		IsOverdue: &f, TimeFormatRaw: &format}
}

// startAttrs returns the attributes object of a start payload built with ref.
func startAttrs(t testing.TB, ref string) map[string]any {
	t.Helper()
	var p struct {
		APS struct {
			Attributes map[string]any `json:"attributes"`
		} `json:"aps"`
	}
	b := LiveActivityStartPayload(time.Unix(1795000000, 0), ref, dueContentState())
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("payload %q: %v", b, err)
	}
	return p.APS.Attributes
}

// TestStartAttributesCarryTheStartID: a start's attributes are the version and the item's ref as `s`, and
// nothing else. A ref that is not 1 to 64 printable ASCII characters (which the wire check never lets
// through) leaves the version alone rather than putting anything else into the attributes.
func TestStartAttributesCarryTheStartID(t *testing.T) {
	id := "las-" + strings.Repeat("A", 22)
	if a := startAttrs(t, id); len(a) != 2 || a["v"] != float64(1) || a["s"] != id {
		t.Errorf("attributes for %q: %v", id, a)
	}
	if a := startAttrs(t, strings.Repeat("x", 64)); a["s"] != strings.Repeat("x", 64) {
		t.Errorf("a 64-character id was dropped: %v", a)
	}
	for _, bad := range []string{"", strings.Repeat("x", 65), "las-é", "a b", "a\"b", "a\\b", "a\nb", "a\x7f"} {
		if a := startAttrs(t, bad); len(a) != 1 || a["v"] != float64(1) {
			t.Errorf("attributes for %q: %v, want the version alone", bad, a)
		}
	}
	b := LiveActivityStartPayload(time.Unix(1795000000, 0), "s2", dueContentState())
	if !strings.Contains(string(b), `"attributes-type":"HealthLogDoseAttributes","attributes":{"v":1,"s":"s2"},"alert"`) {
		t.Errorf("start payload: %s", b)
	}
}

// FuzzStartAttributes: whatever the ref, the start payload is valid JSON whose attributes are the version
// and, at most, the ref itself as `s`.
func FuzzStartAttributes(f *testing.F) {
	for _, s := range []string{"s2", "las-AAAAAAAAAAAAAAAAAAAAAA", "", "a\"b", strings.Repeat("z", 65)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ref string) {
		a := startAttrs(t, ref)
		if a["v"] != float64(1) || len(a) > 2 {
			t.Fatalf("attributes for %q: %v", ref, a)
		}
		if s, ok := a["s"]; ok && (s != ref || len(ref) > maxStartID) {
			t.Fatalf("attributes for %q carry s=%v", ref, s)
		}
	})
}
