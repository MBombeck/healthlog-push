package logx

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestAlertGoesToStandardErrorWithLevel: an alert line is the event line plus "level":"alert" and goes to
// the error stream; an ordinary event has no level and goes to the output stream. Log pipelines and the
// journal priority depend on both.
func TestAlertGoesToStandardErrorWithLevel(t *testing.T) {
	var o, e bytes.Buffer
	mu.Lock()
	prevOut, prevErr := out, errOut
	out, errOut = &o, &e
	mu.Unlock()
	t.Cleanup(func() { mu.Lock(); out, errOut = prevOut, prevErr; mu.Unlock() })

	Event("relay.start", Str(KVersion, "v1"))
	Alert("export.failed", Int(KCount, 2))

	var ev, al map[string]any
	if err := json.Unmarshal(o.Bytes(), &ev); err != nil {
		t.Fatalf("event line %q: %v", o.String(), err)
	}
	if err := json.Unmarshal(e.Bytes(), &al); err != nil {
		t.Fatalf("alert line %q: %v", e.String(), err)
	}
	if ev["action"] != "relay.start" || ev["level"] != nil || len(ev) != 3 {
		t.Errorf("event line: %v", ev)
	}
	if al["action"] != "export.failed" || al["level"] != "alert" || al["n"] != float64(2) || len(al) != 4 {
		t.Errorf("alert line: %v", al)
	}
	if bytes.Contains(o.Bytes(), []byte("export.failed")) || bytes.Contains(e.Bytes(), []byte("relay.start")) {
		t.Error("a line went to the wrong stream")
	}
}
