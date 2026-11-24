package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestServerTimeoutsMatchTheSpec: the timeouts spec/protocol.md promises clients are the ones the public
// server runs with. A HealthLog server sizes its keep-alive by the idle timeout, so the two must not drift.
func TestServerTimeoutsMatchTheSpec(t *testing.T) {
	spec, err := os.ReadFile("../../spec/protocol.md")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("- Server timeouts: read header 5 s, read 10 s, write 15 s, idle %d s.", int(idleTimeout/time.Second))
	if !strings.Contains(string(spec), want) {
		t.Errorf("spec/protocol.md does not state %q", want)
	}
}
