package healthlogpush_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestHostedKeysPublished: keys/push.healthlog.dev.json names the host and exactly the three pinned identity
// keys, each a distinct 32-byte Ed25519 public key in unpadded base64url, and the table in
// docs/hosted-relay.md lists the same values, so the two publications cannot drift apart.
func TestHostedKeysPublished(t *testing.T) {
	raw, err := os.ReadFile("keys/push.healthlog.dev.json")
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]string
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if keys["host"] != "push.healthlog.dev" || len(keys) != 4 {
		t.Fatalf("keys file: %v", keys)
	}
	doc, err := os.ReadFile("docs/hosted-relay.md")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range []string{"current", "next", "emergency"} {
		v := keys[name]
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil || len(b) != 32 {
			t.Errorf("%s: not an unpadded base64url Ed25519 key: %q", name, v)
		}
		if seen[v] {
			t.Errorf("%s repeats another key", name)
		}
		seen[v] = true
		if !strings.Contains(string(doc), "| `"+name+"` | `"+v+"` |") {
			t.Errorf("docs/hosted-relay.md table lacks %s", name)
		}
	}
}
