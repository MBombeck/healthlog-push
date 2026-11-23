package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestExecutableSHA256IsTheRunningFile: the hash is that of the test binary itself, read independently.
func TestExecutableSHA256IsTheRunningFile(t *testing.T) {
	got, err := ExecutableSHA256()
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("ExecutableSHA256 = %s, the file is %s", got, want)
	}
}

func TestPlatformAndGoVersion(t *testing.T) {
	if !regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+$`).MatchString(Platform()) {
		t.Fatalf("Platform() = %q", Platform())
	}
	if !strings.HasPrefix(GoVersion(), "go1.") {
		t.Fatalf("GoVersion() = %q", GoVersion())
	}
}
