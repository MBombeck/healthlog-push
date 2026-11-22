package apns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/signer"
)

func writeJWT(t *testing.T, dir string, iat time.Time) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	j, err := signer.MakeJWT(k, "KEYID12345", "TEAMID1234", iat)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(j+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return j
}

// TestFileTokensReadsTheSignersToken: the relay takes the JWT the signer wrote, trimmed, with its iat.
func TestFileTokensReadsTheSignersToken(t *testing.T) {
	dir := t.TempDir()
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	j := writeJWT(t, dir, iat)
	f := &FileTokens{Dir: dir}
	got, gotIat, ok := f.Token()
	if !ok || got != j || gotIat != iat.Unix() {
		t.Fatalf("token %q %d %v", got, gotIat, ok)
	}
}

// TestFileTokensRefusesMissingBrokenAndOldTokens: no file, a file that is not a JWT with an iat, and a
// token older than 55 minutes all mean no provider token, so the relay never sends with one Apple would
// reject as expired.
func TestFileTokensRefusesMissingBrokenAndOldTokens(t *testing.T) {
	dir := t.TempDir()
	f := &FileTokens{Dir: dir}
	if _, _, ok := f.Token(); ok {
		t.Fatal("token without a file")
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("not.a-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	f = &FileTokens{Dir: dir}
	if _, _, ok := f.Token(); ok {
		t.Fatal("token from a broken file")
	}
	writeJWT(t, dir, time.Now().Add(-56*time.Minute))
	f = &FileTokens{Dir: dir}
	if _, _, ok := f.Token(); ok {
		t.Fatal("token older than 55 minutes")
	}
	writeJWT(t, dir, time.Now().Add(-54*time.Minute))
	f = &FileTokens{Dir: dir}
	if _, _, ok := f.Token(); !ok {
		t.Fatal("token younger than 55 minutes refused")
	}
}

// TestFileTokensCachesAndKeepsTheLastGoodToken: the file is read at most every 10 seconds, and a broken
// write by the signer does not replace a good cached token.
func TestFileTokensCachesAndKeepsTheLastGoodToken(t *testing.T) {
	dir := t.TempDir()
	first := writeJWT(t, dir, time.Now().Add(-2*time.Minute))
	f := &FileTokens{Dir: dir}
	if got, _, _ := f.Token(); got != first {
		t.Fatal("first read")
	}
	second := writeJWT(t, dir, time.Now().Add(-time.Minute))
	if got, _, _ := f.Token(); got != first {
		t.Fatal("file reread within 10 seconds")
	}
	f.mu.Lock()
	f.readAt = time.Now().Add(-11 * time.Second)
	f.mu.Unlock()
	if got, _, _ := f.Token(); got != second {
		t.Fatal("file not reread after 10 seconds")
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.readAt = time.Time{}
	f.mu.Unlock()
	if got, _, ok := f.Token(); !ok || got != second {
		t.Fatal("a broken file replaced the cached token")
	}
}

// TestFileTokensRequestRefresh: a refresh request touches the marker in the refresh directory and makes
// the next Token call read the file again; without a refresh directory it does nothing.
func TestFileTokensRequestRefresh(t *testing.T) {
	dir, refresh := t.TempDir(), t.TempDir()
	first := writeJWT(t, dir, time.Now().Add(-2*time.Minute))
	f := &FileTokens{Dir: dir, RefreshDir: refresh}
	if got, _, _ := f.Token(); got != first {
		t.Fatal("first read")
	}
	marker := filepath.Join(refresh, "refresh")
	old := time.Now().Add(-time.Hour)
	f.RequestRefresh()
	st, err := os.Stat(marker)
	if err != nil || st.Size() != 0 {
		t.Fatalf("marker: %v", err)
	}
	if err := os.Chtimes(marker, old, old); err != nil {
		t.Fatal(err)
	}
	second := writeJWT(t, dir, time.Now().Add(-time.Minute))
	f.RequestRefresh()
	if st, _ := os.Stat(marker); !st.ModTime().After(old.Add(time.Minute)) {
		t.Fatal("marker not touched again")
	}
	if got, _, _ := f.Token(); got != second {
		t.Fatal("refresh did not force a reread")
	}
	n := &FileTokens{Dir: dir}
	n.RequestRefresh() // no refresh directory: nothing is created anywhere
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d entries in the token directory", len(entries))
	}
}
