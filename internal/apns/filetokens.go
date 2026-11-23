package apns

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// FileTokens reads the JWT the signer writes to a shared tmpfs and asks for a refresh by creating an empty
// marker file in a second directory. It never sees the signing key.
type FileTokens struct {
	Dir        string
	RefreshDir string
	mu         sync.Mutex
	cached     string
	iat        int64
	readAt     time.Time
}

// Token returns the current JWT if it is younger than 55 minutes.
func (f *FileTokens) Token() (string, int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.readAt) > 10*time.Second || f.cached == "" {
		if b, err := os.ReadFile(filepath.Join(f.Dir, "token")); err == nil {
			s := strings.TrimSpace(string(b))
			if iat, err := wire.JWTIssuedAt(s); err == nil {
				f.cached, f.iat = s, iat
			}
		}
		f.readAt = time.Now()
	}
	if f.cached == "" || time.Now().Unix()-f.iat > 55*60 {
		return "", 0, false
	}
	return f.cached, f.iat, true
}

// RequestRefresh creates the refresh marker. The signer honors it at most every 20 minutes.
func (f *FileTokens) RequestRefresh() {
	if f.RefreshDir == "" {
		return
	}
	name := filepath.Join(f.RefreshDir, "refresh")
	fh, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o640) //nolint:gosec // fixed name
	if err == nil {
		_ = fh.Close()
		now := time.Now()
		_ = os.Chtimes(name, now, now)
	}
	f.mu.Lock()
	f.readAt = time.Time{}
	f.mu.Unlock()
}
