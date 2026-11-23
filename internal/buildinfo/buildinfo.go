// Package buildinfo carries the version and commit set at link time and the identity of the running
// executable.
package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
)

// Set with -ldflags "-X github.com/MBombeck/healthlog-push/internal/buildinfo.Version=... -X ...Commit=...".
var (
	Version = "dev"
	Commit  = "unknown"
)

// Platform is the operating system and architecture the binary was built for, as in the names of the
// release binaries: linux/amd64 or linux/arm64.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

// GoVersion is the Go release the binary was built with.
func GoVersion() string { return runtime.Version() }

// ExecutableSHA256 returns the lowercase hex SHA-256 of the file the running process was started from.
// On Linux it reads /proc/self/exe, the file the kernel actually mapped, so a renamed or replaced path
// cannot change the answer; elsewhere it falls back to os.Executable. The release lists the same hash in
// SHA256SUMS (docs/verify.md).
func ExecutableSHA256() (string, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		p, perr := os.Executable()
		if perr != nil {
			return "", perr
		}
		if f, err = os.Open(p); err != nil { //nolint:gosec // the process's own executable
			return "", err
		}
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
