// Package buildinfo carries the version and commit set at link time.
package buildinfo

// Set with -ldflags "-X github.com/MBombeck/healthlog-push/internal/buildinfo.Version=... -X ...Commit=...".
var (
	Version = "dev"
	Commit  = "unknown"
)
