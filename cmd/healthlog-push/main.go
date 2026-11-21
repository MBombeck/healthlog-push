// Command healthlog-push is the HealthLog push relay. One binary, two processes: "relay" serves the API and
// talks to Apple; "signer" holds the APNs key without network access and writes short-lived JWTs.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/MBombeck/healthlog-push/internal/admin"
	"github.com/MBombeck/healthlog-push/internal/buildinfo"
	"github.com/MBombeck/healthlog-push/internal/relay"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"relay"}
	}
	var err error
	switch args[0] {
	case "relay":
		err = runRelay()
	case "signer":
		err = runSigner()
	case "admin":
		if len(args) == 1 {
			fmt.Print(admin.Usage)
			return
		}
		var ar *relay.AdminRequest
		if ar, err = admin.Parse(args[1:]); err == nil {
			err = admin.Run(adminSocketPath(), ar, os.Stdout)
		}
	case "keygen":
		err = keygen(arg(args, 1), os.Stdout)
	case "healthcheck":
		err = healthcheck(slices.Contains(args, "--signer"))
	case "version":
		fmt.Println(buildinfo.Version, buildinfo.Commit)
	default:
		err = fmt.Errorf("unknown command %q (relay, signer, admin, keygen, healthcheck, version)", args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthlog-push:", err)
		os.Exit(1)
	}
}

func arg(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envOrFile reads K, or the file named by K_FILE.
func envOrFile(k string) (string, error) {
	if v := os.Getenv(k); v != "" {
		return v, nil
	}
	if f := os.Getenv(k + "_FILE"); f != "" {
		b, err := os.ReadFile(f) //nolint:gosec // operator-provided path
		return strings.TrimSpace(string(b)), err
	}
	return "", fmt.Errorf("%s or %s_FILE is required", k, k)
}

// Paths and addresses inside the container. Each default is defined here and only here; the relay, the
// signer, the admin client and the health check all read them through these functions.

func dataDir() string { return env("HLP_DATA_DIR", "/data") }

// adminSocketPath follows HLP_DATA_DIR unless HLP_ADMIN_SOCKET is set, for the server and the client alike.
func adminSocketPath() string { return env("HLP_ADMIN_SOCKET", filepath.Join(dataDir(), "admin.sock")) }

func jwtDir() string { return env("HLP_JWT_DIR", "/run/jwt") }

func jwtRefreshDir() string { return env("HLP_JWT_REFRESH_DIR", "/run/jwt-refresh") }

func metricsListen() string { return env("HLP_METRICS_LISTEN", "127.0.0.1:9464") }
