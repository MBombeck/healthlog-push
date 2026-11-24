package healthlogpush_test

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestRSAOnlyInWalletAndCLI: the Wallet pass key is RSA; RSA code lives in internal/wallet (with its test
// PKI) and in the CLI (key generation for the CSR), nowhere in the relay.
func TestRSAOnlyInWalletAndCLI(t *testing.T) {
	seen := 0
	for _, f := range goFiles(t) {
		if slices.Contains(imports(f), "crypto/rsa") {
			seen++
			if !strings.HasPrefix(f.path, "internal/wallet/") && !strings.HasPrefix(f.path, "cmd/") {
				t.Errorf("%s imports crypto/rsa", f.path)
			}
		}
	}
	if seen < 2 {
		t.Fatalf("crypto/rsa found in %d files; matcher broken", seen)
	}
}

// TestWalletPassKeyReadOnlyByTheWalletProcess: the pass key and certificate files are named only in the
// wallet command; the relay command never opens them.
func TestWalletPassKeyReadOnlyByTheWalletProcess(t *testing.T) {
	n := 0
	for _, f := range goFiles(t) {
		if strings.Contains(f.src, "HLP_WALLET_KEY_FILE") || strings.Contains(f.src, "secrets/wallet") {
			n++
			if f.path != "cmd/healthlog-push/wallet.go" {
				t.Errorf("%s names the pass key", f.path)
			}
		}
	}
	if n != 1 {
		t.Fatalf("the pass key is named in %d files, want 1", n)
	}
}

// TestComposeWalletHasNoNetwork: in the compose file the wallet service has no network, its own user,
// read-only root, no capabilities, is off by default (a profile), and only it mounts the pass key; the
// relay mounts the socket volume but never the wallet secrets.
func TestComposeWalletHasNoNetwork(t *testing.T) {
	b, err := os.ReadFile("deploy/compose/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	services := splitServices(t, string(b))
	w, r := services["wallet"], services["relay"]
	if w == "" || r == "" || services["signer"] == "" {
		t.Fatalf("services not found (%d parsed)", len(services))
	}
	for _, want := range []string{"network_mode: none", `profiles: ["wallet"]`, `user: "65534:65530"`, "<<: *hardening",
		"target: /run/secrets/wallet", "read_only: true", "target: /run/wallet", `"healthcheck", "--wallet"`} {
		if !strings.Contains(w, want) {
			t.Errorf("wallet service lacks %q", want)
		}
	}
	for _, s := range []string{r, services["signer"]} {
		if strings.Contains(s, "secrets/wallet") {
			t.Error("another service mounts the wallet secrets")
		}
	}
	if !strings.Contains(r, "HLP_WALLET_DIR: ${HLP_WALLET_DIR:-}") || !strings.Contains(r, "target: /run/wallet") {
		t.Error("the relay's Wallet switch is not off by default, or it lacks the socket volume")
	}
	if !strings.Contains(string(b), "read_only: true\n  cap_drop:\n    - ALL") {
		t.Error("the shared hardening block changed")
	}
}

// splitServices cuts the services section of the compose file into one text per service.
func splitServices(t *testing.T, doc string) map[string]string {
	t.Helper()
	start := strings.Index(doc, "\nservices:\n")
	end := strings.Index(doc, "\nvolumes:\n")
	if start < 0 || end < start {
		t.Fatal("compose file has no services or volumes section")
	}
	out := map[string]string{}
	name := ""
	head := regexp.MustCompile(`^ {2}([a-z-]+):$`)
	for _, line := range strings.Split(doc[start:end], "\n") {
		if m := head.FindStringSubmatch(line); m != nil {
			name = m[1]
			continue
		}
		if name != "" {
			out[name] += line + "\n"
		}
	}
	return out
}

// TestTunnelTargetIsAConstant: Apple's push host appears as a dial target only in the tunnel and in the
// APNs endpoint constants, so no configuration can make the tunnel reach anything else.
func TestTunnelTargetIsAConstant(t *testing.T) {
	n := 0
	for _, f := range goFiles(t) {
		if strings.Contains(f.src, "api.push.apple.com") {
			n++
			if f.path != "internal/relay/apnstunnel.go" && f.path != "internal/apns/apns.go" {
				t.Errorf("%s names Apple's push host", f.path)
			}
		}
	}
	if n != 2 {
		t.Fatalf("Apple's push host appears in %d files, want 2", n)
	}
	src, err := os.ReadFile("internal/relay/apnstunnel.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `const APNsHostPort = "api.push.apple.com:443"`) || !strings.Contains(string(src), `dial(dctx, "tcp", APNsHostPort)`) {
		t.Fatal("the tunnel does not dial the constant")
	}
}
