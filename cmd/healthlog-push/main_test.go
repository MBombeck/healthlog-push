package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/relay"
	"github.com/MBombeck/healthlog-push/internal/store"
)

// TestDamagedStoreRecovers: a damaged database is moved aside, the relay starts empty, imports the
// registry export and reports that the recovery window must open.
func TestDamagedStoreRecovers(t *testing.T) {
	data, export := t.TempDir(), t.TempDir()
	st, err := store.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = st.PutInstance(&store.Instance{ID: "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37", PublicKey: bytes.Repeat([]byte{1}, 32), Tier: store.TierStandard, DeviceLimit: 50})
	today := store.Day(time.Now())
	_ = st.BlockPair([]byte("token-mac"), "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37", store.PairBlock{Day: today})
	ex, _ := st.BuildExport(testHost, today)
	_ = st.Close()
	if err := relay.SealExport(testID, ex); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteExport(export, ex); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "relay.db"), bytes.Repeat([]byte("garbage!"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	got, recovered, err := openStore(data, export, testTrust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = got.Close() }()
	ins, _ := got.Instances()
	if _, blocked := got.GetPairBlock([]byte("token-mac"), "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37"); !blocked {
		t.Fatal("device opt-out lost when the damaged database was rebuilt from the export")
	}
	if !recovered || len(ins) != 1 {
		t.Fatalf("recovered=%v instances=%d", recovered, len(ins))
	}
	m, _ := filepath.Glob(filepath.Join(data, "relay.db.damaged-*"))
	if len(m) != 1 {
		t.Fatal("damaged file not kept aside")
	}
}

func TestFreshStoreImportsExportOnce(t *testing.T) {
	data, export := t.TempDir(), t.TempDir()
	ex := &store.Export{Format: store.ExportFormat, Host: testHost, Instances: []store.ExportedInst{{ID: "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37",
		PublicKey: bytes.Repeat([]byte{2}, 32), Tier: "probation", DeviceLimit: 20}}}
	if err := relay.SealExport(testID, ex); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteExport(export, ex); err != nil {
		t.Fatal(err)
	}
	st, recovered, err := openStore(data, export, testTrust)
	if err != nil || !recovered {
		t.Fatal(err, recovered)
	}
	_ = st.Close()
	st, recovered, err = openStore(data, export, testTrust)
	if err != nil || recovered {
		t.Fatal("an existing database must not import again", err)
	}
	_ = st.Close()
}

var (
	testID    = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32))
	testHost  = "push.example.org"
	testTrust = exportTrust{pub: ed25519.PublicKey(testID[32:]), host: testHost}
)

func TestKeygenRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := keygen("relay-id", &b); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	_ = json.Unmarshal(b.Bytes(), &out)
	k, err := loadIdentity([]byte(out["relay_id_key"]))
	if err != nil || len(k) != 64 {
		t.Fatal(err)
	}
	b.Reset()
	if err := keygen("acme-account", &b); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity([]byte("short")); err == nil {
		t.Fatal("bad identity accepted")
	}
}

// TestStoreNotMovedWithoutProof: an error that does not prove damage (here: no permission) stops the
// start and leaves the file where it is.
func TestStoreNotMovedWithoutProof(t *testing.T) {
	data := t.TempDir()
	st, err := store.Open(filepath.Join(data, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	path := filepath.Join(data, "relay.db")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(path, 0o600) }()
	if os.Getuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	if _, _, err := openStore(data, t.TempDir(), testTrust); err == nil {
		t.Fatal("started despite an unreadable database")
	}
	if m, _ := filepath.Glob(filepath.Join(data, "relay.db.damaged-*")); len(m) != 0 {
		t.Fatal("database moved aside without proof of damage")
	}
}

// TestDamagedAsideNeverOverwritten: two damaged starts keep two files aside.
func TestDamagedAsideNeverOverwritten(t *testing.T) {
	data := t.TempDir()
	for range 2 {
		if err := os.WriteFile(filepath.Join(data, "relay.db"), bytes.Repeat([]byte("damaged!"), 8192), 0o600); err != nil {
			t.Fatal(err)
		}
		st, _, err := openStore(data, t.TempDir(), testTrust)
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
	}
	if m, _ := filepath.Glob(filepath.Join(data, "relay.db.damaged-*")); len(m) != 2 {
		t.Fatalf("aside files: %v", m)
	}
}

// TestTLS12OnlyForPureACMEValidation: a client that offers h2 next to acme-tls/1 gets the TLS 1.3
// configuration; only a handshake offering nothing but acme-tls/1 may use TLS 1.2.
func TestTLS12OnlyForPureACMEValidation(t *testing.T) {
	dir := t.TempDir()
	var b bytes.Buffer
	if err := keygen("acme-account", &b); err != nil {
		t.Fatal(err)
	}
	kf := filepath.Join(dir, "acme")
	_ = os.WriteFile(kf, b.Bytes(), 0o600)
	t.Setenv("HLP_TLS_MODE", "acme")
	t.Setenv("HLP_ACME_ACCOUNT_KEY_FILE", kf)
	t.Setenv("HLP_ACME_CACHE_DIR", dir)
	cfg, err := tlsConfig("push.example.org")
	if err != nil {
		t.Fatal(err)
	}
	mixed, _ := cfg.GetConfigForClient(&tls.ClientHelloInfo{SupportedProtos: []string{"h2", "acme-tls/1"}})
	if mixed != nil {
		t.Fatal("a mixed ALPN offer got the TLS 1.2 configuration")
	}
	pure, _ := cfg.GetConfigForClient(&tls.ClientHelloInfo{SupportedProtos: []string{"acme-tls/1"}})
	if pure == nil || pure.MinVersion != tls.VersionTLS12 || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("validation handshake configuration")
	}
	if maxStreams > 16 {
		t.Fatal("more than 16 HTTP/2 streams per connection")
	}
}
