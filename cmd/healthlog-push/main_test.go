package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MBombeck/healthlog-push/internal/store"
)

// TestDamagedStoreRecovers covers F8: a damaged database is moved aside, the relay starts empty, imports the
// registry export and reports that the recovery window must open.
func TestDamagedStoreRecovers(t *testing.T) {
	data, export := t.TempDir(), t.TempDir()
	st, err := store.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = st.PutInstance(&store.Instance{ID: "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37", PublicKey: bytes.Repeat([]byte{1}, 32), Tier: store.TierStandard})
	ex, _ := st.BuildExport(20000)
	_ = st.Close()
	if err := store.WriteExport(export, ex); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "relay.db"), bytes.Repeat([]byte("garbage!"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	got, recovered, err := openStore(data, export)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = got.Close() }()
	ins, _ := got.Instances()
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
	if err := store.WriteExport(export, &store.Export{Format: store.ExportFormat, Instances: []store.ExportedInst{{ID: "a", PublicKey: bytes.Repeat([]byte{2}, 32), Tier: "probation"}}}); err != nil {
		t.Fatal(err)
	}
	st, recovered, err := openStore(data, export)
	if err != nil || !recovered {
		t.Fatal(err, recovered)
	}
	_ = st.Close()
	st, recovered, err = openStore(data, export)
	if err != nil || recovered {
		t.Fatal("an existing database must not import again", err)
	}
	_ = st.Close()
}

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
