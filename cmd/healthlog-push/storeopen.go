package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/relay"
	"github.com/MBombeck/healthlog-push/internal/store"
)

// openStore opens the database. A damaged file is moved aside, an empty store is created, and the latest
// registry export is imported; the caller then opens the recovery window.
// exportTrust is what an imported registry export must match: signed by this identity key for this host.
type exportTrust struct {
	pub  ed25519.PublicKey
	host string
}

func openStore(dataDir, exportDir string, trust exportTrust) (*store.Store, bool, error) {
	path := filepath.Join(dataDir, "relay.db")
	_, statErr := os.Stat(path)
	fresh := errors.Is(statErr, os.ErrNotExist)
	st, err := store.Open(path)
	if err == nil {
		cerr := st.Check()
		if cerr == nil {
			if fresh {
				return importExport(st, exportDir, trust)
			}
			return st, false, nil
		}
		_ = st.Close()
		err = cerr
	}
	// Only proven damage moves the file. A held lock, wrong permissions or a full disk stop the relay
	// instead, so the operator can fix the cause without losing every binding.
	if !store.IsCorrupt(err) {
		return nil, false, fmt.Errorf("open store: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	aside := path + ".damaged-" + stamp
	for n := 1; ; n++ {
		if _, serr := os.Stat(aside); errors.Is(serr, os.ErrNotExist) {
			break
		}
		aside = fmt.Sprintf("%s.damaged-%s-%d", path, stamp, n)
	}
	if rerr := os.Rename(path, aside); rerr != nil {
		return nil, false, fmt.Errorf("database unusable and cannot be moved aside: %w", rerr)
	}
	logx.Alert("store.damaged_moved_aside")
	st, err = store.Open(path)
	if err != nil {
		return nil, false, err
	}
	return importExport(st, exportDir, trust)
}

func importExport(st *store.Store, exportDir string, trust exportTrust) (*store.Store, bool, error) {
	ex, err := store.ReadExport(exportDir, "registry.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, false, nil
		}
		return nil, false, fmt.Errorf("registry export unreadable: %w", err)
	}
	if err := relay.OpenExport(trust.pub, trust.host, ex); err != nil {
		_ = st.Close()
		return nil, false, fmt.Errorf("registry export refused: %w", err)
	}
	n, err := st.Import(ex, store.Day(time.Now()), relay.DefaultLimits.StandardDevicesMax)
	if err != nil {
		return nil, false, err
	}
	logx.Event("store.imported_export", logx.Int(logx.KCount, int64(n)))
	return st, true, nil
}
