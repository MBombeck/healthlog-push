package relay

import (
	"crypto/ed25519"
	"errors"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// SealExport signs the registry export with the relay identity key (hl-relay-export-v1).
func SealExport(id ed25519.PrivateKey, ex *store.Export) error {
	b, err := ex.SignedBytes()
	if err != nil {
		return err
	}
	ex.Signature = wire.EncodeB64(ed25519.Sign(id, []byte(wire.ExportText(ex.Host, b))))
	return nil
}

// OpenExport checks that an export was written by a relay with this identity key for this host. The export
// is the root of trust after a database loss: an edited file must not lift blocks or create instances.
func OpenExport(pub ed25519.PublicKey, host string, ex *store.Export) error {
	if ex.Host != host {
		return errors.New("registry export is for another host")
	}
	sig, err := wire.ParseSignature(ex.Signature)
	if err != nil {
		return errors.New("registry export is not signed")
	}
	b, err := ex.SignedBytes()
	if err != nil {
		return err
	}
	if !wire.Verify(pub, wire.ExportText(host, b), sig) {
		return errors.New("registry export signature does not verify")
	}
	return nil
}
