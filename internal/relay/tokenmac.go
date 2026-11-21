package relay

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/MBombeck/healthlog-push/internal/store"
)

// tokenMAC returns the MAC under the current key and, when the binding exists only under a previous key,
// moves it to the current key (MAC key rotation).
func (r *Relay) tokenMAC(token []byte) string {
	cur := mac(r.cfg.MACKeys[0], token)
	if _, ok := r.bindings[cur]; ok {
		return cur
	}
	for _, k := range r.cfg.MACKeys[1:] {
		old := mac(k, token)
		if b, ok := r.bindings[old]; ok {
			if err := r.st.RenameBinding([]byte(old), []byte(cur), b); err == nil {
				r.dropBindingLocked(old)
				r.setBindingLocked(cur, b)
				if d, ok := r.devs[old]; ok {
					r.devs[cur] = d
					delete(r.devs, old)
				}
			}
			return cur
		}
	}
	return cur
}

// pairBlock and tokenBlocked look the token up under every configured MAC key, so a device opt-out or an
// operator block survives a MAC key rotation. pairBlock returns the device opt-out of the pair and the
// token MAC it is stored under.
func (r *Relay) pairBlock(token []byte, instanceID string) (string, store.PairBlock, bool) {
	for _, k := range r.cfg.MACKeys {
		m := mac(k, token)
		if b, ok := r.st.GetPairBlock([]byte(m), instanceID); ok {
			return m, b, true
		}
	}
	return "", store.PairBlock{}, false
}

func (r *Relay) tokenBlocked(token []byte) bool {
	for _, k := range r.cfg.MACKeys {
		if r.st.TokenBlocked([]byte(mac(k, token))) {
			return true
		}
	}
	return false
}

func mac(key, token []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(token)
	return string(m.Sum(nil))
}

func keyHash(pk []byte) []byte { s := sha256.Sum256(pk); return s[:] }
