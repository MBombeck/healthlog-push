package wallet

import (
	"bytes"
	"testing"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// FuzzReadWalletFrame: the frame reader of the wallet socket never panics and never returns more than its
// limit or a body of the wrong declared length.
func FuzzReadWalletFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{0, 1, 0, 0})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		body, err := ReadFrame(bytes.NewReader(b), wire.WalletFrameMax)
		if err != nil {
			return
		}
		if len(body) == 0 || len(body) > wire.WalletFrameMax || len(b) < 4+len(body) {
			t.Fatalf("frame of %d bytes from %d", len(body), len(b))
		}
	})
}
