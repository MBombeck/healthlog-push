package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// Benchmarks of the checks on the push path: the envelope frame (the relay's only look at a sealed
// envelope), parsing and validating a batch, the Ed25519 check of a signed request, and the device-signed
// binding statement. docs/performance.md has the method and the numbers.

const benchHost = "push.example.org"

func benchEnvelope(c Class) []byte {
	e := make([]byte, c.EnvelopeLength())
	e[0], e[1], e[2] = envelopeVersion, envelopeSuite, c.ClassByte()
	_, _ = rand.Read(e[3:])
	return e
}

// benchPushBody is a POST /v1/push body with n alert items, as a HealthLog server sends it.
func benchPushBody(b *testing.B, n int) []byte {
	b.Helper()
	pb := PushBody{}
	for i := range n {
		tok := make([]byte, 32)
		_, _ = rand.Read(tok)
		pb.Items = append(pb.Items, PushItem{Ref: "ref-" + strconv.Itoa(i), Token: hex.EncodeToString(tok), Env: "production",
			Class: ClassAlert, TTLSeconds: 3600, Envelope: EncodeB64(benchEnvelope(ClassAlert)), Collapse: strings.Repeat("C", 22)})
	}
	raw, err := json.Marshal(pb)
	if err != nil {
		b.Fatal(err)
	}
	return raw
}

func BenchmarkCheckEnvelopeFrame(b *testing.B) {
	env := benchEnvelope(ClassAlert)
	for b.Loop() {
		if err := CheckEnvelopeFrame(ClassAlert, env); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAndValidatePushBody(b *testing.B) {
	for _, n := range []int{1, MaxPushItems} {
		raw := benchPushBody(b, n)
		b.Run("items="+strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			for b.Loop() {
				pb, err := ParsePushBody(raw)
				if err != nil {
					b.Fatal(err)
				}
				for i := range pb.Items {
					if _, err := ValidateItem(&pb.Items[i]); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// BenchmarkVerifyRequest is the signature check of an instance request: the signed text over host,
// instance, method, path, time, nonce and the SHA-256 of the body, then Ed25519.
func BenchmarkVerifyRequest(b *testing.B) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	const id, nonce = "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37", "AAAAAAAAAAAAAAAAAAAAAA"
	for _, n := range []int{1, MaxPushItems} {
		body := benchPushBody(b, n)
		sig := ed25519.Sign(key, []byte(RequestText(benchHost, id, "POST", "/v1/push", 1795000000, nonce, body)))
		b.Run("items="+strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				if !Verify(pub, RequestText(benchHost, id, "POST", "/v1/push", 1795000000, nonce, body), sig) {
					b.Fatal("signature did not verify")
				}
			}
		})
	}
}

// BenchmarkParseBind is the device statement of a binding: parse the body and verify the hl-bind-v1
// signature of the app's binding key.
func BenchmarkParseBind(b *testing.B) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	const id = "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37"
	const iat = int64(1795000000)
	tag := TokenTag(tok)
	bb := BindBody{Token: hex.EncodeToString(tok), Env: "production", BindingKey: EncodeB64(pub),
		Statement: Statement{InstanceID: id, TokenTag: hex.EncodeToString(tag), Kind: "device", Seq: 1, Iat: iat},
		Signature: EncodeB64(ed25519.Sign(key, []byte(BindText(benchHost, id, tag, "device", 1, iat)))),
		Consent:   Consent{TextVersion: "2026-11-21", Day: "2026-11-21"}}
	raw, err := json.Marshal(bb)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := ParseBind(raw, benchHost, id, iat); err != nil {
			b.Fatal(err)
		}
	}
}
