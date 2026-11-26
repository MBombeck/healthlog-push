package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testHost = "push.example.org"

var (
	testInst = ed25519.NewKeyFromSeed(make([]byte, 32))
	testDev  = ed25519.NewKeyFromSeed([]byte(strings.Repeat("d", 32)))
)

func tok(b byte) []byte {
	t := make([]byte, 32)
	for i := range t {
		t[i] = b
	}
	return t
}

func regBody(pk ed25519.PrivateKey, host string, ts int64) []byte {
	pub := ed25519.PublicKey(pk[32:])
	b, _ := json.Marshal(RegisterBody{PublicKey: EncodeB64(pub), Client: "healthlog/1.49.0", Time: ts,
		Proof: EncodeB64(ed25519.Sign(pk, []byte(RegisterText(host, pub, ts))))})
	return b
}

func TestParseRegistration(t *testing.T) {
	now := int64(1795000000)
	if _, err := ParseRegistration(regBody(testInst, testHost, now), testHost, now); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRegistration(regBody(testInst, "other.example.org", now), testHost, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("other host: %v", err)
	}
	if _, err := ParseRegistration(regBody(testInst, testHost, now-301), testHost, now); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	// Proof by a different key than the one registered: no proof of possession.
	var rb RegisterBody
	_ = json.Unmarshal(regBody(testInst, testHost, now), &rb)
	rb.PublicKey = EncodeB64(ed25519.PublicKey(testDev[32:]))
	b, _ := json.Marshal(rb)
	if _, err := ParseRegistration(b, testHost, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("foreign key: %v", err)
	}
	if _, err := ParseRegistration([]byte(`{"publicKey":"x","time":1,"proof":"y","extra":1}`), testHost, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field: %v", err)
	}
}

// BindRequest builds a signed binding body; shared with other packages' tests through copy.
func bindBody(dev ed25519.PrivateKey, host, inst string, token []byte, seq, iat int64) []byte {
	tag := TokenTag(token)
	st := Statement{InstanceID: inst, TokenTag: hex.EncodeToString(tag), Kind: "device", Seq: seq, Iat: iat}
	b, _ := json.Marshal(BindBody{
		Token: hex.EncodeToString(token), Env: "production", BindingKey: EncodeB64(ed25519.PublicKey(dev[32:])), Statement: st,
		Signature: EncodeB64(ed25519.Sign(dev, []byte(BindText(host, inst, tag, "device", seq, iat)))),
		Consent:   Consent{TextVersion: "2026-11-21", Day: "2026-11-21"},
	})
	return b
}

func TestParseBind(t *testing.T) {
	now := int64(1795000000)
	inst := "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37"
	if _, err := ParseBind(bindBody(testDev, testHost, inst, tok(1), 1, now), testHost, inst, now); err != nil {
		t.Fatal(err)
	}
	// A statement for another instance cannot be used by this one.
	other := "00000000-0000-4000-8000-000000000000"
	if _, err := ParseBind(bindBody(testDev, testHost, other, tok(1), 1, now), testHost, inst, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("other instance: %v", err)
	}
	if _, err := ParseBind(bindBody(testDev, testHost, inst, tok(1), 1, now-400), testHost, inst, now); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	// tokenTag must match the token in the body.
	var bb BindBody
	_ = json.Unmarshal(bindBody(testDev, testHost, inst, tok(1), 1, now), &bb)
	bb.Token = hex.EncodeToString(tok(2))
	b, _ := json.Marshal(bb)
	if _, err := ParseBind(b, testHost, inst, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("token swap: %v", err)
	}
}

func TestValidateItem(t *testing.T) {
	env := make([]byte, ClassAlert.EnvelopeLength())
	env[0], env[1], env[2] = 1, 1, 1
	ok := PushItem{Ref: "r1", Token: hex.EncodeToString(tok(1)), Env: "production", Class: ClassAlert, TTLSeconds: 999999,
		Envelope: EncodeB64(env), Collapse: strings.Repeat("A", 22)}
	it, err := ValidateItem(&ok)
	if err != nil {
		t.Fatal(err)
	}
	if it.TTL != ClassAlert.MaxTTL() {
		t.Errorf("ttl not clamped: %d", it.TTL)
	}
	cases := map[string]func(p *PushItem){
		"alert without collapse": func(p *PushItem) { p.Collapse = "" },
		"bad collapse":           func(p *PushItem) { p.Collapse = strings.Repeat("A", 21) + "=" },
		"class byte mismatch":    func(p *PushItem) { p.Class = ClassSilent },
		"ref too long":           func(p *PushItem) { p.Ref = strings.Repeat("r", 41) },
		"zero ttl":               func(p *PushItem) { p.TTLSeconds = 0 },
		"short token":            func(p *PushItem) { p.Token = "abcd" },
		"unknown class":          func(p *PushItem) { p.Class = "urgent" },
		"activity on alert":      func(p *PushItem) { p.Activity = &Activity{} },
		"no envelope":            func(p *PushItem) { p.Envelope = "" },
		"padded base64":          func(p *PushItem) { p.Envelope += "==" },
	}
	for name, mut := range cases {
		p := ok
		mut(&p)
		if _, err := ValidateItem(&p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Live Activity items carry no envelope and need an activity statement.
	la := PushItem{Ref: "r2", Token: ok.Token, Env: "production", Class: ClassLiveActivity, TTLSeconds: 60, Envelope: ok.Envelope}
	if _, err := ValidateItem(&la); err == nil {
		t.Error("liveactivity with envelope accepted")
	}
}

func TestParsePushBodyRefusesUnknownFields(t *testing.T) {
	if _, err := ParsePushBody([]byte(`{"items":[{"ref":"a","urgent":true}]}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := ParsePushBody([]byte(`{"items":[]}`)); err == nil {
		t.Fatal("empty batch accepted")
	}
	if _, err := ParsePushBody([]byte(`{"items":[{"ref":"a"}]} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestParseUnixAndNonce(t *testing.T) {
	for _, s := range []string{"", "-1", "+1", "01", "1e9", " 1", "99999999999999"} {
		if _, err := ParseUnix(s); err == nil {
			t.Errorf("ParseUnix(%q) accepted", s)
		}
	}
	if n, err := ParseUnix("1795000000"); err != nil || n != 1795000000 {
		t.Fatal(n, err)
	}
	if _, err := ParseNonce(EncodeB64(make([]byte, 16))); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNonce(EncodeB64(make([]byte, 15))); err == nil {
		t.Fatal("short nonce accepted")
	}
}

func TestParseClient(t *testing.T) {
	if _, v, err := ParseClient("healthlog/1.49.0"); err != nil || v != [3]int{1, 49, 0} {
		t.Fatal(v, err)
	}
	for _, s := range []string{"healthlog", "healthlog/1.49", "Healthlog/1.0.0", "healthlog/1.0.0-rc1"} {
		if _, _, err := ParseClient(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestJWTIssuedAt(t *testing.T) {
	for _, bad := range []string{"a.b", "a.b.c.d", "e30.e30.x", "e30.eyJpYXQiOjB9.x", "e30.!!.x"} {
		if _, err := JWTIssuedAt(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if n, err := JWTIssuedAt("e30.eyJpYXQiOjEyM30.x"); err != nil || n != 123 {
		t.Fatal(n, err)
	}
}

// TestStrictKeys: encoding/json alone would accept a key in another case and the last of two duplicates.
func TestStrictKeys(t *testing.T) {
	for _, b := range []string{
		`{"Token":"` + strings.Repeat("ab", 32) + `"}`,
		`{"token":"` + strings.Repeat("ab", 32) + `","token":"` + strings.Repeat("cd", 32) + `"}`,
	} {
		if _, err := ParseTokenBody([]byte(b)); err == nil {
			t.Errorf("accepted %s", b[:20])
		}
	}
	if _, err := ParseTokenBody([]byte(`{"token":"` + strings.Repeat("ab", 32) + `"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePushBody([]byte(`{"items":[{"ref":"a","Class":"alert"}]}`)); err == nil {
		t.Error("nested key in another case accepted")
	}
}

// Apple documents no fixed token length; push-to-start tokens of 128 bytes are in the field.
func TestParseTokenLengths(t *testing.T) {
	for _, n := range []int{64, 200, 256, 512} {
		if _, err := ParseToken(strings.Repeat("a", n)); err != nil {
			t.Errorf("refused a %d character token: %v", n, err)
		}
	}
	for _, s := range []string{
		strings.Repeat("a", 62),
		strings.Repeat("a", 514),
		strings.Repeat("a", 255),
		strings.Repeat("g", 64),
	} {
		if _, err := ParseToken(s); err == nil {
			t.Errorf("accepted a %d character token", len(s))
		}
	}
}
