package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Vectors mirrors the parts of spec/vectors/v1.json the relay uses.
type Vectors struct {
	Constants struct {
		Host           string         `json:"host"`
		Now            int64          `json:"now"`
		EnvelopeLength map[string]int `json:"envelopeLength"`
	} `json:"constants"`
	Keys struct {
		InstanceSeed string `json:"instanceSeed"`
		InstanceRot  string `json:"instanceRotatedSeed"`
		BindingSeed  string `json:"bindingSeed"`
		RelaySeed    string `json:"relaySeed"`
		InstanceID   string `json:"instanceId"`
		APNsToken    string `json:"apnsToken"`
		LAToken      string `json:"laToken"`
		Nonce        string `json:"nonce"`
	} `json:"keys"`
	TokenTags []struct {
		Token    string `json:"token"`
		TokenTag string `json:"tokenTag"`
	} `json:"tokenTags"`
	Envelopes []struct {
		Name          string `json:"name"`
		ExpectedClass string `json:"expectedClass"`
		Envelope      string `json:"envelope"`
		Expect        string `json:"expect"`
		Relay         string `json:"relay"`
	} `json:"envelopes"`
	Statements []struct {
		Name      string `json:"name"`
		PublicKey string `json:"publicKey"`
		Text      string `json:"text"`
		Signature string `json:"signature"`
		Body      string `json:"body"`
	} `json:"statements"`
	NegativeStatements []struct {
		Name string `json:"name"`
		Of   string `json:"of"`
		Text string `json:"text"`
	} `json:"negativeStatements"`
}

// LoadVectors reads spec/vectors/v1.json relative to the repository root.
func LoadVectors(t testing.TB) *Vectors {
	t.Helper()
	for _, p := range []string{"../../spec/vectors/v1.json", "../spec/vectors/v1.json", "spec/vectors/v1.json"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var v Vectors
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		return &v
	}
	t.Fatal("spec/vectors/v1.json not found")
	return nil
}

func seedKey(t testing.TB, h string) ed25519.PrivateKey {
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(b)
}

func TestVectorsTokenTags(t *testing.T) {
	v := LoadVectors(t)
	for _, tt := range v.TokenTags {
		tok, err := ParseToken(tt.Token)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(TokenTag(tok)); got != tt.TokenTag {
			t.Errorf("token tag %s: got %s want %s", tt.Token[:8], got, tt.TokenTag)
		}
	}
}

// TestVectorsEnvelopeFrame: the relay accepts exactly the envelopes whose outer frame fits the class the
// item claims, and treats everything inside as opaque (inner failures such as authFailure pass the relay).
func TestVectorsEnvelopeFrame(t *testing.T) {
	v := LoadVectors(t)
	for _, e := range v.Envelopes {
		raw, err := DecodeB64(e.Envelope, 0)
		if err != nil {
			t.Fatal(e.Name, err)
		}
		err = CheckEnvelopeFrame(Class(e.ExpectedClass), raw)
		if got := map[bool]string{true: "accept", false: "reject"}[err == nil]; got != e.Relay {
			t.Errorf("%s: relay verdict %s, vector says %s", e.Name, got, e.Relay)
		}
	}
	for c, n := range v.Constants.EnvelopeLength {
		if Class(c).EnvelopeLength() != n {
			t.Errorf("class %s length %d, spec %d", c, Class(c).EnvelopeLength(), n)
		}
	}
	// The Live Activity class byte is reserved in version 1: no envelope of that class passes the relay,
	// whatever its length.
	for _, n := range []int{563, 1075} {
		env := make([]byte, n)
		env[0], env[1], env[2] = envelopeVersion, envelopeSuite, 0x03
		if CheckEnvelopeFrame(ClassLiveActivity, env) == nil {
			t.Errorf("reserved liveactivity envelope of %d bytes accepted", n)
		}
	}
}

// TestVectorsStatements: the Go text builders produce byte-identical statements to the reference, and Go
// Ed25519 produces the same (deterministic) signatures.
func TestVectorsStatements(t *testing.T) {
	v := LoadVectors(t)
	k := v.Keys
	inst, rot, bind, rel := seedKey(t, k.InstanceSeed), seedKey(t, k.InstanceRot), seedKey(t, k.BindingSeed), seedKey(t, k.RelaySeed)
	tok, _ := ParseToken(k.APNsToken)
	la, _ := ParseToken(k.LAToken)
	tag := TokenTag(tok)
	h, now := v.Constants.Host, v.Constants.Now
	byName := map[string]string{}
	keyOf := map[string]ed25519.PrivateKey{}
	for _, s := range v.Statements {
		byName[s.Name] = s.Text
	}
	challenge := strings.Split(byName["challenge"], "\n")[2]
	build := map[string]struct {
		text string
		key  ed25519.PrivateKey
	}{
		"register":             {RegisterText(h, ed25519.PublicKey(inst[32:]), now), inst},
		"request":              {RequestText(h, k.InstanceID, "POST", "/v1/push", now, k.Nonce, []byte(`{"items":[]}`)), inst},
		"requestWithQuery":     {RequestText(h, k.InstanceID, "GET", "/v1/status?probe=1", now, k.Nonce, nil), inst},
		"rotateNewKeyProof":    {RegisterText(h, ed25519.PublicKey(rot[32:]), now), rot},
		"bind":                 {BindText(h, k.InstanceID, tag, "device", 7, now), bind},
		"unbind":               {UnbindText(h, k.InstanceID, tag, now), bind},
		"challenge":            {ChallengeText(h, challenge, tag), bind},
		"activity":             {ActivityText(h, k.InstanceID, tag, TokenTag(la), now), bind},
		"selfRead":             {SelfReadText(h, tag, now), bind},
		"laStart":              {LAStartText(h, k.InstanceID, tag, TokenTag(la), now), bind},
		"laConsent":            {LAConsentText(h, k.InstanceID, tag, "2026-11-21", now), bind},
		"laWithdraw":           {LAWithdrawText(h, k.InstanceID, tag, now), bind},
		"response":             {ResponseText(h, "POST", "/v1/push", k.Nonce, 200, []byte(`{"items":[]}`)), rel},
		"responseAppEndpoint":  {ResponseText(h, "DELETE", "/v1/bindings/self", k.Nonce, 204, nil), rel},
		"responseWithoutNonce": {ResponseText(h, "GET", "/healthz", "-", 200, []byte(`{"status":"ok"}`)), rel},
		"registryExport":       {ExportText(h, []byte(`{"format":"healthlog-push-registry-v2"}`)), rel},
		"statusFile":           {StatusFileText(h, []byte(`{"notice":null}`)), rel},
	}
	for _, s := range v.Statements {
		b, ok := build[s.Name]
		if !ok {
			t.Errorf("vector %s has no Go builder", s.Name)
			continue
		}
		keyOf[s.Name] = b.key
		if b.text != s.Text {
			t.Errorf("%s: text differs\n go: %q\nref: %q", s.Name, b.text, s.Text)
		}
		pk, err := ParsePublicKey(s.PublicKey)
		if err != nil || !pk.Equal(b.key.Public()) {
			t.Errorf("%s: public key differs", s.Name)
		}
		sig, err := ParseSignature(s.Signature)
		if err != nil || !Verify(pk, s.Text, sig) {
			t.Errorf("%s: signature does not verify", s.Name)
		}
		if EncodeB64(ed25519.Sign(b.key, []byte(b.text))) != s.Signature {
			t.Errorf("%s: Go signature differs from reference", s.Name)
		}
	}
	for _, n := range v.NegativeStatements {
		var of struct{ pk, sig string }
		for _, s := range v.Statements {
			if s.Name == n.Of {
				of.pk, of.sig = s.PublicKey, s.Signature
			}
		}
		pk, _ := ParsePublicKey(of.pk)
		sig, _ := ParseSignature(of.sig)
		if Verify(pk, n.Text, sig) {
			t.Errorf("negative %s verified", n.Name)
		}
	}
}
