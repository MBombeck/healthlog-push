package wire

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Every parser that reads network input has a fuzz target. The properties: no panic, and anything accepted
// is consistent with the rules (for example, an accepted envelope has the exact class length).

func FuzzParseRegistration(f *testing.F) {
	now := int64(1795000000)
	f.Add(regBody(testInst, testHost, now))
	f.Add([]byte(`{"publicKey":"","time":0,"proof":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		reg, err := ParseRegistration(b, testHost, now)
		if err == nil && len(reg.PublicKey) != 32 {
			t.Fatal("accepted a key of the wrong size")
		}
	})
}

func FuzzParseBind(f *testing.F) {
	now := int64(1795000000)
	inst := "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37"
	f.Add(bindBody(testDev, testHost, inst, tok(1), 1, now))
	f.Add([]byte(`{"token":"00","statement":{}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		bd, err := ParseBind(b, testHost, inst, now)
		if err == nil && (bd.Seq < 0 || len(bd.Token) < 32) {
			t.Fatal("accepted an invalid binding")
		}
	})
}

func FuzzPushItems(f *testing.F) {
	env := make([]byte, ClassAlert.EnvelopeLength())
	env[0], env[1], env[2] = 1, 1, 1
	f.Add([]byte(`{"items":[{"ref":"r1","token":"` + hex.EncodeToString(tok(1)) + `","env":"production","class":"alert","ttlSeconds":60,"envelope":"` +
		EncodeB64(env) + `","collapse":"` + strings.Repeat("A", 22) + `"}]}`))
	f.Add([]byte(`{"items":[{"class":"liveactivity","activity":{"statement":{}}}]}`))
	f.Add([]byte(`{"items":[{"ref":"r","token":"` + hex.EncodeToString(tok(1)) + `","env":"production","class":"liveactivity","ttlSeconds":60,` +
		`"activity":{"event":"update","token":"` + hex.EncodeToString(tok(2)) + `","bindingKey":"","statement":{},"signature":"",` +
		`"state":{"status":"due","countdownTarget":0,"isOverdue":false,"confirmed":false,"pendingConfirm":false,"timeFormatRaw":"AUTO"}}}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		pb, err := ParsePushBody(b)
		if err != nil {
			return
		}
		for i := range pb.Items {
			it, err := ValidateItem(&pb.Items[i])
			if err != nil {
				continue
			}
			if it.TTL <= 0 || it.TTL > it.Class.MaxTTL() {
				t.Fatal("ttl out of range accepted")
			}
			if it.Class != ClassLiveActivity && CheckEnvelopeFrame(it.Class, it.Envelope) != nil {
				t.Fatal("bad frame accepted")
			}
			if it.Class == ClassAlert && !ValidCollapse(it.Collapse) {
				t.Fatal("alert without collapse accepted")
			}
			_ = it.VerifyActivity(testHost, "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37", 1795000000)
			if it.State != nil && it.State.Check(1795000000) && !oneOf(*it.State.Status, StateStatuses) {
				t.Fatal("content state outside the template accepted")
			}
		}
	})
}

func FuzzCheckEnvelopeFrame(f *testing.F) {
	f.Add("alert", make([]byte, 1075))
	f.Add("liveactivity", make([]byte, 563))
	f.Fuzz(func(t *testing.T, c string, b []byte) {
		if CheckEnvelopeFrame(Class(c), b) == nil && (Class(c) == ClassLiveActivity || len(b) != Class(c).EnvelopeLength() || b[2] != Class(c).ClassByte()) {
			t.Fatal("frame check accepted a mismatch")
		}
	})
}

func FuzzParseUnbind(f *testing.F) {
	f.Add([]byte(`{"token":"` + hex.EncodeToString(tok(1)) + `","bindingKey":"","statement":{"instanceId":"","tokenTag":"","iat":0},"signature":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if u, err := ParseUnbind(b, 1795000000); err == nil {
			_ = u.Verify(testHost)
		}
	})
}

func FuzzParseChallenge(f *testing.F) {
	f.Add([]byte(`{"bindingKey":"","challenge":"","tokenTag":"","signature":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := ParseChallenge(b); err == nil {
			if !ValidChallenge(c.Challenge) {
				t.Fatal("bad challenge accepted")
			}
			_ = c.Verify(testHost)
		}
	})
}

func FuzzParseSelfRead(f *testing.F) {
	f.Add(hex.EncodeToString(tok(1)), "", "1795000000", "")
	f.Fuzz(func(t *testing.T, a, b, c, d string) {
		if s, err := ParseSelfRead(a, b, c, d, 1795000000); err == nil {
			_ = s.Verify(testHost)
		}
	})
}

func FuzzHeaders(f *testing.F) {
	f.Add("1795000000", EncodeB64(make([]byte, 16)), "healthlog/1.49.0", "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37")
	f.Fuzz(func(t *testing.T, ts, nonce, client, id string) {
		if n, err := ParseUnix(ts); err == nil && n < 0 {
			t.Fatal("negative time accepted")
		}
		if n, err := ParseNonce(nonce); err == nil && len(n) != 22 {
			t.Fatal("nonce length")
		}
		_, _, _ = ParseClient(client)
		_ = ValidInstanceID(id)
		_, _ = ParseToken(id)
		_, _ = ParseTokenTag(id)
	})
}

func FuzzParseReceipts(f *testing.F) {
	f.Add([]byte(`{"accepted":10,"confirmed":9}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := ParseReceipts(b); err == nil && (r.Confirmed > r.Accepted || r.Accepted < 0) {
			t.Fatal("inconsistent receipts accepted")
		}
	})
}

func FuzzJWTIssuedAt(f *testing.F) {
	f.Add("e30.eyJpYXQiOjEyM30.x")
	f.Add("a.b")
	f.Fuzz(func(t *testing.T, jwt string) {
		if n, err := JWTIssuedAt(jwt); err == nil && (n == 0 || strings.Count(jwt, ".") != 2) {
			t.Fatal("accepted a token without three parts or without iat")
		}
	})
}
