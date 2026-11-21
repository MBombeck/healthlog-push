package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
)

// validEnv reports whether env names an APNs environment.
func validEnv(env string) bool { return env == "production" || env == "sandbox" }

// DecodeStrict decodes exactly one JSON value into v, refusing unknown fields and trailing data.
func DecodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrInvalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

// RegisterBody is the body of POST /v1/instances and POST /v1/instances/self/rotate.
type RegisterBody struct {
	PublicKey string `json:"publicKey"`
	Client    string `json:"client,omitempty"`
	Time      int64  `json:"time"`
	Proof     string `json:"proof"`
	Invite    string `json:"invite,omitempty"`
}

// Registration is a parsed, signature-checked registration.
type Registration struct {
	PublicKey ed25519.PublicKey
	Client    string
	Invite    string
}

// ParseRegistration parses and verifies a registration body against the relay host and clock.
// It returns ErrStale for a valid body whose time is outside the skew.
func ParseRegistration(b []byte, host string, now int64) (*Registration, error) {
	var rb RegisterBody
	if err := DecodeStrict(b, &rb); err != nil {
		return nil, err
	}
	pk, err := ParsePublicKey(rb.PublicKey)
	if err != nil {
		return nil, err
	}
	sig, err := ParseSignature(rb.Proof)
	if err != nil {
		return nil, err
	}
	if rb.Client != "" {
		if _, _, err := ParseClient(rb.Client); err != nil {
			return nil, err
		}
	}
	if len(rb.Invite) > 64 {
		return nil, ErrInvalid
	}
	if !WithinSkew(rb.Time, now) {
		return nil, ErrStale
	}
	if !Verify(pk, RegisterText(host, pk, rb.Time), sig) {
		return nil, ErrSignature
	}
	return &Registration{PublicKey: pk, Client: rb.Client, Invite: rb.Invite}, nil
}

// Statement is the device binding statement as sent on the wire.
type Statement struct {
	InstanceID string `json:"instanceId"`
	TokenTag   string `json:"tokenTag"`
	Kind       string `json:"kind"`
	Seq        int64  `json:"seq"`
	Iat        int64  `json:"iat"`
}

// Consent records which consent text the person accepted and on which day.
type Consent struct {
	TextVersion string `json:"textVersion"`
	Day         string `json:"day"`
}

// BindBody is the body of POST /v1/bindings.
type BindBody struct {
	Token      string    `json:"token"`
	Env        string    `json:"env"`
	BindingKey string    `json:"bindingKey"`
	Statement  Statement `json:"statement"`
	Signature  string    `json:"signature"`
	Consent    Consent   `json:"consent"`
}

// Bind is a parsed, signature-checked binding request.
type Bind struct {
	Token      []byte
	Env        string
	BindingKey ed25519.PublicKey
	Seq        int64
	Iat        int64
	Consent    Consent
}

// ParseBind parses a binding request and verifies the device statement. The statement must name the
// requesting instance, the token in the body and the kind "device".
func ParseBind(b []byte, host, instanceID string, now int64) (*Bind, error) {
	var bb BindBody
	if err := DecodeStrict(b, &bb); err != nil {
		return nil, err
	}
	tok, err := ParseToken(bb.Token)
	if err != nil {
		return nil, err
	}
	if !validEnv(bb.Env) {
		return nil, ErrInvalid
	}
	pk, err := ParsePublicKey(bb.BindingKey)
	if err != nil {
		return nil, err
	}
	sig, err := ParseSignature(bb.Signature)
	if err != nil {
		return nil, err
	}
	tag, err := ParseTokenTag(bb.Statement.TokenTag)
	if err != nil {
		return nil, err
	}
	if !ValidConsentVersion(bb.Consent.TextVersion) || !ValidDay(bb.Consent.Day) {
		return nil, ErrInvalid
	}
	if bb.Statement.Kind != "device" || bb.Statement.Seq < 0 || !bytes.Equal(tag, TokenTag(tok)) {
		return nil, ErrInvalid
	}
	if bb.Statement.InstanceID != instanceID {
		return nil, ErrSignature
	}
	if !WithinSkew(bb.Statement.Iat, now) {
		return nil, ErrStale
	}
	st := bb.Statement
	if !Verify(pk, BindText(host, instanceID, tag, st.Kind, st.Seq, st.Iat), sig) {
		return nil, ErrSignature
	}
	return &Bind{Token: tok, Env: bb.Env, BindingKey: pk, Seq: st.Seq, Iat: st.Iat, Consent: bb.Consent}, nil
}

// TokenBody is the body of DELETE /v1/bindings.
type TokenBody struct {
	Token string `json:"token"`
}

// ParseTokenBody parses a body that carries only a device token.
func ParseTokenBody(b []byte) ([]byte, error) {
	var tb TokenBody
	if err := DecodeStrict(b, &tb); err != nil {
		return nil, err
	}
	return ParseToken(tb.Token)
}

// UnbindBody is the body of DELETE /v1/bindings/self, sent by the app.
type UnbindBody struct {
	Token      string `json:"token"`
	BindingKey string `json:"bindingKey"`
	Statement  struct {
		InstanceID string `json:"instanceId"`
		TokenTag   string `json:"tokenTag"`
		Iat        int64  `json:"iat"`
	} `json:"statement"`
	Signature string `json:"signature"`
}

// Unbind is a parsed direct opt-out. The caller first compares the binding key with the stored key hash,
// then checks the signature with Verify.
type Unbind struct {
	Token      []byte
	BindingKey ed25519.PublicKey
	InstanceID string
	Iat        int64
	sig        []byte
}

// ParseUnbind parses DELETE /v1/bindings/self.
func ParseUnbind(b []byte, now int64) (*Unbind, error) {
	var ub UnbindBody
	if err := DecodeStrict(b, &ub); err != nil {
		return nil, err
	}
	tok, err := ParseToken(ub.Token)
	if err != nil {
		return nil, err
	}
	pk, err := ParsePublicKey(ub.BindingKey)
	if err != nil {
		return nil, err
	}
	sig, err := ParseSignature(ub.Signature)
	if err != nil {
		return nil, err
	}
	tag, err := ParseTokenTag(ub.Statement.TokenTag)
	if err != nil || !bytes.Equal(tag, TokenTag(tok)) || !ValidInstanceID(ub.Statement.InstanceID) {
		return nil, ErrInvalid
	}
	if !WithinSkew(ub.Statement.Iat, now) {
		return nil, ErrStale
	}
	return &Unbind{Token: tok, BindingKey: pk, InstanceID: ub.Statement.InstanceID, Iat: ub.Statement.Iat, sig: sig}, nil
}

// Verify checks the opt-out signature.
func (u *Unbind) Verify(host string) bool {
	return Verify(u.BindingKey, UnbindText(host, u.InstanceID, TokenTag(u.Token), u.Iat), u.sig)
}

// ChallengeBody is the body of POST /v1/bindings/challenge, sent by the app.
type ChallengeBody struct {
	BindingKey string `json:"bindingKey"`
	Challenge  string `json:"challenge"`
	TokenTag   string `json:"tokenTag"`
	Signature  string `json:"signature"`
}

// ChallengeAnswer is a parsed challenge answer; Verify checks it.
type ChallengeAnswer struct {
	BindingKey ed25519.PublicKey
	Challenge  string
	TokenTag   []byte
	sig        []byte
}

// ParseChallenge parses POST /v1/bindings/challenge.
func ParseChallenge(b []byte) (*ChallengeAnswer, error) {
	var cb ChallengeBody
	if err := DecodeStrict(b, &cb); err != nil {
		return nil, err
	}
	pk, err := ParsePublicKey(cb.BindingKey)
	if err != nil {
		return nil, err
	}
	sig, err := ParseSignature(cb.Signature)
	if err != nil {
		return nil, err
	}
	tag, err := ParseTokenTag(cb.TokenTag)
	if err != nil || !ValidChallenge(cb.Challenge) {
		return nil, ErrInvalid
	}
	return &ChallengeAnswer{BindingKey: pk, Challenge: cb.Challenge, TokenTag: tag, sig: sig}, nil
}

// Verify checks the challenge answer signature.
func (c *ChallengeAnswer) Verify(host string) bool {
	return Verify(c.BindingKey, ChallengeText(host, c.Challenge, c.TokenTag), c.sig)
}

// SelfRead carries the headers of GET /v1/bindings/self.
type SelfRead struct {
	Token      []byte
	BindingKey ed25519.PublicKey
	Iat        int64
	sig        []byte
}

// ParseSelfRead parses the HL-Token, HL-Binding-Key, HL-Iat and HL-Signature header values.
func ParseSelfRead(token, key, iat, sig string, now int64) (*SelfRead, error) {
	tok, err := ParseToken(token)
	if err != nil {
		return nil, err
	}
	pk, err := ParsePublicKey(key)
	if err != nil {
		return nil, err
	}
	t, err := ParseUnix(iat)
	if err != nil {
		return nil, err
	}
	s, err := ParseSignature(sig)
	if err != nil {
		return nil, err
	}
	if !WithinSkew(t, now) {
		return nil, ErrStale
	}
	return &SelfRead{Token: tok, BindingKey: pk, Iat: t, sig: s}, nil
}

// Verify checks the self-read signature.
func (s *SelfRead) Verify(host string) bool {
	return Verify(s.BindingKey, SelfReadText(host, TokenTag(s.Token), s.Iat), s.sig)
}
