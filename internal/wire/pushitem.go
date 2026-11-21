package wire

import (
	"bytes"
	"crypto/ed25519"
)

// Activity is the Live Activity part of a liveactivity push item.
type Activity struct {
	Token      string `json:"token"`
	BindingKey string `json:"bindingKey"`
	Statement  struct {
		InstanceID string `json:"instanceId"`
		TokenTag   string `json:"tokenTag"`
		LATokenTag string `json:"laTokenTag"`
		Iat        int64  `json:"iat"`
	} `json:"statement"`
	Signature string `json:"signature"`
}

// PushItem is one entry of POST /v1/push.
type PushItem struct {
	Ref        string    `json:"ref"`
	Token      string    `json:"token"`
	Env        string    `json:"env"`
	Class      Class     `json:"class"`
	TTLSeconds int64     `json:"ttlSeconds"`
	Envelope   string    `json:"envelope,omitempty"`
	Collapse   string    `json:"collapse,omitempty"`
	Activity   *Activity `json:"activity,omitempty"`
}

// PushBody is the body of POST /v1/push.
type PushBody struct {
	Items []PushItem `json:"items"`
}

// MaxPushItems is the largest batch the relay accepts.
const MaxPushItems = 50

// ParsePushBody decodes the batch. Unknown fields anywhere make the whole request invalid; per-item
// checks happen in ValidateItem.
func ParsePushBody(b []byte) (*PushBody, error) {
	var pb PushBody
	if err := DecodeStrict(b, &pb); err != nil {
		return nil, err
	}
	if len(pb.Items) == 0 {
		return nil, ErrInvalid
	}
	return &pb, nil
}

// Item is a validated push item.
type Item struct {
	Ref        string
	Token      []byte
	Env        string
	Class      Class
	TTL        int64
	Envelope   []byte
	Collapse   string
	LAToken    []byte
	BindingKey ed25519.PublicKey
	actIat     int64
	actSig     []byte
	actTag     []byte
}

// ValidateItem checks one push item without touching any state: formats, envelope frame, collapse rules,
// and the shape of the activity statement. ttl above the class maximum is clamped.
func ValidateItem(p *PushItem) (*Item, error) {
	if !ValidRef(p.Ref) || !p.Class.Valid() {
		return nil, ErrInvalid
	}
	tok, err := ParseToken(p.Token)
	if err != nil {
		return nil, err
	}
	if !validEnv(p.Env) || p.TTLSeconds <= 0 {
		return nil, ErrInvalid
	}
	it := &Item{Ref: p.Ref, Token: tok, Env: p.Env, Class: p.Class, TTL: min(p.TTLSeconds, p.Class.MaxTTL())}
	if p.Class == ClassLiveActivity {
		if p.Envelope != "" || p.Collapse != "" || p.Activity == nil {
			return nil, ErrInvalid
		}
		if err := validateActivity(p.Activity, tok, it); err != nil {
			return nil, err
		}
		return it, nil
	}
	if p.Activity != nil {
		return nil, ErrInvalid
	}
	env, err := DecodeB64(p.Envelope, p.Class.EnvelopeLength())
	if err != nil {
		return nil, err
	}
	if err := CheckEnvelopeFrame(p.Class, env); err != nil {
		return nil, err
	}
	// An alert always carries a collapse id; a silent push may.
	if (p.Class == ClassAlert || p.Collapse != "") && !ValidCollapse(p.Collapse) {
		return nil, ErrInvalid
	}
	it.Envelope, it.Collapse = env, p.Collapse
	return it, nil
}

// validateActivity checks the shape of the activity statement of a liveactivity item for device token tok
// and fills the activity fields of it. The signature is checked later, by VerifyActivity.
func validateActivity(a *Activity, tok []byte, it *Item) error {
	la, err := ParseToken(a.Token)
	if err != nil {
		return err
	}
	pk, err := ParsePublicKey(a.BindingKey)
	if err != nil {
		return err
	}
	sig, err := ParseSignature(a.Signature)
	if err != nil {
		return err
	}
	tag, err := ParseTokenTag(a.Statement.TokenTag)
	if err != nil || !bytes.Equal(tag, TokenTag(tok)) {
		return ErrInvalid
	}
	laTag, err := ParseTokenTag(a.Statement.LATokenTag)
	if err != nil || !bytes.Equal(laTag, TokenTag(la)) {
		return ErrInvalid
	}
	if !ValidInstanceID(a.Statement.InstanceID) {
		return ErrInvalid
	}
	it.LAToken, it.BindingKey, it.actIat, it.actSig, it.actTag = la, pk, a.Statement.Iat, sig, tag
	return nil
}

// ActivityMaxAge bounds how old an activity statement may be when the end is sent: the activity lifetime
// (8 h) plus the class deadline (4 h).
const ActivityMaxAge = 12 * 3600

// VerifyActivity checks the activity statement for instanceID: signature, age and not in the future.
func (it *Item) VerifyActivity(host, instanceID string, now int64) bool {
	if it.Class != ClassLiveActivity || it.actIat > now+ClockSkew || now-it.actIat > ActivityMaxAge {
		return false
	}
	return Verify(it.BindingKey, ActivityText(host, instanceID, it.actTag, TokenTag(it.LAToken), it.actIat), it.actSig)
}

// ReceiptsBody is the body of POST /v1/receipts: counts only, no ids.
type ReceiptsBody struct {
	Accepted  int64 `json:"accepted"`
	Confirmed int64 `json:"confirmed"`
}

// ParseReceipts parses POST /v1/receipts.
func ParseReceipts(b []byte) (*ReceiptsBody, error) {
	var rb ReceiptsBody
	if err := DecodeStrict(b, &rb); err != nil {
		return nil, err
	}
	if rb.Accepted < 0 || rb.Confirmed < 0 || rb.Confirmed > rb.Accepted || rb.Accepted > 100000 {
		return nil, ErrInvalid
	}
	return &rb, nil
}
