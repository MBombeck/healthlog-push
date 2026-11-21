package wire

import "crypto/ed25519"

// Activity is the Live Activity part of a liveactivity push item. Event is start, update or end (end when
// absent); State is required for start and update and refused for end.
type Activity struct {
	Event      string        `json:"event,omitempty"`
	State      *ContentState `json:"state,omitempty"`
	Token      string        `json:"token"`
	BindingKey string        `json:"bindingKey"`
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
	Event      string        // Live Activity only: start, update or end
	State      *ContentState // Live Activity start and update only
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
