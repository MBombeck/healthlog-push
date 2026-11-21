package wire

import "bytes"

// Live Activity events the relay can send.
const (
	EventStart  = "start"
	EventUpdate = "update"
	EventEnd    = "end"
)

// Statement ages: an update or end statement covers one activity (at most 8 h plus the 4 h class deadline);
// a push-to-start token lives as long as the installation, so its statement is renewed by the app at least
// every 30 days.
const (
	ActivityMaxAge = 12 * 3600
	StartMaxAge    = 30 * 24 * 3600
)

// ContentState is the only Live Activity content the relay forwards. ActivityKit cannot decrypt, so the
// state travels in the clear; the template is closed: fixed keys, fixed types, closed enumerations and a
// bounded time, and no free text at all, in particular no medication name.
type ContentState struct {
	Status          *string `json:"status"`
	CountdownTarget *int64  `json:"countdownTarget"`
	IsOverdue       *bool   `json:"isOverdue"`
	Confirmed       *bool   `json:"confirmed"`
	PendingConfirm  *bool   `json:"pendingConfirm"`
	TimeFormatRaw   *string `json:"timeFormatRaw"`
}

// The closed enumerations of the content state.
var (
	StateStatuses    = []string{"pending", "due", "overdue", "snoozed", "taken", "skipped"}
	StateTimeFormats = []string{"AUTO", "H12", "H24"}
)

// Bounds of countdownTarget relative to the relay clock: 0 (no countdown) or a time from one day back to two
// days ahead.
const (
	countdownPast   = 24 * 3600
	countdownFuture = 48 * 3600
)

func oneOf(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// Check reports whether every field is present and inside its closed range at time now.
func (c *ContentState) Check(now int64) bool {
	if c == nil || c.Status == nil || c.CountdownTarget == nil || c.IsOverdue == nil || c.Confirmed == nil ||
		c.PendingConfirm == nil || c.TimeFormatRaw == nil {
		return false
	}
	t := *c.CountdownTarget
	if t != 0 && (t < now-countdownPast || t > now+countdownFuture) {
		return false
	}
	return oneOf(*c.Status, StateStatuses) && oneOf(*c.TimeFormatRaw, StateTimeFormats)
}

// validateActivity checks the shape of the activity part of a liveactivity item for device token tok and
// fills the activity fields of it. Signature, age and content-state range are checked later, by
// VerifyActivity and CheckState, because they need the instance and the clock.
func validateActivity(a *Activity, tok []byte, it *Item) error {
	event := a.Event
	if event == "" {
		event = EventEnd
	}
	switch event {
	case EventEnd:
		if a.State != nil {
			return ErrInvalid // the end carries a fixed state
		}
	case EventStart, EventUpdate:
		if a.State == nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
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
	if err != nil || !bytes.Equal(laTag, TokenTag(la)) || !ValidInstanceID(a.Statement.InstanceID) {
		return ErrInvalid
	}
	it.Event, it.State = event, a.State
	it.LAToken, it.BindingKey, it.actIat, it.actSig, it.actTag = la, pk, a.Statement.Iat, sig, tag
	return nil
}

// VerifyActivity checks the activity statement for instanceID: signature, age and not in the future. A start
// is signed as hl-la-start-v1 over the push-to-start token, an update or end as hl-activity-v1 over the
// activity's update token.
func (it *Item) VerifyActivity(host, instanceID string, now int64) bool {
	if it.Class != ClassLiveActivity || it.actIat > now+ClockSkew {
		return false
	}
	if it.Event == EventStart {
		return now-it.actIat <= StartMaxAge &&
			Verify(it.BindingKey, LAStartText(host, instanceID, it.actTag, TokenTag(it.LAToken), it.actIat), it.actSig)
	}
	return now-it.actIat <= ActivityMaxAge &&
		Verify(it.BindingKey, ActivityText(host, instanceID, it.actTag, TokenTag(it.LAToken), it.actIat), it.actSig)
}

// LAConsentBody is the body of POST /v1/bindings/liveactivity: the device's signed consent to Live Activity
// start and update, passed on by its instance.
type LAConsentBody struct {
	Token      string `json:"token"`
	BindingKey string `json:"bindingKey"`
	Consent    struct {
		TextVersion string `json:"textVersion"`
		Day         string `json:"day"`
		Iat         int64  `json:"iat"`
	} `json:"consent"`
	Signature string `json:"signature"`
}

// LAConsent is a parsed, signature-checked Live Activity consent.
type LAConsent struct {
	Token       []byte
	BindingKey  []byte
	TextVersion string
	Day         string
}

// ParseLAConsent parses and verifies a Live Activity consent for instanceID.
func ParseLAConsent(b []byte, host, instanceID string, now int64) (*LAConsent, error) {
	var cb LAConsentBody
	if err := DecodeStrict(b, &cb); err != nil {
		return nil, err
	}
	tok, err := ParseToken(cb.Token)
	if err != nil {
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
	c := cb.Consent
	if !ValidConsentVersion(c.TextVersion) || !ValidDay(c.Day) {
		return nil, ErrInvalid
	}
	if !WithinSkew(c.Iat, now) {
		return nil, ErrStale
	}
	if !Verify(pk, LAConsentText(host, instanceID, TokenTag(tok), c.TextVersion, c.Iat), sig) {
		return nil, ErrSignature
	}
	return &LAConsent{Token: tok, BindingKey: pk, TextVersion: c.TextVersion, Day: c.Day}, nil
}

// ParseLAWithdraw parses DELETE /v1/bindings/self/liveactivity; it has the opt-out's shape, signed as
// hl-la-withdraw-v1. Verify with VerifyWithdraw.
func ParseLAWithdraw(b []byte, now int64) (*Unbind, error) { return ParseUnbind(b, now) }

// VerifyWithdraw checks a Live Activity consent withdrawal signature.
func (u *Unbind) VerifyWithdraw(host string) bool {
	return Verify(u.BindingKey, LAWithdrawText(host, u.InstanceID, TokenTag(u.Token), u.Iat), u.sig)
}
