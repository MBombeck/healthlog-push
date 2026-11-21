package wire

// Class is a push class. The relay knows exactly three.
type Class string

// The push classes (spec/envelope.md).
const (
	ClassAlert        Class = "alert"
	ClassSilent       Class = "silent"
	ClassLiveActivity Class = "liveactivity"
)

// Envelope frame constants (spec/envelope.md, section "Format").
const (
	envelopeVersion = 0x01
	envelopeSuite   = 0x01
	envHeader       = 3
	envEnc          = 32
	envTag          = 16
	// sealedLength is the exact wire length of a version 1 envelope.
	sealedLength = envHeader + envEnc + 1024 + envTag
)

// classInfo holds everything the relay knows about a class, so that a new class cannot miss one value.
type classInfo struct {
	envelopeByte byte  // the class byte inside the envelope frame
	maxTTL       int64 // longest accepted lifetime in seconds
	envelopeLen  int   // exact envelope length, 0 for a class without an envelope
}

// classes is the closed class table. Version 1 seals alert and silent content only; the Live Activity class
// byte 0x03 is reserved and a liveactivity item travels as a fixed template without an envelope.
var classes = map[Class]classInfo{
	ClassAlert:        {envelopeByte: 0x01, maxTTL: 6 * 3600, envelopeLen: sealedLength},
	ClassSilent:       {envelopeByte: 0x02, maxTTL: 3600, envelopeLen: sealedLength},
	ClassLiveActivity: {envelopeByte: 0x03, maxTTL: 4 * 3600},
}

// ClassByte returns the envelope class byte of c, or 0 for an unknown class.
func (c Class) ClassByte() byte { return classes[c].envelopeByte }

// Valid reports whether c is one of the three classes.
func (c Class) Valid() bool { return c.ClassByte() != 0 }

// MaxTTL is the longest lifetime the relay accepts for a class, in seconds.
func (c Class) MaxTTL() int64 { return classes[c].maxTTL }

// EnvelopeLength is the exact wire length of an envelope of class c, or 0 for a class that carries no
// envelope.
func (c Class) EnvelopeLength() int { return classes[c].envelopeLen }

// CheckEnvelopeFrame validates the outer frame of an envelope for the class the push item claims:
// version, suite, class byte and exact length. The content stays opaque; the relay never decrypts.
func CheckEnvelopeFrame(c Class, env []byte) error {
	if !c.Valid() || c.EnvelopeLength() == 0 || len(env) != c.EnvelopeLength() {
		return ErrInvalid
	}
	if env[0] != envelopeVersion || env[1] != envelopeSuite || env[2] != c.ClassByte() {
		return ErrInvalid
	}
	return nil
}
