// Package wire holds every parser and every signed text of the relay protocol (spec/protocol.md,
// spec/statements.md). Everything that reads bytes from the network goes through this package, and every
// parser here has a fuzz test.
package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// ClockSkew is the accepted difference between a signed time and the relay clock, in seconds.
const ClockSkew = 300

// Parser errors. Callers map each to a fixed reason.
var (
	// ErrInvalid is returned by every parser for any malformed input.
	ErrInvalid = errors.New("invalid")
	// ErrStale marks a well-formed statement whose time is outside the accepted window.
	ErrStale = errors.New("stale")
	// ErrSignature marks a well-formed statement whose signature does not verify.
	ErrSignature = errors.New("signature")
)

var b64 = base64.RawURLEncoding

// DecodeB64 decodes unpadded base64url and requires exactly n bytes when n > 0.
func DecodeB64(s string, n int) ([]byte, error) {
	if len(s) > 4096 || strings.ContainsAny(s, "=+/ \n\r\t") {
		return nil, ErrInvalid
	}
	b, err := b64.DecodeString(s)
	if err != nil || (n > 0 && len(b) != n) {
		return nil, ErrInvalid
	}
	return b, nil
}

// EncodeB64 encodes unpadded base64url.
func EncodeB64(b []byte) string { return b64.EncodeToString(b) }

// ParsePublicKey decodes an Ed25519 public key in base64url.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := DecodeB64(s, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

// ParseSignature decodes an Ed25519 signature in base64url.
func ParseSignature(s string) ([]byte, error) { return DecodeB64(s, ed25519.SignatureSize) }

// Verify checks an Ed25519 signature over a statement text.
func Verify(pk ed25519.PublicKey, text string, sig []byte) bool {
	if len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pk, []byte(text), sig)
}

// ParseToken parses an APNs device or activity token: lowercase or uppercase hex, 32 to 100 bytes.
func ParseToken(s string) ([]byte, error) {
	if len(s) < 64 || len(s) > 200 || len(s)%2 != 0 {
		return nil, ErrInvalid
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

// TokenTag is SHA-256("hl-push-token" || token)[0:16], the value the device signs and the envelope AAD binds.
func TokenTag(token []byte) []byte {
	h := sha256.New()
	h.Write([]byte("hl-push-token"))
	h.Write(token)
	return h.Sum(nil)[:16]
}

// ParseTokenTag parses a 16-byte token tag in lowercase hex.
func ParseTokenTag(s string) ([]byte, error) {
	if len(s) != 32 || strings.ToLower(s) != s {
		return nil, ErrInvalid
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

var (
	uuidRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	refRE       = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,40}$`)
	collapseRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	consentRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	dayRE       = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	clientRE    = regexp.MustCompile(`^[a-z0-9-]{1,32}/\d{1,4}\.\d{1,4}\.\d{1,6}$`)
	noticeRE    = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	challengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// ValidInstanceID reports whether s is a lowercase UUIDv4.
func ValidInstanceID(s string) bool { return uuidRE.MatchString(s) }

// ValidRef reports whether s is a valid idempotency reference.
func ValidRef(s string) bool { return refRE.MatchString(s) }

// ValidCollapse reports whether s is a valid collapse id (22 base64url characters).
func ValidCollapse(s string) bool { return collapseRE.MatchString(s) }

// ValidConsentVersion reports whether s is a valid consent text version.
func ValidConsentVersion(s string) bool { return consentRE.MatchString(s) }

// ValidDay reports whether s looks like YYYY-MM-DD.
func ValidDay(s string) bool { return dayRE.MatchString(s) }

// ValidNoticeID reports whether s is a valid notice identifier.
func ValidNoticeID(s string) bool { return noticeRE.MatchString(s) }

// ValidChallenge reports whether s is a 32-byte challenge in base64url.
func ValidChallenge(s string) bool { return challengeRE.MatchString(s) }

// ParseClient parses "name/major.minor.patch" and returns the version triple.
func ParseClient(s string) (name string, ver [3]int, err error) {
	if !clientRE.MatchString(s) {
		return "", ver, ErrInvalid
	}
	name, v, _ := strings.Cut(s, "/")
	parts := strings.Split(v, ".")
	for i, p := range parts {
		n, e := strconv.Atoi(p)
		if e != nil {
			return "", ver, ErrInvalid
		}
		ver[i] = n
	}
	return name, ver, nil
}

// ParseUnix parses a decimal unix time in seconds, rejecting signs, leading zeros and absurd values.
func ParseUnix(s string) (int64, error) {
	if s == "" || len(s) > 11 || (len(s) > 1 && s[0] == '0') {
		return 0, ErrInvalid
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, ErrInvalid
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, ErrInvalid
	}
	return n, nil
}

// ParseNonce validates a request nonce: 16 bytes in unpadded base64url (22 characters).
func ParseNonce(s string) (string, error) {
	if len(s) != 22 {
		return "", ErrInvalid
	}
	if _, err := DecodeB64(s, 16); err != nil {
		return "", err
	}
	return s, nil
}

// hexSHA256 is the lowercase hex SHA-256 of b.
func hexSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// JWTIssuedAt extracts the iat claim of a provider JWT without verifying it. It is the one JWT parser of the
// relay and the signer; a token without three parts or without a non-zero iat is invalid.
func JWTIssuedAt(jwt string) (int64, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return 0, ErrInvalid
	}
	b, err := DecodeB64(parts[1], 0)
	if err != nil {
		return 0, err
	}
	var c struct {
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(b, &c); err != nil || c.Iat == 0 {
		return 0, ErrInvalid
	}
	return c.Iat, nil
}

func join(fields ...string) string { return strings.Join(fields, "\n") }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// RegisterText is signed by a new instance key (proof of possession) at registration and rotation.
func RegisterText(host string, pub ed25519.PublicKey, t int64) string {
	return join("hl-register-v1", host, hex.EncodeToString(pub), itoa(t))
}

// RequestText is signed by the instance for every authenticated request.
func RequestText(host, instanceID, method, pathQuery string, t int64, nonce string, body []byte) string {
	return join("hl-relay-v1", host, instanceID, method, pathQuery, itoa(t), nonce, hexSHA256(body))
}

// ResponseText is signed by the relay identity key for every response. It binds the response to the request
// by method, path with query (the raw request target) and nonce. nonce is "-" only for the public monitoring
// endpoints (/healthz, /version) and for the refusal of a request that carried no valid nonce; a client must
// treat a response bound to "-" as untrusted.
func ResponseText(host, method, pathQuery, nonce string, status int, body []byte) string {
	return join("hl-relay-resp-v2", host, method, pathQuery, nonce, strconv.Itoa(status), hexSHA256(body))
}

// StatusFileText is signed by the relay identity key for the out-of-band status file.
func StatusFileText(host string, body []byte) string {
	return join("hl-relay-status-v1", host, hexSHA256(body))
}

// BindText is signed by the device binding key.
func BindText(host, instanceID string, tokenTag []byte, kind string, seq, iat int64) string {
	return join("hl-bind-v1", host, instanceID, hex.EncodeToString(tokenTag), kind, itoa(seq), itoa(iat))
}

// UnbindText is signed by the device binding key for the direct opt-out.
func UnbindText(host, instanceID string, tokenTag []byte, iat int64) string {
	return join("hl-unbind-v1", host, instanceID, hex.EncodeToString(tokenTag), itoa(iat))
}

// ChallengeText is signed by the device binding key to answer a conflict challenge.
func ChallengeText(host, challenge string, tokenTag []byte) string {
	return join("hl-challenge-v1", host, challenge, hex.EncodeToString(tokenTag))
}

// ActivityText is signed by the device binding key when a Live Activity starts.
func ActivityText(host, instanceID string, tokenTag, laTokenTag []byte, iat int64) string {
	return join("hl-activity-v1", host, instanceID, hex.EncodeToString(tokenTag), hex.EncodeToString(laTokenTag), itoa(iat))
}

// SelfReadText is signed by the device binding key to read its own binding.
func SelfReadText(host string, tokenTag []byte, iat int64) string {
	return join("hl-selfread-v1", host, hex.EncodeToString(tokenTag), itoa(iat))
}

// WithinSkew reports whether t is within ClockSkew seconds of now.
func WithinSkew(t, now int64) bool {
	d := t - now
	return d <= ClockSkew && d >= -ClockSkew
}
