package wire

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

// Wallet bounds (spec/wallet.md).
const (
	WalletBodyMax       = 16 << 10 // body of POST /v1/wallet/apple/sign and /notify
	WalletManifestMax   = 8 << 10  // manifest.json bytes
	WalletNotifyMax     = 50       // items per notify request
	WalletFrameMax      = 16 << 10 // one request on the wallet socket
	WalletReplyFrameMax = 32 << 10 // one answer on the wallet socket
)

// WalletSignBody is the body of POST /v1/wallet/apple/sign.
type WalletSignBody struct {
	V        int    `json:"v"`
	Manifest string `json:"manifest"` // unpadded base64url of the exact manifest.json bytes
}

// ParseWalletSign returns the manifest bytes of a sign body. Only the shape is checked here; the file set
// and the pins are checked by internal/wallet, in the relay and again in the wallet process.
func ParseWalletSign(b []byte) ([]byte, error) {
	var sb WalletSignBody
	if err := DecodeStrict(b, &sb); err != nil || sb.V != 1 {
		return nil, ErrInvalid
	}
	if sb.Manifest == "" || len(sb.Manifest) > base64.RawURLEncoding.EncodedLen(WalletManifestMax) ||
		strings.ContainsAny(sb.Manifest, "=+/ \n\r\t") {
		return nil, ErrInvalid
	}
	m, err := base64.RawURLEncoding.DecodeString(sb.Manifest)
	if err != nil {
		return nil, ErrInvalid
	}
	return m, nil
}

// WalletSignResp is the answer to a successful sign request.
type WalletSignResp struct {
	Signature          string `json:"signature"` // unpadded base64url of the DER SignedData
	PassTypeIdentifier string `json:"passTypeIdentifier"`
	TeamIdentifier     string `json:"teamIdentifier"`
	SignerSubjectO     string `json:"signerSubjectO"`
	CertNotAfterDay    int    `json:"certNotAfterDay"`
}

// WalletNotifyItem is one pass update push.
type WalletNotifyItem struct {
	Ref   string `json:"ref"`
	Token string `json:"token"` // the pass push token Wallet registered with the instance, hex
}

// WalletNotifyBody is the body of POST /v1/wallet/apple/notify.
type WalletNotifyBody struct {
	Items []WalletNotifyItem `json:"items"`
}

// WalletNotifyResult is the result of one item.
type WalletNotifyResult struct {
	Ref    string `json:"ref"`
	Result string `json:"result"`
}

// WalletNotifyResp is the answer to a notify request.
type WalletNotifyResp struct {
	Results []WalletNotifyResult `json:"results"`
}

// Results of one pass update push.
const (
	PassAccepted     = "accepted"
	PassUnregistered = "unregistered" // the instance drops the registration
	PassRejected     = "rejected"
	PassTokenQuota   = "token_quota"
	PassUnavailable  = "unavailable" // try again later
)

var (
	walletRefRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	passTokenRE   = regexp.MustCompile(`^[0-9a-fA-F]{64,200}$`)
	passTypeIDRE  = regexp.MustCompile(`^pass\.[A-Za-z0-9.-]{1,120}$`)
	teamIDRE      = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	walletOpsList = []string{WalletOpSign, WalletOpNotify, WalletOpInfo}
)

// ValidPassTypeID and ValidTeamID check Apple's identifiers.
func ValidPassTypeID(s string) bool { return passTypeIDRE.MatchString(s) }

// ValidTeamID checks a ten-character Apple team identifier.
func ValidTeamID(s string) bool { return teamIDRE.MatchString(s) }

// ParseWalletNotify parses a notify body: 1 to 50 items, unique refs, even-length hex tokens of 32 to 100
// bytes. It returns the items and their tokens as bytes.
func ParseWalletNotify(b []byte) ([]WalletNotifyItem, [][]byte, error) {
	var nb WalletNotifyBody
	if err := DecodeStrict(b, &nb); err != nil || len(nb.Items) == 0 || len(nb.Items) > WalletNotifyMax {
		return nil, nil, ErrInvalid
	}
	seen := map[string]bool{}
	toks := make([][]byte, len(nb.Items))
	for i, it := range nb.Items {
		if !walletRefRE.MatchString(it.Ref) || seen[it.Ref] || !passTokenRE.MatchString(it.Token) || len(it.Token)%2 != 0 {
			return nil, nil, ErrInvalid
		}
		seen[it.Ref] = true
		t, err := hex.DecodeString(it.Token)
		if err != nil {
			return nil, nil, ErrInvalid
		}
		toks[i] = t
	}
	return nb.Items, toks, nil
}

// The wallet socket (spec/wallet.md, "Processes"): the relay sends one request per connection, framed by a
// four-byte big-endian length, and reads one answer framed the same way.

// Operations on the wallet socket.
const (
	WalletOpSign   = "sign"
	WalletOpNotify = "notify"
	WalletOpInfo   = "info"
)

// Errors the wallet process answers.
const (
	WalletErrManifest    = "manifest_invalid" // with a reason from internal/wallet
	WalletErrUnavailable = "unavailable"      // certificate too close to expiry, or the push path is down
	WalletErrBadRequest  = "bad_request"
)

// WalletRequest is one request from the relay to the wallet process.
type WalletRequest struct {
	Op       string   `json:"op"`
	Manifest []byte   `json:"manifest,omitempty"` // sign
	Tokens   [][]byte `json:"tokens,omitempty"`   // notify, at most WalletNotifyMax
}

// ValidOp reports whether the request names a known operation with the fields it needs.
func (w *WalletRequest) ValidOp() bool {
	for _, op := range walletOpsList {
		if w.Op != op {
			continue
		}
		switch op {
		case WalletOpSign:
			return len(w.Manifest) > 0 && len(w.Manifest) <= WalletManifestMax && w.Tokens == nil
		case WalletOpNotify:
			return len(w.Tokens) > 0 && len(w.Tokens) <= WalletNotifyMax && w.Manifest == nil
		default:
			return w.Manifest == nil && w.Tokens == nil
		}
	}
	return false
}

// WalletInfo describes the signing identity; every answer of the wallet process carries it.
type WalletInfo struct {
	PassTypeIdentifier string `json:"passTypeIdentifier"`
	TeamIdentifier     string `json:"teamIdentifier"`
	SignerSubjectO     string `json:"signerSubjectO"`
	CertNotAfterDay    int    `json:"certNotAfterDay"`
	CertDaysLeft       int    `json:"certDaysLeft"`
	// Usable is false once the certificate has less than seven days left: the process then signs nothing.
	Usable bool `json:"usable"`
}

// WalletReply is the answer of the wallet process.
type WalletReply struct {
	Error     string     `json:"error,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Signature []byte     `json:"signature,omitempty"`
	Results   []string   `json:"results,omitempty"` // notify: one of the Pass* results per token, in order
	Info      WalletInfo `json:"info"`
}
