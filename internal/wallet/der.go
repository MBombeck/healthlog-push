package wallet

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"slices"
	"time"
)

// A minimal DER writer: just what the detached SignedData needs, written so that every byte is visible and
// the JavaScript reference (spec/tools/wallet.mjs) can produce the same bytes step by step.

// DER tags used here.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagUTCTime     = 0x17
	tagSequence    = 0x30
	tagSet         = 0x31
	tagContext0    = 0xa0 // [0], constructed
)

// Object identifiers of the SignedData (RFC 5652) and its attributes.
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// tlv writes one element: tag, definite length, content.
func tlv(tag byte, parts ...[]byte) []byte {
	content := bytes.Join(parts, nil)
	n := len(content)
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	case n <= 0xffff:
		out = append(out, 0x82, byte(n>>8), byte(n)) //nolint:gosec // n <= 0xffff: its two big-endian bytes
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n)) //nolint:gosec // elements stay far below 16 MiB
	}
	return append(out, content...)
}

func derOID(o asn1.ObjectIdentifier) []byte {
	b, err := asn1.Marshal(o)
	if err != nil {
		panic(err) // constant identifiers only
	}
	return b
}

func derInt(n *big.Int) []byte {
	b, err := asn1.Marshal(n)
	if err != nil {
		panic(err) // never for a non-nil integer
	}
	return b
}

func derSmallInt(n int64) []byte { return derInt(big.NewInt(n)) }

// derUTCTime is UTCTime YYMMDDHHMMSSZ, the form RFC 5652 requires for signingTime between 1950 and 2049.
func derUTCTime(t time.Time) []byte {
	return tlv(tagUTCTime, []byte(t.UTC().Format("060102150405")+"Z"))
}

// algorithm is an AlgorithmIdentifier with explicit NULL parameters, as node-forge and OpenSSL write them.
func algorithm(o asn1.ObjectIdentifier) []byte {
	return tlv(tagSequence, derOID(o), []byte{tagNull, 0})
}

// derSetOf is a DER SET OF: the encoded elements sorted bytewise (X.690, 11.6).
func derSetOf(tag byte, elems ...[]byte) []byte {
	sorted := slices.Clone(elems)
	slices.SortFunc(sorted, bytes.Compare)
	return tlv(tag, sorted...)
}
