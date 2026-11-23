// Package notice embeds the privacy notice and the short terms that the relay serves at /privacy and
// /terms, and renders them as HTML for browsers. The files next to this one are the authoritative texts;
// docs/privacy.md and docs/terms.md are copies, kept in sync with them by a test, and the HTML is rendered
// from the same embedded text when the relay starts.
package notice

import _ "embed"

// Privacy is served at /privacy.
//
//go:embed privacy.md
var Privacy string

// Terms is served at /terms.
//
//go:embed terms.md
var Terms string

// Index is served at /.
const Index = `HealthLog push relay

This service forwards end-to-end encrypted notifications from self-hosted HealthLog servers to the
HealthLog iOS app through Apple Push Notification service. It cannot read their content.

Privacy notice: /privacy
Terms:          /terms
Health:         /healthz
Version:        /version
Source:         https://github.com/MBombeck/healthlog-push
Contact:        relay@healthlog.dev, abuse@healthlog.dev, privacy@healthlog.dev
Security:       /.well-known/security.txt
`

// SecurityTxt is served at /.well-known/security.txt (RFC 9116). Expires must be renewed every year;
// TestSecurityTxtCurrent fails a month before it lapses.
const SecurityTxt = `Contact: mailto:relay@healthlog.dev
Contact: https://github.com/MBombeck/healthlog-push/security/advisories/new
Expires: 2027-11-21T00:00:00Z
Preferred-Languages: en, de
Policy: https://github.com/MBombeck/healthlog-push/blob/main/SECURITY.md
`
