// Package notice embeds the privacy notice and the short terms that the relay serves at /privacy and
// /terms. The files next to this one are the authoritative texts; docs/privacy.md points here.
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
`
