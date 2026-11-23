# Running your own relay

## First: do you need one?

An APNs key belongs to one Apple developer team, and a device token only works with the key of the team
that signed the app. From the design notes of this project:

> A self-hosted relay cannot serve the HealthLog app from the App Store. It works only with an app that you
> build yourself from source and sign with your own Apple developer account (99 USD a year). Whoever uses
> the App Store app uses either the maintainer's relay or no APNs at all.

So:

- **App Store app:** use the hosted relay at `push.healthlog.dev` (household use only), or no relay.
- **Your own app build, one HealthLog server:** the server can talk to APNs directly with your key; no relay
  is needed.
- **Your own app build, several servers or an organisation:** run your own relay as described here.

## What you need

- A small Linux host with a public IPv4 and preferably IPv6 address, Docker with the compose plugin, and a
  DNS name for it (`push.example.org` below). 256 MB of memory for the relay and 32 MB for the signer are
  the limits set in `deploy/compose/compose.yaml`; the compose file also sets `GOMEMLIMIT=220MiB` for the
  relay so that the Go runtime collects before the kernel would kill it.
- An APNs authentication key (`.p8`) from your Apple developer account, with its key id and your team id.
  Create it with the environment scope **"Sandbox & Production"**, so the same key serves development builds
  and TestFlight or App Store builds. A key limited to one environment fails on the other with
  `BadEnvironmentKeyInToken`.
- The bundle id of your app build as the APNs topic. The relay sends Live Activity starts, updates and
  ends to `<topic>.push-type.liveactivity`.
- A released image, pinned by digest and verified ([release-verification.md](release-verification.md)).

The Ansible roles in [deploy/ansible/](../deploy/ansible/README.md) turn a fresh Ubuntu 24.04 host into a
relay host and deploy verified releases. The steps below are the same contract by hand.

## Keys and secrets

```sh
IMAGE=ghcr.io/mbombeck/healthlog-push@sha256:<digest>
docker run --rm "$IMAGE" keygen relay-id
docker run --rm "$IMAGE" keygen relay-id       # a second one: your "next" identity
docker run --rm "$IMAGE" keygen token-mac
docker run --rm "$IMAGE" keygen acme-account
```

- `keygen relay-id` prints `{"relay_id_key": "<seed>", "publicKey": "<public key>"}`, both base64url. The
  seed is the secret; the public key is what your app build and your servers pin. Keep a second pair as
  `next` so you can switch identity later without a new app build.
- `keygen token-mac` prints 32 random bytes in base64url.
- `keygen acme-account` prints an EC P-256 key in PEM.

Store all values in your secret store, then write the files:

| File | Content | Owner, mode |
|---|---|---|
| `/srv/healthlog-push/secrets/relay/relay_id_key` | the `relay_id_key` value only (a base64 32-byte seed), or a PKCS#8 PEM Ed25519 key | 65532, 0400 |
| `/srv/healthlog-push/secrets/relay/token_mac_key` | base64 of at least 32 bytes | 65532, 0400 |
| `/srv/healthlog-push/secrets/relay/token_mac_key_previous` | optional, only during a MAC key rotation | 65532, 0400 |
| `/srv/healthlog-push/secrets/relay/acme_account_key` | PEM EC key (only needed with `HLP_TLS_MODE=acme`) | 65532, 0400 |
| `/srv/healthlog-push/secrets/signer/apns.p8` | your APNs key, PKCS#8 PEM, P-256 | 65533, 0400 |

Directories: `secrets/relay` owned by 65532 and `secrets/signer` by 65533, both 0500; `data` and `acme`
65532:65530 0700; `export` 65532:65530 0750. The relay never sees `apns.p8`; only the signer container
mounts it.

Do not back up `secrets/`, `data/` or `acme/`. Back up `export/registry.json`, which the relay writes daily.
Do not take provider snapshots of the host; a snapshot contains every secret.

## Configuration

Copy `deploy/compose/compose.yaml` and `deploy/compose/.env.example` to `/srv/healthlog-push/compose/`
(the latter as `.env`) and set at least `HLP_IMAGE`, `HLP_IMAGE_DIGEST`, `HLP_PUBLIC_HOST`, `HLP_APNS_TOPIC`,
`HLP_APNS_KEY_ID` and `HLP_APNS_TEAM_ID`. The compose file passes the variables below; the defaults are the
ones in `cmd/healthlog-push/main.go`.

### Relay (`healthlog-push relay`)

| Variable | Default | Meaning |
|---|---|---|
| `HLP_PUBLIC_HOST` | required | public host name; part of every signed text, the only name a certificate is requested for. Must be a lower-case DNS name without port or trailing dot (`push.example.org`); anything else stops the relay at start |
| `HLP_LISTEN` | `:8443` | public TLS listener |
| `HLP_TLS_MODE` | `acme` | `acme` (Let's Encrypt over TLS-ALPN-01) or `files` |
| `HLP_ACME_ACCOUNT_KEY_FILE` | `/run/secrets/relay/acme_account_key` | ACME account key, PEM EC |
| `HLP_ACME_CACHE_DIR` | `/acme` | certificate cache |
| `HLP_ACME_DIRECTORY` | Let's Encrypt production directory | ACME directory URL; use the staging directory for tests |
| `HLP_ACME_EMAIL` | empty | contact address for the ACME account |
| `HLP_TLS_CERT_FILE`, `HLP_TLS_KEY_FILE` | empty | certificate and key for `files` mode, read at start |
| `HLP_SECRETS_DIR` | `/run/secrets/relay` | directory with `relay_id_key`, `token_mac_key` and `token_mac_key_previous` |
| `HLP_DATA_DIR` | `/data` | bbolt database `relay.db` |
| `HLP_EXPORT_DIR` | `/export` | daily `registry.json` |
| `HLP_ADMIN_SOCKET` | `<HLP_DATA_DIR>/admin.sock` | operator socket; the `admin` subcommand uses the same default |
| `HLP_METRICS_LISTEN` | `127.0.0.1:9464` | `/metrics` and a local `/healthz`; keep it on loopback |
| `HLP_JWT_DIR` | `/run/jwt` | where the signer writes the provider token |
| `HLP_JWT_REFRESH_DIR` | `/run/jwt-refresh` | where the relay touches the refresh marker |
| `HLP_APNS_TOPIC` | required | your app's bundle id; there is no default |
| `HLP_APNS_ENVIRONMENT` | `production` | comma-separated list of served environments; only `production` and `sandbox` are accepted, any other value stops the relay at start |
| `HLP_MIN_CLIENT_VERSION` | none | refuse instance requests whose `HL-Client` version is lower, for example `1.49.0` (`426 min_server_version`); the compose file passes it from `.env`, and a value that is not `major.minor.patch` stops the relay at start |
| `HLP_IMAGE_DIGEST` | empty | shown at `/version`; the compose file requires it |
| `HLP_REGISTRATION_MODE` | `invite` | registration mode of a store that has none yet: `invite`, `closed` or `open`; applied and stored before the first request is accepted. A mode set later with `admin registration` is stored and wins (see [Registration](#registration)); any other value stops the relay at start |
| `HLP_APPARMOR_RELAY`, `HLP_APPARMOR_SIGNER` | `docker-default` | AppArmor profile per container, read by the compose file only (see [AppArmor](#apparmor)) |

### Signer (`healthlog-push signer`)

| Variable | Default | Meaning |
|---|---|---|
| `HLP_APNS_KEY_FILE` | `/run/secrets/signer/apns.p8` | the APNs key |
| `HLP_APNS_KEY_ID` or `HLP_APNS_KEY_ID_FILE` | required | key id from the Apple developer account |
| `HLP_APNS_TEAM_ID` or `HLP_APNS_TEAM_ID_FILE` | required | your team id |
| `HLP_JWT_DIR`, `HLP_JWT_REFRESH_DIR` | as above | the shared tmpfs volumes (1 MB each, mounted `noexec`, `nosuid`, `nodev`) |

The limits (`DefaultLimits`, `DefaultRegistrationLimits`) are compiled in; there is no variable for them in
this version. If one of the three listeners (public, metrics, admin socket) fails, the relay logs
`relay.listener_failed` with the listener's name, shuts down and exits with an error, so the container
restarts. So are Apple's endpoints (`api.push.apple.com` and `api.sandbox.push.apple.com`): no setting
can send the provider token or device tokens to another host. Per-instance device limits can be raised with `admin limits`.

### Serving development builds (sandbox)

Builds you run from Xcode get sandbox device tokens; TestFlight and App Store builds get production tokens.
Every binding states its environment, and the relay refuses a binding for an environment it does not serve
with `422 env_unsupported`. The compose file sets `HLP_APNS_ENVIRONMENT=production`. To serve both, add a
`compose.override.yaml` next to it:

```yaml
services:
  relay:
    environment:
      HLP_APNS_ENVIRONMENT: production,sandbox
```

The same APNs key is used for both, which is why it needs the "Sandbox & Production" scope.

### Certificates from files

With `HLP_TLS_MODE=files`, mount the certificate and key into the relay container in the override file and
point `HLP_TLS_CERT_FILE` and `HLP_TLS_KEY_FILE` at them. They are read at start only: restart the relay
after every renewal. TLS 1.3 is the minimum in both modes; only a TLS-ALPN-01 validation handshake in
`acme` mode, one that offers no ALPN protocol other than `acme-tls/1`, may use TLS 1.2.

### Registration

A new relay accepts no registration without a one-time code: it starts in `invite` (or in what
`HLP_REGISTRATION_MODE` says) and stores that mode before the listener takes its first request, so there is no
moment in which anyone could register. Register your own servers with codes:

```sh
docker compose exec relay /healthlog-push admin invite
```

To let any HealthLog server register, open it on purpose; the registration limits still apply:

```sh
docker compose exec relay /healthlog-push admin registration open
```

The stored mode survives restarts and updates; `HLP_REGISTRATION_MODE` only decides the first one.

### AppArmor

`deploy/apparmor/` holds one profile per container. They allow what the relay and the signer do and nothing
else: the relay reads its own secrets but not the APNs key, writes only `/data`, `/acme`, `/export` and the
refresh marker, and has no capability; the signer has no network rule at all and writes only the provider
token. Without them Docker applies its own `docker-default` profile. To use them on an AppArmor host:

```sh
install -m 0644 deploy/apparmor/healthlog-push-relay deploy/apparmor/healthlog-push-signer /etc/apparmor.d/
apparmor_parser -r -W /etc/apparmor.d/healthlog-push-relay /etc/apparmor.d/healthlog-push-signer
grep healthlog-push /sys/kernel/security/apparmor/profiles   # both "(enforce)"
```

then set `HLP_APPARMOR_RELAY=healthlog-push-relay` and `HLP_APPARMOR_SIGNER=healthlog-push-signer` in `.env`
and recreate the containers. `docker inspect -f '{{.AppArmorProfile}}' <container>` shows the profile in use.
With the Ansible role, `healthlog_push_apparmor_install: true` and the two profile names do the same: the role
installs the profiles of the release it deploys, loads them and checks after the start that each container
runs under its profile. A profile name the kernel has not loaded makes `docker compose up` fail; the role
checks this before it touches the running containers. To try a change first, load it with `apparmor_parser -C -r` (complain) and
look for `apparmor="ALLOWED"` lines in the audit log while you use the relay.

## Firewall

The relay uses host networking and listens on 8443 without any capability. Redirect 443 to 8443 for IPv4
and IPv6, accept 8443 only for redirected connections, and allow nothing else inbound except ICMP, ICMPv6
and your administrative access:

```
table inet hlp {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport 443 redirect to :8443
  }
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    tcp dport 8443 ct status dnat accept
    ip protocol icmp accept
    meta l4proto ipv6-icmp accept
    # SSH only from your management network or VPN of your choice
  }
}
```

Outbound, the relay needs tcp/443 (APNs, ACME, the image registry), DNS and NTP. Restrict the rest if you
can. The full rule set with egress filtering is `deploy/ansible/roles/firewall/templates/nftables.conf.j2`;
it limits outbound traffic by port, not by destination.
Keep administrative access on a private management network or VPN of your choice rather than on the public
interface.

With `acme` mode, port 443 must be reachable from the internet as soon as DNS points at the host; the first
TLS handshake for your name triggers the certificate request. If you publish a CAA record, allow your CA and
preferably bind it to your ACME account and to `tls-alpn-01`.

## Start and check

```sh
cd /srv/healthlog-push/compose
docker compose up -d
docker compose exec relay /healthlog-push healthcheck && echo healthy
curl -s https://push.example.org/healthz
curl -s https://push.example.org/version
```

`healthcheck` exits 0 only when `/healthz` reports `"status":"ok"`, which depends only on the relay's own
facts (a usable provider token, a writable store); `breaker` and `delivery` are shown but do not change it. Day-to-day operation, admin commands and
key rotation: [operations.md](operations.md).

## Building the app against your relay

Your app build needs to know where the relay is and which keys sign its answers:

- `HLPushRelayURL`: the base URL, for example `https://push.example.org`.
- `HLPushRelayKeys`: the relay's public identity keys, `current` and `next` (and optionally a separately held
  `emergency` key, see [key-ceremony.md](key-ceremony.md#lost-current-and-next)), as printed in the `publicKey`
  field of `keygen relay-id`.

Both are build settings of the HealthLog iOS app (Info.plist values set at build time); the app's build
documentation describes where to set them, together with your team, bundle id prefix, app group and keychain
groups. The bundle id you choose is your `HLP_APNS_TOPIC`.

Your HealthLog servers must also be allowed to use your relay and must pin the same public keys; see the
HealthLog server documentation for its relay settings. Every response of your relay is signed with the key in
`relay_id_key`, and a server treats a response with a missing or wrong signature as a transport error.

## Responsibilities

Running a relay for other people makes you responsible for what it processes. Publish your own privacy notice
and terms: the relay serves the texts compiled into the binary at `/privacy` and `/terms` (as HTML to a
browser, rendered from the same text), which describe the hosted relay of the HealthLog project, so build your
own binary with your texts in `internal/notice/` if you serve anyone but yourself. Keep them in the markdown
subset the HTML renderer accepts (headings, paragraphs, `-` and numbered lists, code, bold, https and mailto
links); the tests fail on anything else. The same applies to `/.well-known/security.txt` and the index page
(`internal/notice/notice.go`), which name the HealthLog project's contacts.
