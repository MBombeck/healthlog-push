# Key ceremony

How the long-lived keys of the hosted relay are generated, kept, rotated and revoked. Self-hosters can
follow the same steps with their own secret store. Day-to-day rotation commands are in
[operations.md](operations.md#key-rotation); this document fixes who does what, where, and how often.

## The keys

| Key | Type | Used by | Lives at runtime | If it leaks |
|---|---|---|---|---|
| Relay identity key (`current`) | Ed25519 | relay, signs every response and the registry export | `secrets/relay/relay_id_key`, relay process memory | an attacker who also controls DNS or TLS can answer for the relay; switch to `next` |
| Relay identity key (`next`) | Ed25519 | nobody yet; its public half is pinned by servers and apps | secret store only | as above once it is promoted; generate a new `next` |
| APNs key (`.p8`) | ECDSA P-256 | signer only | `secrets/signer/apns.p8`, signer process memory | anyone can send notifications to tokens they know under the app's name; revoke in the Apple developer account |
| Token MAC keys (current, previous) | 32 random bytes | relay | `secrets/relay/token_mac_key[_previous]` | together with a copy of the database, tokens someone already knows can be matched to bindings |
| ACME account key | ECDSA P-256 | relay (autocert) | `secrets/relay/acme_account_key` | certificates for the relay name can be requested through this account; the CAA record pins the account |

No key is ever written to a backup, a log, a container image or the repository. The registry export is
signed with the identity key but does not contain it.

## Roles

- **Key holder:** the maintainer. Generates, stores, rotates and revokes every key. Holds the Apple developer
  account.
- **Host:** receives keys only as files written by the deployment role, readable only by the container user
  that needs them (mode 0400).
- There is no second key holder. While the maintainer is unavailable, nobody can rotate or revoke a key;
  the absence checklist in [operations.md](operations.md#absence-checklist) limits what can go wrong in
  that time. A delegate may pause the relay or switch registration off, which needs no key.

## Generation

All relay keys are generated with the released image itself, on the key holder's workstation, with the
network switched off for the container, and written straight into the secret store:

```sh
IMAGE=ghcr.io/mbombeck/healthlog-push@sha256:<digest of the release you run>
cosign verify "$IMAGE" --certificate-identity-regexp '^https://github.com/MBombeck/healthlog-push/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null
docker run --rm --network none "$IMAGE" keygen relay-id      # identity: run twice, for current and next
docker run --rm --network none "$IMAGE" keygen token-mac
docker run --rm --network none "$IMAGE" keygen acme-account
```

- `keygen relay-id` prints a JSON line with the private seed (`relay_id_key`) and the public key
  (`publicKey`). Only the seed goes into the secret store; the public key is published (below).
- The APNs key is created in the Apple developer account, restricted to the app's bundle id and
  "Sandbox & Production" (or production only for the hosted relay), downloaded once, and moved into the
  secret store at once. The downloaded file is deleted from the workstation.
- The terminal output is not kept: no copy in shell history (run with a leading space or `HISTCONTROL`),
  scrollback or clipboard managers.

## Storage

- One project in the secret store holds the relay secrets. Only the key holder and the deployment have
  access; the deployment's access is read-only and limited to that project.
- Each secret has a fixed name and a note with its creation date, its fingerprint (SHA-256 of the public
  key, or of the value for MAC keys) and its planned rotation date. Fingerprints, not values, go into the
  operations log.
- The identity key `next` exists only in the secret store until it is promoted.

## Publication of the identity keys

The public identity keys are pinned in two places that are released separately from the relay:

1. the HealthLog server release (the pinned list for the hosted relay), and
2. the iOS app build (`HLPushRelayKeys`).

A new `next` key is published in both before it can be promoted. The public keys are also listed in
`README.md` of this repository, so anyone can compare.

## Rotation

| Key | Regular | Procedure |
|---|---|---|
| Relay identity key | yearly, and at once after a suspected compromise of the relay process | promote `next` to `current`, generate a new `next`, ship its public key with the next server and app releases ([operations.md](operations.md#relay-identity-key)) |
| APNs key | yearly | create the new key, deploy it, verify one push, revoke the old one ([operations.md](operations.md#apns-key)) |
| Token MAC key | only when exposed | current becomes previous; the previous one is kept for the 365-day block retention ([operations.md](operations.md#token-mac-key)) |
| ACME account key | only when exposed | add the new account to CAA first ([operations.md](operations.md#acme-account-key)) |

Every rotation is recorded with date, key name and the fingerprints of the old and the new key.

## Revocation

- **APNs key compromised:** revoke it in the Apple developer account first. The relay then fails closed
  (`InvalidProviderToken`, sending stops, `/healthz` reports `down`). Deploy a new key; the restart clears
  the stop. Revocation takes effect at Apple within minutes; it is the strongest control there is.
- **Identity key compromised:** promote `next` at once. Servers and apps reject the old key only once their
  pins are updated, so publish a server and app release that drops the old key, and set a notice
  (`admin notice set identity_key_rotated --level action_required`).
- **Token MAC key exposed:** rotate as above; it matters only together with a copy of the database.
- **ACME account key exposed:** remove the account from the CAA record; issuance through it then fails.

## Drill

Once a year, and before the first public launch, the full emergency path is rehearsed against a staging
relay: revoke a throwaway APNs key and watch the relay fail closed, promote a throwaway `next` identity key
and watch a pinned client accept it and reject the old key once unpinned, restore the relay from a signed
registry export. The drill is recorded like a rotation.
