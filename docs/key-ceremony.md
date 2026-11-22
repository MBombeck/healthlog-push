# Key ceremony

How the long-lived keys of the hosted relay are generated, kept, rotated and revoked. Self-hosters can
follow the same steps with their own secret store. Day-to-day rotation commands are in
[operations.md](operations.md#key-rotation); this document fixes who does what, where, and how often.

## The keys

| Key | Type | Used by | Lives at runtime | If it leaks |
|---|---|---|---|---|
| Relay identity key (`current`) | Ed25519 | relay, signs every response and the registry export | `secrets/relay/relay_id_key`, relay process memory | an attacker who also controls DNS or TLS can answer for the relay; switch to `next` |
| Relay identity key (`next`) | Ed25519 | nobody yet; its public half is pinned by servers and apps | secret store only | as above once it is promoted; generate a new `next` |
| Relay identity key (`emergency`) | Ed25519 | nobody; its public half is pinned by servers and apps | held separately from the relay host and from the operational keys; never deployed to the relay | as above once it is promoted; generate a new `emergency` |
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
docker run --rm --network none "$IMAGE" keygen relay-id      # identity: run three times, for current, next and emergency
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

- The relay secrets are kept in a secret store that only the key holder and the deployment can read. The
  relay host has no access to that store: it receives each secret as a file, written by the deployment.
- Each secret has a fixed name. Its fingerprint (SHA-256 of the public key, or of the value for MAC keys),
  never its value, goes into the operations log.
- The identity key `next` exists only in the secret store until it is promoted.
- The identity key `emergency` is held separately from the relay host and from the operational keys. It is
  never deployed to the relay unless it is promoted (below).

## Publication of the identity keys

The public identity keys are pinned in two places that are released separately from the relay:

1. the HealthLog server release (the pinned list for the hosted relay), and
2. the iOS app build (`HLPushRelayKeys`).

`current`, `next` and `emergency` are pinned in both, in the same way. A new `next` or `emergency` key is
published in both before it can be promoted. The public keys are also listed in
[hosted-relay.md](hosted-relay.md#identity-keys), so anyone can compare.

## Rotation

| Key | Regular | Procedure |
|---|---|---|
| Relay identity key | yearly, and at once after a suspected compromise of the relay process | promote `next` to `current`, generate a new `next`, ship its public key with the next server and app releases ([operations.md](operations.md#relay-identity-key)) |
| APNs key | yearly | create the new key, deploy it, verify one push, revoke the old one ([operations.md](operations.md#apns-key)) |
| Token MAC key | only when exposed | current becomes previous; the previous one is kept for the 365-day block retention ([operations.md](operations.md#token-mac-key)) |
| ACME account key | only when exposed | add the new account to CAA first ([operations.md](operations.md#acme-account-key)) |

Every rotation is recorded with date, key name and the fingerprints of the old and the new key, and is
announced in [transparency.md](transparency.md) (an identity key rotation at least 7 days ahead, except in an
emergency).

### Lost current and next

If the private halves of both `current` and `next` are lost or must be considered compromised, the relay
switches to `emergency`, which clients already pin, so no client release is needed to keep working:

1. Take the `emergency` seed from where it is held and deploy it as the relay identity key, exactly like
   a promoted `next` ([operations.md](operations.md#relay-identity-key)). The relay accepts any Ed25519 key
   as its identity; nothing in it requires the key to have been `next` before.
2. Write a new registry export at once (`admin export`), so the export on disk is signed by the key now in
   use. A restore verifies the export against the running identity key, and the key that signed the old one
   is gone.
3. Generate a new `next` and a new `emergency` with the generation command above. The new `next` goes into
   the secret store, the new `emergency` is held separately as described under Storage.
4. Publish both public keys (release notes, `keys/push.healthlog.dev.json`, the table in
   [hosted-relay.md](hosted-relay.md#identity-keys) and [transparency.md](transparency.md)), ship them in the next server and app releases, and drop the lost
   keys from the pins in the same releases. If the old keys may be compromised, set a notice as for a
   compromised identity key (below).

Until those releases are out, clients pin the promoted key as `emergency` and nothing else changes for
them. If `emergency` was lost as well, there is no pinned key left: a server and app release with new pins is
the only way back.

## Revocation

- **APNs key compromised:** revoke it in the Apple developer account first. The relay then fails closed
  (`InvalidProviderToken`, sending stops, `/healthz` reports `down`). Deploy a new key; the restart clears
  the stop. Revocation takes effect at Apple within minutes; it is the strongest control there is.
- **Identity key compromised:** promote `next` at once (or `emergency`, if `next` is affected too, see
  "Lost current and next"). Servers and apps reject the old key only once their
  pins are updated, so publish a server and app release that drops the old key, and set a notice
  (`admin notice set identity_key_rotated --level action_required`).
- **Token MAC key exposed:** rotate as above; it matters only together with a copy of the database.
- **ACME account key exposed:** remove the account from the CAA record; issuance through it then fails.

## Drill

Once a year, and before the first public launch, the full emergency path is rehearsed against a staging
relay: revoke a throwaway APNs key and watch the relay fail closed, promote a throwaway `next` identity key
and watch a pinned client accept it and reject the old key once unpinned, restore the relay from a signed
registry export. The drill is recorded like a rotation.
