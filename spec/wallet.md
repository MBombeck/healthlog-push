# Wallet passes, version 1

A HealthLog server can offer its users an Apple Wallet pass of their emergency card. A pass must be signed
with a Pass Type ID certificate of an Apple developer account, which a self-hosted server does not have. The
relay's third process, `wallet`, holds the certificate of the HealthLog project and signs for registered
servers, blind: it receives the pass manifest, a list of file names with their SHA-1 hashes, and never a
file. The content of the pass, its QR link and its serial number never leave the server. The wallet process
also sends the pass update pushes, which Apple accepts only with the same certificate.

This document is the protocol between a HealthLog server (the instance) and the relay. Request signing,
response signing, the error envelope, nonces and time windows are those of [protocol.md](protocol.md); this
document adds two endpoints, a block in `GET /v1/status`, limits and a ledger. The vectors are in
[vectors/wallet-v1.json](vectors/wallet-v1.json), the reference implementation in
[tools/wallet.mjs](tools/wallet.mjs), the closed file set in [wallet-manifest-v1.json](wallet-manifest-v1.json).

Wallet is off unless the operator configured a certificate (see docs/self-hosting.md, "Wallet passes").
While it is off both endpoints answer `503 wallet_unavailable` and the status block says `"sign": false`.

## What the relay sees and keeps

- The manifest: file names and SHA-1 hashes. `pass.json` is covered by its `authenticationToken` (256 bits
  of secret), and every `pass.strings` starts with a fresh random line, so a hash is no confirmation oracle
  for guessed content.
- Which instance asked, and when: the request is signed by the instance (`hl-relay-v1`).
- A pass push token while a pass push is processed, and its MAC in memory for the per-token limit.
- A ledger entry per signature: SHA-256 of the manifest bytes, the instance id and the UTC day, 400 days,
  readable only on the admin socket (`admin wallet lookup`). It is not in the registry export, the logs, the
  metrics or `/stats`.

The relay never sees `pass.json`, a `pass.strings`, an image, the QR link, the serial number or the
authentication token.

## Processes

```
relay (host network)  --dials-->   /run/wallet/wallet.sock   (served by wallet: sign, notify, info)
wallet (no network)   --dials-->   /run/wallet/apns.sock     (served by relay: byte tunnel)
relay                 --TCP-->     api.push.apple.com:443    (the only target of the tunnel)
```

- The pass key and certificate exist only in the wallet process. It has no network; the relay never reads
  either file.
- `wallet.sock`: one request per connection, a four-byte big-endian length and a JSON object, at most
  16 KiB; the answer is framed the same way, at most 32 KiB. Deadlines 5 s for `sign`, 10 s for `notify`;
  at most 8 connections at a time on each side. Operations: `{"op":"sign","manifest":"<base64>"}`,
  `{"op":"notify","tokens":["<base64>", ...]}` (1 to 50), `{"op":"info"}`. Every answer carries `info`
  (Pass Type ID, team, `O=` of the certificate, last day of validity, days left, usable); errors are
  `manifest_invalid` with a `reason`, `unavailable` and `bad_request`.
- `apns.sock`: each connection is joined to a new TCP connection to `api.push.apple.com:443` and bytes are
  copied both ways unread; at most two at a time. TLS runs inside it from the wallet process to Apple, with
  the pass certificate as client certificate and the server name `api.push.apple.com`, so the relay carries
  bytes it cannot read and cannot use the certificate.
- The wallet process checks the manifest itself, with its own compiled pins, before it touches the key. It
  does not trust the relay for that check; it does trust the relay for the instance check and the limits.

The relay asks `info` every minute. An answer older than three minutes, or a certificate with fewer than
seven days left, makes Wallet unavailable.

## Manifest

`manifest.json` of a pass is one JSON object of file path to the lowercase hex SHA-1 of that file. The relay
and the wallet process accept it only when all of these hold, checked in this order, and refuse it with the
first reason that applies:

1. At most 8192 bytes, valid UTF-8 and valid JSON (`shape`).
2. One object; every key once; every value a string of 40 characters `0-9a-f` (`shape`). At most 40
   entries (`too_many`).
3. Every path is in the closed set (`unknown_file`):
   - `pass.json`, any hash;
   - `<locale>.lproj/pass.strings` for a locale of `de en es fr it ko nl pl pt-BR pt_BR ru`, any hash;
   - the brand images `icon.png`, `icon@2x.png`, `icon@3x.png`, `logo@2x.png`, `logo@3x.png`,
     `primaryLogo@2x.png`, `primaryLogo@3x.png`, `artwork@2x.png`, `artwork@3x.png`.
   Nothing else: no image in a `.lproj` folder (it would replace a pinned image on a device in that
   language), no `logo.png`, `thumbnail`, `strip`, `background`, `footer`, `personalization.json`, no
   other folder, no `..`, no leading `/`, no case variant.
4. Every brand image carries one of the hashes pinned for its path (`foreign_asset`). The pins are compiled
   into the relay and listed in [wallet-manifest-v1.json](wallet-manifest-v1.json); a path may have more
   than one hash so that an image can change without a gap.
5. `pass.json` and `icon.png` are present (`missing_file`).

The pins are empty until the HealthLog artwork is final; until then the wallet process refuses to start.

What the pins cannot stop: a registered instance writes `pass.json` itself, so the texts, the organisation
name and the QR content of a pass it has signed are its own. The logo and the icon are always HealthLog's,
and Wallet itself refuses a pass whose `passTypeIdentifier` and `teamIdentifier` do not match the
certificate. The ledger, the limits and the per-instance Wallet block are the answers to misuse
(docs/threat-model.md, "Wallet signing").

## Signature

A detached CMS SignedData (RFC 5652) over the exact manifest bytes, DER:

```
ContentInfo {
  contentType  1.2.840.113549.1.7.2 (signedData)
  [0] SignedData {
    version 1
    digestAlgorithms  SET { sha256 with NULL parameters }
    encapContentInfo  { 1.2.840.113549.1.7.1 (data) }         no content: detached
    [0] certificates  pass certificate, then the intermediate (Apple WWDR G4)
    signerInfos SET { SignerInfo {
      version 1
      issuerAndSerialNumber of the pass certificate
      digestAlgorithm   sha256 with NULL
      [0] signedAttrs   DER SET, sorted: contentType = data,
                        signingTime = UTCTime (YYMMDDHHMMSSZ), messageDigest = SHA-256(manifest)
      signatureAlgorithm rsaEncryption with NULL
      signature          RSA PKCS#1 v1.5 over SHA-256 of signedAttrs encoded with the SET tag
    } }
  }
}
```

PKCS#1 v1.5 is deterministic: the same key, certificates, manifest and signing time give the same bytes in
every implementation. Vector `walletSign` holds two such signatures; the Go service and the JavaScript
reference produce them byte for byte, and `openssl smime -verify -binary -inform DER -in signature -content
manifest.json -purpose any -CAfile root.pem` accepts them. A HealthLog server that signs with its own Pass
Type ID must produce the same structure.

The intermediate is Apple's "Worldwide Developer Relations Certification Authority, G4", embedded in the
binary and pinned by SHA-256 `ea4757885538dd8cb59ff4556f676087d83c85e70902c122e42c0808b5bce14c`. The
wallet process starts only when the pass certificate was issued by it (key identifiers, issuer name and
signature), names the configured Pass Type ID in `UID` and the configured team in `OU`, belongs to the key,
and is valid for at least seven more days.

## POST /v1/wallet/apple/sign

Instance-signed (protocol.md, "Request signing"). Body at most 16 KiB:

```json
{ "v": 1, "manifest": "<unpadded base64url of the exact manifest.json bytes>" }
```

Answer `200`:

```json
{
  "signature": "<unpadded base64url of the DER SignedData>",
  "passTypeIdentifier": "pass.dev.healthlog.emergency",
  "teamIdentifier": "ABCDE12345",
  "signerSubjectO": "<O= of the pass certificate>",
  "certNotAfterDay": 20800
}
```

`certNotAfterDay` is the last day of validity in days since 1970-01-01 (UTC). The signature is not cached;
the same manifest signed twice gives two signatures with their own signing times.

| Status | `error` | When |
|---|---|---|
| 422 | `wallet_manifest_invalid` with `reason` | the body or the manifest is refused (Manifest above); `reason` is one of `shape`, `unknown_file`, `foreign_asset`, `missing_file`, `too_many` |
| 403 | `wallet_blocked` | the operator blocked Wallet for this instance; pushes to the app are not affected |
| 403 | `instance_suspended`, `instance_revoked` | as on every endpoint |
| 429 | `wallet_rate`, `wallet_quota` | the instance's signatures per minute or per UTC day, with `retryAfter` |
| 429 | `global` | the relay-wide signatures per minute |
| 503 | `wallet_unavailable` | Wallet is off, the wallet process does not answer, or its certificate has fewer than seven days left; `retryAfter` |
| 503 | `maintenance`, `storage_unavailable` | a pause of all classes; the ledger could not be written (no signature leaves without its entry) |

Replay: the nonce and the 300 s window of `hl-relay-v1`. A replayed request is refused before it reaches the
wallet process.

## POST /v1/wallet/apple/notify

Instance-signed. Body at most 16 KiB, 1 to 50 items with unique references:

```json
{ "items": [ { "ref": "<1 to 64 of A-Z a-z 0-9 _ ->", "token": "<hex, 64 to 512 characters, even length>" } ] }
```

The token is the pass push token Wallet registered with the instance's pass web service. The wallet process
sends `POST /3/device/<token>` to Apple's production endpoint with `apns-topic` = the Pass Type ID, the
body `{}`, and no push type, priority or expiration header.

Answer `200`, one result per item in the request's order:

```json
{ "results": [ { "ref": "a1", "result": "accepted" } ] }
```

| `result` | Meaning |
|---|---|
| `accepted` | Apple accepted the push |
| `unregistered` | Apple answered 410, `BadDeviceToken` or `DeviceTokenNotForTopic`: drop the registration |
| `rejected` | any other refusal by Apple |
| `token_quota` | this token had its 12 pushes this hour or 48 today |
| `unavailable` | Apple or the wallet process did not answer, or the same reference is still in flight: try later |

A reference repeated within ten minutes gets the first result without a second push, except `unavailable`,
which is sent again. Refusals of the whole request are those of the sign endpoint, with `invalid_item` (422)
for a malformed body and `wallet_rate` / `wallet_quota` for the instance's pass pushes per minute and day.

## Status

`GET /v1/status` (protocol.md, "Status") carries a block `wallet`:

```json
"wallet": { "sign": true, "notify": true, "passTypeIdentifier": "pass.dev.healthlog.emergency",
            "teamIdentifier": "ABCDE12345", "certNotAfterDay": 20800 }
```

`sign` and `notify` are false, and the other fields absent, while Wallet is off, the wallet process has not
answered for three minutes, its certificate has fewer than seven days left, or the instance is blocked for
Wallet. An instance shows the Wallet option only while `sign` is true.

## Limits

| Limit | probation | standard | Refusal |
|---|---|---|---|
| signatures per instance and minute | 10 | 30 | `429 wallet_rate` |
| signatures per instance and UTC day | 200 | 2000 | `429 wallet_quota` |
| signatures relay-wide per minute | 600 | | `429 global` |
| pass pushes per instance and minute | 60 | 60 | `429 wallet_rate` |
| pass pushes per instance and UTC day | 300 | 3000 | `429 wallet_quota` |
| pass pushes per token and hour, and per day | 12, 48 | 12, 48 | result `token_quota` |

The windows are kept in memory and start again after a restart.

## Ledger and operator commands

Bucket `walletsign` of the store: key SHA-256(manifest bytes) followed by the instance id, value the UTC
day. Retention 400 days. Commands on the admin socket:

- `admin wallet lookup <sha256>`: which instance had this manifest signed, and on which day. For a pass
  reported as misuse: unzip it and run `shasum -a 256 manifest.json`.
- `admin wallet block <id>` and `admin wallet unblock <id>`: stop or allow Wallet for one instance. The
  block is kept with the instance and travels in the registry export.
- `admin wallet status`: the identity the wallet process reported and when.

## Test vectors

[vectors/wallet-v1.json](vectors/wallet-v1.json), generated by `node spec/tools/gen-wallet-vectors.mjs
--write` and checked by `node spec/tools/check-vectors.mjs`:

- `seeds` and `moduli`: three RSA-2048 keys (root, intermediate, pass) derived from public seeds by
  `deriveRSAKey` in [tools/wallet.mjs](tools/wallet.mjs). The file holds no key: candidates are 1024-bit
  numbers from SHA-256(seed, label, counter) with the top two bits and the low bit set, the next probable
  prime with gcd(p - 1, 65537) = 1 is taken for each of the labels `p` and `q`, and e = 65537.
- `certificates`: the test chain, DER, base64url; the pass certificate names `passTypeIdentifier` in `UID`
  and `teamIdentifier` in `OU`, as Apple's do.
- `pins` and `manifests`: a pin set and 22 manifests with the answer the relay gives (`ok` or a reason).
- `walletSign`: manifest, signing time, signed attributes (hex) and the SignedData (base64url). Go and the
  reference must produce exactly these bytes.
