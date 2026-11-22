# Operations

How to run the relay day to day: deploy and roll back, use the operator commands, rotate keys, react to
alerts, handle abuse, prepare an absence, handle an incident, restore. Host provisioning is in
[deploy/ansible/README.md](../deploy/ansible/README.md); moving to a new host is in
[migration.md](migration.md).

Commands below run on the relay host in the compose directory. The compose file sets the project name
`healthlog-push`, so no `-p` is needed there:

```sh
cd /srv/healthlog-push/compose
```

## Deploy

A deploy changes exactly one thing: the image digest. The Ansible role does every step below and refuses a
tag without a digest; use it ([deploy/ansible/README.md](../deploy/ansible/README.md#deploying-a-release)).
By hand, the order is the same:

1. **Pin.** Take the digest from the GitHub release notes, never a tag alone:
   `IMAGE=ghcr.io/mbombeck/healthlog-push@sha256:<digest>`, `TAG=vX.Y.Z`.
2. **Verify** the signature and the provenance. Stop on any failure.

   ```sh
   cosign verify "$IMAGE" \
     --certificate-identity "https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/$TAG" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   cosign verify-attestation "$IMAGE" --type slsaprovenance1 \
     --certificate-identity "https://github.com/MBombeck/healthlog-push/.github/workflows/provenance.yml@refs/tags/$TAG" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-github-workflow-repository MBombeck/healthlog-push > /dev/null
   ```

3. **Note the running image** for the rollback: `cat /srv/healthlog-push/deployed-digest`.
4. **Switch.** Set `HLP_IMAGE` to `$IMAGE` and `HLP_IMAGE_DIGEST` to its `sha256:<digest>` part in `.env`,
   then `docker compose pull --quiet && docker compose up -d`. The processes read secrets only at start: if
   a secret file changed, also change `HLP_SECRETS_REV` in `.env` (any new value; the Ansible role writes a
   fingerprint of the secrets there) so that compose recreates both containers, or add `--force-recreate`.
5. **Health gate.** `healthcheck` exits 0 only when the relay's local `/healthz` says `"status":"ok"`.

   ```sh
   for i in $(seq 30); do
     docker compose exec -T relay /healthlog-push healthcheck && break
     sleep 5
   done
   docker compose ps signer      # must show "healthy": a provider token younger than 60 minutes
   ```

6. **Record.** `echo "$IMAGE" > /srv/healthlog-push/deployed-digest`, and check from outside:
   `curl -s https://push.example.org/version` shows the new `imageDigest`.

If the gate fails, look at `/healthz` before rolling back. `status` depends only on the relay's own facts:
`down` when the relay has no fresh provider token from the signer or Apple rejected a renewed one,
`degraded` when the store is not writable. `breaker` and `delivery` are shown but never change `status`, the
HTTP code, the container health check or the gate, because instances can influence both; a third party
therefore cannot hold up a deploy through them.

## Rollback

The role rolls back by itself when the gate fails. By hand: put the previous image from `deployed-digest`
back into `HLP_IMAGE` and `HLP_IMAGE_DIGEST`, `docker compose up -d`, and run the health gate again. A
rollback does not touch `/data`, `/export` or `/acme`.

## Health

`GET /healthz` (public and signed, and on the local metrics listener) has five fields and no time stamps:

| Field | Values | Meaning |
|---|---|---|
| `status` | `ok`, `degraded`, `down` | `down`: no provider token younger than 55 minutes, or the APNs key was rejected after a renewal. `degraded`: store not writable. HTTP 503 unless `ok`. Only these own facts count; the container health check and the deploy gate use this field. |
| `db_writable` | `true`, `false` | `false` after a failed write; `true` again after the next successful write (the flush runs every minute). |
| `apns_recent` | `true`, `false` | Apple accepted a push in the last 15 minutes. Expected to be `false` on a quiet relay; not part of `status`. |
| `breaker` | `closed`, `open`, `half_open` | the token-failure breaker; display only, not part of `status` |
| `delivery` | `ok`, `degraded`, `unknown` | from `POST /v1/receipts` of `standard` instances, each reported `accepted` capped at what the relay accepted for that instance in the last three days: `degraded` when fewer than 80 % of at least 20 accepted pushes in the last 24 hours were confirmed by devices, counted over at least three reports; `unknown` below either threshold. Display only, not part of `status` |

## Operator commands

Every command goes over the admin unix socket (`admin.sock` in `HLP_DATA_DIR`, so `/data/admin.sock` in the
container; mode 0600; `HLP_ADMIN_SOCKET` overrides it for the server and the client alike) and takes effect at once,
without a restart. The answer is JSON; a refused command prints `{"error": "..."}` and exits with status 1.
Use `exec -T` in scripts. Commands that change state write a log line when they run (`admin.pause`,
`admin.suspend`, `admin.block_token` and so on) without any id.

### stats

Service state and usage aggregates. Counts only; see [Usage statistics](#usage-statistics).

```sh
docker compose exec relay /healthlog-push admin stats
```

```json
{
  "service": {
    "instances": { "probation": 3, "standard": 41, "suspended": 1 },
    "bindings": { "active": 96, "provisional": 2, "soft_invalid": 1 },
    "queue": 0,
    "breaker": "closed",
    "dbWritable": true,
    "registration": "invite",
    "pauses": null,
    "notice": null,
    "globalLimitPerMinute": 600,
    "apnsMisconfigured": false
  },
  "usage": { "...": "see Usage statistics" }
}
```

`recoveryUntil` appears while a recovery window is open.

### instance

Tier, limit and binding counts of one instance. Instance ids reach you from the instance's operator (for
example in an abuse report or a limit request) or from [suspects](#suspects); they appear only on the admin
socket, never in logs, metrics or `stats`.

```sh
docker compose exec relay /healthlog-push admin instance 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
```

```json
{
  "id": "6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c",
  "tier": "standard",
  "created": "2026-11-02",
  "deviceLimit": 50,
  "active": 4,
  "provisional": 0,
  "delivered": true
}
```

### suspects

Instances with any invalid token, rebind or conflict challenge in the last 7 days, worst first: sorted by
invalid tokens today, then over 7 days, then rebinds; at most 50 rows. This is how an instance that floods
the relay with invented tokens is found. The ids appear only in this answer on the admin socket.

```sh
docker compose exec relay /healthlog-push admin suspects
```

```json
[
  {
    "id": "6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c",
    "tier": "probation",
    "created": "2026-11-20",
    "invalidToday": 21,
    "invalid7d": 21,
    "sent7d": 30,
    "rebinds7d": 0,
    "challengesToday": 0,
    "blockedNewBindingsUntil": "2026-11-22T09:14:03Z",
    "active": 0,
    "provisional": 0,
    "softInvalid": 9
  }
]
```

`invalidToday` and `challengesToday` count the current UTC day, the `7d` fields today and the six days
before. `blockedNewBindingsUntil` is present while the instance is over its invalid-token budget: no new
bindings, and pushes only to active bindings. `active`, `provisional` and `softInvalid` are its current
bindings. When no instance qualifies the answer is an empty list `[]`.

### pause and resume

Stops a class (`all`, `alert`, `silent`, `liveactivity`) for a tier (`all`, `probation`) for a duration
between 1 second and 7 days; default `all`, `all`, `30m`. A pause of class `all` refuses whole push
requests with `503 maintenance`; a class pause refuses the matching items. Pauses expire by themselves.
`/v1/status` shows `"state":"maintenance"` while an `all`/`all` pause is active.

```sh
docker compose exec relay /healthlog-push admin pause --tier probation --for 2h
docker compose exec relay /healthlog-push admin pause --class silent --for 30m
docker compose exec relay /healthlog-push admin resume          # removes every pause
```

### registration and invite

`open`, `invite` or `closed`. A new store starts in `HLP_REGISTRATION_MODE` (default `invite`), which the
relay stores before it accepts the first request; from then on the stored mode counts, and only this
command changes it, so a restart never reopens registration. To let anyone register, set
`admin registration open` on purpose. `closed` answers new registrations with `503 registration_paused`;
`invite` requires a one-time code in the registration body's `invite` field, otherwise `403
invite_required`. A key that is already registered gets its existing id back in every mode.

```sh
docker compose exec relay /healthlog-push admin registration invite
docker compose exec relay /healthlog-push admin invite
```

```json
{ "invite": "<24 base64url characters>", "validDays": "7" }
```

The code is shown once and stored only as a hash. It is valid for 7 days and for one registration. It is
spent only when the registration passes every limit; a registration refused by a limit keeps the code.

### notice

Sets the notice that every instance receives in `/v1/status`, in every `/v1/push` response and in the
status file. A notice is an identifier (`[a-z0-9_]{1,40}`) and a level (`info`, `planned`,
`action_required`); the text belongs to the HealthLog server, which maps known identifiers to its own
messages. `--for` makes it expire.

```sh
docker compose exec relay /healthlog-push admin notice set planned_maintenance --level planned --for 72h
docker compose exec relay /healthlog-push admin notice clear
```

### suspend, unsuspend and revoke

`suspend <id> <reason>` keeps the bindings and refuses every request of the instance with `403
instance_suspended` and the reason. Reasons are a closed set: `abuse`, `spam`, `invalid_tokens`,
`harassment`, `legal`, `compromised`, `terms`, `operator_request`. The tier, the reason and the day are
stored in the instance record and travel in the export; the record is kept for 365 days after that day.
A revoked instance cannot be suspended (the command is refused), so a revocation cannot be undone by a
suspend and an unsuspend.

`unsuspend <id>` returns a suspended instance to `probation` (not to its previous tier) and clears the
reason.

`revoke <id> [reason]` deletes every binding of the instance and keeps its record as `revoked`, in one
transaction, so the key cannot register again; the reason defaults to `abuse`. The record expires 365 days
after the revocation. There is no command to undo a revocation; the operator registers a new key.

```sh
docker compose exec relay /healthlog-push admin suspend 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c spam
docker compose exec relay /healthlog-push admin unsuspend 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c
docker compose exec relay /healthlog-push admin revoke 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c harassment
```

### block-token and unblock-token

Blocks a device token for every instance except the one it is bound to now. Give the raw token in hex, or
its HMAC under the current MAC key as 64 hex characters. Blocks are kept for 365 days.

```sh
docker compose exec relay /healthlog-push admin block-token --token <hex token>
docker compose exec relay /healthlog-push admin unblock-token --token <hex token>
```

### limits

Sets the active device limit of an instance, from 1 to 150. A probation instance stays capped at its tier
limit of 20 until it is promoted.

```sh
docker compose exec relay /healthlog-push admin limits 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c devices=80
```

### recovery

Opens the recovery window until a day (UTC), optionally importing an export first. During the window the
global registration caps are ten times higher (300 per hour, 2000 per day with the defaults), never
unlimited, and the per-address caps still apply. Instances whose key is in the imported export get their
old id and tier back; any other key registers in `probation`, as outside the window. The export given with
`--from` is verified like the one read at start: signed by this relay's identity key, for this host, every
instance inside the closed sets. Otherwise nothing is imported and the command fails. `--from` must name a
file inside the export directory (`HLP_EXPORT_DIR`, `/export` in the container), as a name relative to it
or an absolute path under it; a path that leaves it, also through a symbolic link, is refused. Copy an
export from elsewhere into that directory first.

```sh
docker compose exec relay /healthlog-push admin recovery --until 2026-12-05 --from /export/registry.json
```

```json
{ "imported": 44 }
```

The relay opens a 14-day window by itself when it starts from an empty or damaged database and finds an
export ([Restore](#restore)).

### export

Writes `/export/registry.json` now, in format `healthlog-push-registry-v2`: `host`, `day`, the instances
(suspended and revoked ones with their tier, reason and reason day), the device opt-out blocks
(`blockedPairs`, reason `device_opt_out`), the operator token blocks (`blockedTokens`, reason
`operator_block`) and the opt-out key pins (`optOutPins`, reason `device_opt_out_pin`), each as keyed hash,
reason and expiry day. Entries past the 365-day retention are left out; no bindings, no counters, no
secrets, no binding key hashes. The file carries a `signature` by the relay identity key over
`hl-relay-export-v1` ([spec/statements.md](../spec/statements.md#hl-relay-export-v1)); an unsigned export is
never written. The relay also writes it at start and at every UTC day change.

```sh
docker compose exec relay /healthlog-push admin export
```

### breaker

`open` forces the token-failure breaker open (no deletions, no marks, pushes refused with `503
relay_misconfigured`), `close` closes it and clears its window, `reset-apns` clears the "APNs key rejected"
stop and the 20-minute pause after `TooManyProviderTokenUpdates`. Use `close` and `reset-apns` only after the
cause is fixed. `reset-apns` also sets the gauge `hlp_apns_misconfigured` back to 0.

```sh
docker compose exec relay /healthlog-push admin breaker open
docker compose exec relay /healthlog-push admin breaker close
docker compose exec relay /healthlog-push admin breaker reset-apns
```

### status-file

Prints the signed status document for publishing at a location that does not depend on the relay host, so
that instances can learn about an outage while the relay itself is unreachable. The signature is Ed25519 by
the relay identity key over `hl-relay-status-v1`, the host and the SHA-256 of `body`.

```sh
docker compose exec relay /healthlog-push admin status-file > status.json
```

```json
{
  "body": { "host": "push.example.org", "issued": 1795000000, "notice": null, "state": "ok" },
  "signature": "<base64url Ed25519 signature>"
}
```

### delivery

Shows Apple's `apns-unique-id` and the item result of one push, by instance id and the item's `ref`, so a
single lost push can be looked up in the delivery log of Apple's Push Notifications Console. The instance's
operator supplies both values (the HealthLog server keeps the `ref` of every push in its delivery ledger).

```sh
docker compose exec relay /healthlog-push admin delivery 6f1c2a4e-8b3d-4c5e-9a7f-0d1e2f3a4b5c dose-1795000000-3
```

```json
{ "apnsUniqueId": "3f0c1d2e-4b5a-4c6d-8e7f-90a1b2c3d4e5", "result": "accepted" }
```

Retention: Apple sends `apns-unique-id` only in the development (sandbox) environment, so only pushes to
development builds have a trace; production pushes leave none. A trace lives in the relay's memory for 72
hours, at most 50,000 of them (the oldest go first), and is gone sooner when the relay restarts or the
instance is deleted. It is never written to the database, the export, a log line or a metric. A retry of
the same `ref` replaces the trace. When nothing is found the command answers `{"error": "no trace: ..."}`.

## Key rotation

Generate keys with the same image you run: `docker run --rm "$IMAGE" keygen relay-id|token-mac|acme-account`.
Every secret file is owned by the container user that reads it (relay 65532, signer 65533) with mode 0400.
Keep every value in your secret store first, then write the file. With the Ansible role, change the
variable and rerun the role. The role writes a fingerprint of all secrets as `HLP_SECRETS_REV` into `.env`
and the compose environment, so compose recreates the containers whenever the secrets differ from those the
running containers started with, also when an earlier run wrote the files and then failed.

### APNs key

1. Create a new APNs key in the Apple developer account and note its key id.
2. Write it to `secrets/signer/apns.p8` and set `HLP_APNS_KEY_ID` (and `HLP_APNS_TEAM_ID` if it changed) in
   `.env`.
3. Restart both containers together, so that the shared tmpfs is emptied and the signer signs with the new
   key at once (otherwise it keeps a still-valid token from the old key for up to 30 minutes):
   `docker compose down && docker compose up -d`.
4. Run the health gate, send one push to a test device, and check that `hlp_push_total{result="accepted"}`
   rises and `relay_misconfigured` does not appear.
5. Revoke the old key in the Apple developer account.

If the old key is compromised, revoke it first. Sends then fail with `InvalidProviderToken`; after the next
renewal the relay stops sending (`/healthz` `down`). Deploy the new key as above; the restart clears the
stop.

### Relay identity key

The relay loads one identity key. HealthLog servers and the app pin three public keys, `current`, `next` and
`emergency`, so the relay can switch to `next`, or to `emergency` if both others are lost, without a client
release. The relay does not care which pinned key it runs with; promoting one is a change of the
`relay_id_key` file only.

1. Make sure the `next` public key is already pinned in the released server and app builds you serve.
2. Write the private seed of `next` to `secrets/relay/relay_id_key` (only the `relay_id_key` value of the
   `keygen relay-id` output, or a PKCS#8 PEM Ed25519 key).
3. `docker compose up -d --force-recreate relay`, then check that a pinned client accepts a signed
   `GET /v1/status`.
4. Generate a new `next` with `keygen relay-id`, keep the seed in the secret store, and ship its public key
   as the new `next` in the following server and app releases. Drop the old `current` from the pins once no
   supported client needs it.

After a suspected compromise of the relay process, do this at once.

If both `current` and `next` are lost, promote `emergency` the same way (its seed comes from its offline
storage), run `admin export` right after the restart so the export is signed by the new
key, and generate a new `next` and a new `emergency`: [key-ceremony.md](key-ceremony.md#lost-current-and-next).
The same `admin export` after any promotion keeps a restore possible on the same day.

### Token MAC key

Bindings are stored under an HMAC of the device token. The relay reads `token_mac_key` (current) and, if
present, `token_mac_key_previous`; a binding found under the previous key moves to the current key the next
time it is used.

1. `keygen token-mac` for the new value.
2. Move the current value to `secrets/relay/token_mac_key_previous`, write the new one to `token_mac_key`.
3. `docker compose up -d --force-recreate relay`.
4. Keep the previous key for 365 days, the block retention. Bindings move to the new key when they are
   used, and bindings without a push for about 13 weeks are deleted by retention, but opt-out blocks,
   opt-out pins and token blocks stay under the old key for their full 365 days.
5. Remove `token_mac_key_previous` and recreate the relay.

Opt-out blocks, opt-out pins and token blocks are stored as hashes over the token MAC and are not
rewritten. While the old key is configured as `token_mac_key_previous` the relay checks them under both
keys. Once it is removed, those recorded under it no longer match: re-apply the token blocks you still need
with `admin block-token --token`; opt-out blocks and pins cannot be re-created, because the relay never knew
the tokens. There is one slot for a previous key, so rotate this key at most once a year, or when it is
exposed.

### ACME account key

The ACME account key decides which account obtains the certificate. If your CAA record names the account
(`accounturi=`), the new account must be allowed there before it is used.

1. `keygen acme-account`. Register the key with the certificate authority using an ACME client of your
   choice to learn its account URI, and add that URI to the CAA record next to the old one.
2. Write the key to `secrets/relay/acme_account_key` and `docker compose up -d --force-recreate relay`.
   The cached certificate stays in use; the next renewal uses the new account. To test now, move the
   contents of `/srv/healthlog-push/acme` aside before the restart (mind the CA's rate limits).
3. After a certificate was issued through the new account, remove the old account URI from the CAA record.

## Alerts worth acting on

While fewer than 20 instances are active, the metrics snapshot refreshes once an hour. Alert on the live
`/healthz` from outside the host for anything that needs a quick reaction; `status` covers only the relay's
own facts, so also alert on the `breaker` field of the body when it is not `closed`. Use metrics for trends.
Metrics are served on `127.0.0.1:9464/metrics` and carry no instance, device or address labels.

| Signal | Means | Act |
|---|---|---|
| `/healthz` `status` `down` for more than a few minutes | no fresh provider token, or Apple rejected the key | check `docker compose ps signer` and the `signer.*` log lines; check key id, team id, topic and whether the key was revoked |
| `hlp_apns_misconfigured == 1`, log `apns.provider_token_rejected` | a renewed provider token was rejected; the relay stopped sending | fix the key or the ids, then restart or `admin breaker reset-apns` |
| `hlp_breaker_open == 1`, log `breaker.opened` | more than 30 % of at least 20 sends to established bindings (bindings that had a push accepted) failed with token errors, from at least three instances | look for a wrong topic, environment or key, or a bad image; roll back if a deploy preceded it; do not close by hand before the cause is fixed |
| `hlp_db_writable == 0`, log `store.write_failed` or `store.check_failed` | the store cannot be written; pushes continue, bindings and registrations are refused | check disk space and the file; the flag clears on the next successful write; see [Restore](#restore) |
| log `store.damaged_moved_aside`, `store.imported_export` | the relay started from a damaged database and restored the registry | expected after damage; watch registrations during the recovery window |
| rising `hlp_push_total{result="apns_unavailable"}` or `{result="relay_misconfigured"}` | Apple unreachable, Apple throttling provider tokens, or the breaker | check the host's egress to Apple on 443 and the items above |
| rising `hlp_push_total{result="apns_rejected"}` | Apple answers 4xx other than token errors: a request defect | check recent deploys; the reasons appear in the `errors` map of the `relay.summary` log line |
| `increase(hlp_silent_paused_total) > 0`, log `apns.throttled` | Apple throttled more than 2 % of sends; silent pushes are off for 15 minutes | check for an instance flooding silent pushes; consider `admin pause --class silent` |
| `increase(hlp_invalid_budget_exceeded_total) > 0` | an instance exceeded its invalid-token budget: for 24 hours no new bindings and no pushes to non-active bindings | abuse runbook, step 1 (`admin suspects`) |
| rising `hlp_registrations_total{result="limited"}` | registrations hit the per-address or global caps | abuse runbook; consider `admin registration invite` |
| rising `hlp_auth_failures_total{reason="bad_signature"}` | requests with wrong signatures (counted at most at the rate of the per-instance `badSignatureBurst` bucket; nobody is refused because of it) | usually a misconfigured instance; sustained growth may be probing |
| rising `hlp_body_budget_refused_total` | the 32 MiB budget for request bodies in flight was full; requests got `503 overloaded` | a body flood; check `hlp_connections_rejected_total` and the cloud firewall |
| rising `hlp_queue_dropped_total` or `hlp_push_total{result="queue_full"}` | the send queue refuses work | capacity or a slow Apple connection |
| rising `hlp_connections_rejected_total` | connection caps reached | connection flood; the cloud firewall is the next lever |
| jump in `hlp_http_errors_total` | the HTTP server discarded error lines (often TLS scans) | informational |
| high share of `hlp_apns_rejections_total` against `hlp_apns_sends_total` | Apple refuses requests; `reason` says why (`BadTopic`, `BadDeviceToken`, `other`, ...) | check the topic, environment and recent deploys; token reasons alone are usually stale devices |
| rising `hlp_delivery_latency_seconds` above the 1 s bucket, or `hlp_queue_depth` staying above zero | sends to Apple are slow and the queue builds up | Apple's status, the host's egress, `hlp_queue_dropped_total` |
| rising `hlp_silent_budget_refused_total{kind="sync"}` | instances send more background pushes than the device budgets allow | an instance flooding silent pushes; the budgets work as intended |
| rising `hlp_rate_limited_total{surface}` or `hlp_registrations_rejected_total{reason}` | a limit refuses requests; the surface or reason says which | abuse runbook; `bad_signature` and `no_invite` are usually misconfigured servers |
| log `export.failed` | the daily export was not written | check `/export` permissions and space; the export is your only backup |
| certificate valid for less than 14 days (external check) | renewal over TLS-ALPN-01 failed | check DNS, port 443 reachability and the CAA record |

Other metrics: `hlp_requests_total{status="2xx"|"4xx"|"5xx"}`, `hlp_bindings_total{result}` (`bound`,
`conflict`, `challenge_resolved`, `opt_out_lifted`, `unbound_instance`, `unbound_self`,
`liveactivity_consent` for a stored Live Activity consent, `liveactivity_consent_withdrawn` for one removed by
the device or the instance), `hlp_challenges_total{result}`, the operational counters
`hlp_apns_sends_total{kind}`, `hlp_liveactivity_priority_total{priority}`, `hlp_push_retries_total{answer}`
and `hlp_deliveries_by_key_slot_total{slot}` (after a key switch the accepted deliveries move to the new slot),
and the usage gauges below. [transparency.md](transparency.md#metrics-the-operator-sees) lists every metric
with its labels. Log lines are JSON with the keys `ts` (to the second), `action` and a closed set of
value keys; the summary line `relay.summary` carries `pushes`, `errors` by reason, `events` (counts of
`registered`, `rotated`, `deleted` and `challenge_resolved` in the period) and `p95_ms`. Registrations, key
rotations, instance deletions and resolved challenges have no log line of their own. The summary is written
every minute with at least 20 active instances and every hour below that.

## Usage statistics

The relay keeps usage figures as counts only. There is no per-device statistic; the only per-instance view
is [suspects](#suspects) on the admin socket, for abuse handling.

`admin stats` includes the `usage` block for the last 28 days:

```json
"usage": {
  "granularity": "day",
  "activeInstances": 44,
  "instancesPushedLast7Days": 40,
  "instancesPushedLast30Days": 43,
  "activeBindings": 97,
  "registrationsPerWeek": [ { "weekOf": "2026-10-26", "n": 3 }, { "weekOf": "2026-11-02", "n": 1 } ],
  "optOutsPerWeek": [ { "weekOf": "2026-10-26", "n": 0 }, { "weekOf": "2026-11-02", "n": 1 } ],
  "pushesPerDay": [
    { "day": "2026-11-20", "total": 812, "byClass": { "alert": 301, "liveactivity": 12, "silent": 499 },
      "accepted": 805, "softFailed": 5, "unregistered": 2 }
  ]
}
```

- `activeInstances` (probation and standard), `instancesPushedLast7Days` and `instancesPushedLast30Days`
  (instances with an accepted push in that window) and `activeBindings` (active and soft-invalid) are current
  counts at the time of the report.
- `pushesPerDay` lists completed UTC days only, from 28 days ago to yesterday; the current day never
  appears. `total` counts pushes that reached a final answer from Apple: `accepted`, `softFailed`
  (`BadDeviceToken`, `DeviceTokenNotForTopic`, or a Live Activity that was already gone) and
  `unregistered`. Refusals by the relay and transient failures are not in it.
- `registrationsPerWeek` and `optOutsPerWeek` list completed weeks only (Monday to Sunday, UTC), keyed by
  the Monday. Opt-outs are direct opt-outs by devices (`DELETE /v1/bindings/self`).

The same figures as metrics, recomputed at every scrape and exposed through the snapshot, which refreshes
every minute with at least 20 active instances and every hour below that:

| Metric | Labels | Value |
|---|---|---|
| `hlp_usage_active_instances` | | probation and standard instances |
| `hlp_usage_instances_pushed` | `window="7d"`, `window="30d"` | instances with an accepted push in the window |
| `hlp_usage_active_bindings` | | active and soft-invalid bindings |
| `hlp_usage_pushes_yesterday` | `class="alert"`, `"silent"`, `"liveactivity"` | pushes of the last completed day |
| `hlp_usage_outcomes_yesterday` | `outcome="accepted"`, `"soft_failed"`, `"unregistered"` | outcomes of the last completed day |
| `hlp_usage_registrations_last_week` | | registrations in the last completed week |
| `hlp_usage_opt_outs_last_week` | | direct opt-outs in the last completed week |
| `hlp_instances` | `tier="probation"`, `"standard"`, `"suspended"`, `"revoked"` | instances per tier, the `instances` block of `admin stats` |
| `hlp_bindings` | `state="provisional"`, `"active"`, `"soft_invalid"` | bindings per state, the `bindings` block of `admin stats` |

The underlying day counters (`counters_global`) are kept for 400 days.

## Abuse runbook

1. **Find.** `admin suspects` lists the instances with invalid tokens, rebinds or challenges in the last
   7 days, worst first. Triggers to run it: `hlp_invalid_budget_exceeded_total`,
   `hlp_registrations_total{result="limited"}`, `hlp_auth_failures_total`, a rising share of
   `hlp_push_total{result="global"}`, a breaker that opened, or a report to abuse@healthlog.dev. Reports name
   the instance id that the app or the server shows.
2. **Let the automatic limits work.** Over the invalid-token budget an instance gets no new bindings and no
   pushes to provisional or soft-invalid bindings for 24 hours; a soft-invalid binding gets at most one probe
   push a day; probation instances share a small pool; provisional bindings expire after two days; per-device
   limits cap what one device receives.
3. **Look and suspend.** `admin instance <id>`, then `admin suspend <id> <reason>`. Reply to the reporter;
   do not confirm details about other instances.
4. **If the actor comes back** with new instances: `admin registration invite`; `admin block-token` for
   tokens that are being targeted.
5. **If others are affected:** `admin pause --tier probation`, then `admin pause --class silent`.
6. **Last step:** revoke the APNs key in the Apple developer account and deploy a replacement
   ([APNs key](#apns-key)). Confirm `/healthz` is `ok` and a test push arrives.
7. **For every step:** write it in your change log, set a notice if instances are affected, and if data may
   have been exposed, start the [incident procedure](#incident-and-breach) and its 72-hour clock.

Appeals arrive at abuse@healthlog.dev with the instance id. Review the reason, answer, and use
`admin unsuspend <id>` when the appeal is upheld. A suspension can remain unreviewed for up to 14 days; the
terms say so.

## Absence checklist

Before an absence of more than a week:

- [ ] Deploys frozen; the running digest noted.
- [ ] `admin registration invite`.
- [ ] A notice set if instances should know (`admin notice set <id> --level info`).
- [ ] Apple Developer Program membership and the domain valid for more than 60 days.
- [ ] TLS certificate valid for more than 30 days.
- [ ] Last restore test from the export succeeded.
- [ ] Secret store reachable by the person who would rebuild.
- [ ] A delegate named in writing, with access to the host and the abuse mailbox, authorised for abuse
      runbook steps 1 to 5 and for a rebuild from the export ([migration.md](migration.md),
      [Restore](#restore)). The delegate does not hold and does not revoke the APNs key.
- [ ] It is agreed who decides on a breach notification within 72 hours while you are away.

## Incident and breach

1. **Contain.** Depending on the case: `admin pause`, `admin breaker open`, `admin registration closed`,
   stop the relay (`docker compose stop relay`), or revoke the APNs key. A suspected host compromise means:
   revoke the APNs key, rotate the relay identity (switch to `next`), the token MAC key and the ACME account
   key, and rebuild on a fresh host from the export ([migration.md](migration.md)). Do not reuse anything
   from the old disk.
2. **Preserve.** Note times, the running digest (`/version`), and which logs exist. The relay's logs contain
   no ids or addresses, so they show what happened, not to whom.
3. **Assess** which assets were reachable ([threat-model.md](threat-model.md#assets)): tokens in flight, the
   token MAC key and database, the identity key, the APNs key.
4. **Notify.** If personal data was affected and a risk to people cannot be ruled out, notify the
   supervisory authority within 72 hours of becoming aware (Art. 33 GDPR). The relay cannot identify the
   people concerned, so inform them through every instance with `admin notice set <id> --level
   action_required` and a public statement on the project's pages (Art. 34(3)(c) GDPR). Tell instance
   operators who reported issues directly.
5. **Recover and record.** Restore service through a verified deploy, write down cause, timeline, effect and
   the changes made, and update this document if a step was missing.

Security reports from outside follow [SECURITY.md](../SECURITY.md).

## Restore

Only `/export/registry.json` is backed up. The database, the certificate cache and the secrets are not.

- **Damaged database.** At start the relay runs a consistency check. Only proven damage (a failed
  consistency check, an invalid file, a version or checksum mismatch, a mapping error or a truncated file)
  moves the file aside as `relay.db.damaged-YYYYMMDDTHHMMSSZ` (with a numeric suffix if that name exists;
  an earlier copy is never overwritten). The relay then creates an empty store, imports
  `/export/registry.json` and opens a 14-day recovery window. Log lines: `store.damaged_moved_aside`,
  `store.imported_export`. Nothing needs to be done by hand.
- **Database that cannot be opened for another reason** (a lock still held by another process, wrong
  permissions after a deploy, a full disk): the relay leaves the file in place and exits with an error, and
  the container restarts. Fix the cause; the next start uses the file with every binding intact.
- **Lost database or new host.** An empty `/data` with an export present has the same effect: import and a
  14-day recovery window. Copy the export from your backup to `/srv/healthlog-push/export/registry.json`
  (owner 65532, group 65530, mode 0640) before the first start.
- **On a running relay**, `admin recovery --until <day> --from /export/registry.json` imports instances that
  are missing and opens the window.
- **The export must verify.** It is imported only when its signature verifies against this relay's identity
  key, its `host` is `HLP_PUBLIC_HOST`, and every instance is inside the closed sets (UUIDv4 id, 32-byte key,
  known tier and reason, device limit 1 to 150). Otherwise the import fails as a whole and the relay does not
  start (log and exit code tell why); a restore therefore needs the same identity key and host name. An
  export written before format `healthlog-push-registry-v2` is refused.

Device bindings are not restored. The first push for a device answers `404 binding_unknown`; the instance
submits its stored device statement again, or gets a fresh one from the app. Bindings come back over a few
hours. Device opt-out blocks are restored from the export, so a server a device opted out of stays blocked;
the restore must use the same token MAC keys (current and previous) from the secret store, because the pair
hash is built from the token MAC. The opt-out key pins are restored without the key, so every new binding
of such a token goes through the challenge that only the device can answer. Operator token blocks
(`block-token`, reason `operator_block`) travel in the export as well, and suspended or revoked instances
keep their tier and reason, so every abuse block is still in force after a restore. Check with `admin stats` (tiers) and one `admin instance <id>` of a
blocked instance.

Test a restore regularly: start a relay with an empty `/data` and a copy of the export on a test host with
the same identity key and `HLP_PUBLIC_HOST` (the signature binds both), and check that `admin stats` shows
the imported instances.

## Hosting and certifications

The hosted relay runs on a dedicated Hetzner Cloud server operated by Hetzner Online GmbH in
Falkenstein, Germany. The certification wording for users is section 13 of
[privacy.md](privacy.md#13-hosting-and-certifications); keep both in step and re-check the sources there at
least once a year (ISO/IEC 27001 certificate, BSI C5 Type 2 attestation period, sub-processor list). Before
the notice may say that processing is governed by a concluded data processing agreement, confirm in the
Hetzner customer account that the agreement under Art. 28 GDPR has been concluded; until then the notice
only says it is available under Hetzner's standard terms. Host hardening: [hardening.md](hardening.md).
