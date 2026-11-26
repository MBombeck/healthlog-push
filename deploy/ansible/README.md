# Deploying healthlog-push with Ansible

This directory turns a fresh Ubuntu 24.04 host into a single-purpose
healthlog-push relay host and deploys a signed release onto it. It is written
for a small cloud VM and contains nothing provider-specific; the cloud
firewall table further down uses plain rules that any provider firewall can
express.

The runtime contract the roles follow (paths, users, ports, health) is the
same one the compose file in `deploy/compose/compose.yaml` encodes. The role
copies that exact file to the host; there is no second copy.

## What the roles do

| Role | Does |
|---|---|
| `base` | Admin accounts with SSH keys only, sshd hardening (no passwords, no root login, `AllowUsers`), core dumps off (sysctl, limits, systemd, systemd-coredump, apport masked), swap off and removed from fstab, chrony with two or more sources, unattended upgrades for the security pocket only, checked daily, with an automatic reboot at a fixed early-morning time (`base_unattended_reboot_time`, default `04:20`, host time UTC) when an update needs one. The SSH restart handler fails the run if the restart fails. |
| `firewall` | nftables `inet` table: inbound 443 redirected to 8443 (IPv4 and IPv6), ICMP and ICMPv6, SSH from the configured management sources, default drop; egress limited to the list below, default drop. Validated with `nft -c -f` before it is installed and applied behind a dead-man switch. |
| `docker` | Docker CE from the official apt repository; the signing key is accepted only with the pinned fingerprint. `daemon.json` is written before the first start (`iptables: false`, `ip6tables: false`, `userland-proxy: false`, `live-restore: true`, json-file 10m x 3). |
| `healthlog_push` | Directories and owners, secret files, backup lists, cosign at a pinned version and checksum, signature and provenance verification, compose deploy with a health gate and automatic rollback, optional export timer, optional log shipping hook. |

## Requirements on the control node

- `ansible-core` 2.16 or newer. Only `ansible.builtin` modules are used.
- SSH access to the host as described under Bootstrap.
- Your secret store, reachable from the control node.

## Files you create (not committed)

```
deploy/ansible/inventory.yml          from inventory.example.yml
deploy/ansible/group_vars/all.yml     from group_vars/all.example.yml
```

Secrets are passed at run time, never written into either file. Any
mechanism that ends up as Ansible variables works: an encrypted vars file
(`-e @secrets.vault.yml --ask-vault-pass`), a lookup plugin for your secret
store, or environment lookups in a wrapper script. Every task that touches a
secret runs with `no_log: true` and `diff: false`.

| Variable | Content | Written to |
|---|---|---|
| `healthlog_push_secret_relay_id_key` | the `relay_id_key` value from `healthlog-push keygen relay-id` (the seed only, not the JSON line) | `secrets/relay/relay_id_key` |
| `healthlog_push_secret_token_mac_key` | output of `healthlog-push keygen token-mac` | `secrets/relay/token_mac_key` |
| `healthlog_push_secret_token_mac_key_previous` | previous MAC key, only during a rotation | `secrets/relay/token_mac_key_previous` (removed when empty) |
| `healthlog_push_secret_acme_account_key` | output of `healthlog-push keygen acme-account` | `secrets/relay/acme_account_key` |
| `healthlog_push_secret_apns_key_p8_b64` | the APNs `.p8` file, base64 | `secrets/signer/apns.p8` (signer only) |
| `healthlog_push_secret_wallet_pass_key_pem` | the Wallet pass key, PEM; only with `healthlog_push_wallet_enabled` | `secrets/wallet/pass.key` (wallet only) |
| `healthlog_push_secret_wallet_pass_cert_pem` | the Pass Type ID certificate, PEM; only with `healthlog_push_wallet_enabled` | `secrets/wallet/pass.crt` (wallet only) |

All secret files are mode 0400, owned by the container user that reads them,
and excluded from backups.

## Host layout

| Path | Owner | Mode | Purpose | Backed up |
|---|---|---|---|---|
| `/srv/healthlog-push/data` | 65532:65530 | 0700 | bbolt database, admin socket | no |
| `/srv/healthlog-push/export` | 65532:65530 | 0750 | daily `registry.json` | **yes, the only path** |
| `/srv/healthlog-push/acme` | 65532:65530 | 0700 | TLS certificate and key | never, never copied |
| `/srv/healthlog-push/secrets/relay` | 65532 | 0500, files 0400 | relay keys | no |
| `/srv/healthlog-push/secrets/signer` | 65533 | 0500, file 0400 | `apns.p8` | no |
| `/srv/healthlog-push/secrets/wallet` | 65534 | 0500, files 0400 | `pass.key`, `pass.crt`; only while Wallet is on, removed when it is off | no |
| `/srv/healthlog-push/compose` | root | 0750 | `compose.yaml`, `compose.journald.yaml` (used with `healthlog_push_log_driver: journald`), `.env` (0600) | no |
| `/srv/healthlog-push/deployed-digest` | root | 0644 | image of the last healthy deploy | no |
| `/etc/healthlog-push/backup-include.list` | root | 0644 | for your backup tool | n/a |
| `/etc/healthlog-push/backup-exclude.list` | root | 0644 | for your backup tool | n/a |

Point your backup tool at the include list and the exclude list. The role
fails if the include list ever contains anything other than the export path.
Do not take provider snapshots of this host: a snapshot contains every
secret. Rebuilding runs through this playbook and the export.

## Bootstrap

SSH must stay reachable for you at every step. The `base` role refuses to run
unless `ssh_allowed_interfaces` or `ssh_allowed_cidrs` is set, and the
`firewall` role refuses if a named interface does not exist yet.

1. Create the host with your SSH key. In the cloud firewall, allow tcp/22
   temporarily from your current address only.
2. Set `ssh_allowed_cidrs` to that address (and, if you use one, the
   management network or VPN in `ssh_allowed_interfaces` once it is up).
3. First run as root:
   `ansible-playbook -i inventory.yml site.yml -u root`
   Root login is disabled by this run; from now on connect as one of
   `base_admin_users`.
4. Once your management path works, remove the bootstrap CIDR, rerun with
   `--tags base,firewall`, and remove the temporary tcp/22 rule from the
   cloud firewall.

### Firewall dead-man switch

When the rule set changes, the handler first schedules a restore of the
previous `/etc/nftables.conf` (`systemd-run --on-active=120`), reloads
nftables, then opens a fresh TCP connection to the SSH port from the control
node. Only when that succeeds is the restore cancelled. If you lock yourself
out, the old rules come back by themselves after `firewall_rollback_seconds`.

## Firewall policy

Inbound:

| Traffic | Rule |
|---|---|
| tcp/443, IPv4 and IPv6 | redirected to 8443 in `prerouting`; 8443 accepted only with `ct status dnat` |
| ICMP | echo, unreachable, time exceeded, parameter problem (rate limited) |
| ICMPv6 | the same plus packet too big and neighbour discovery (required for IPv6) |
| tcp/22 | only from `ssh_allowed_interfaces` and `ssh_allowed_cidrs` |
| established, related, loopback | accepted |
| DHCP replies | accepted when `firewall_allow_dhcp` (cloud IPv4 uses DHCP) |
| everything else | dropped and counted |

Egress:

| Traffic | Why |
|---|---|
| tcp/443 | APNs, ACME TLS-ALPN-01, image registry, signature log, HTTPS package repositories |
| udp/53, tcp/53 | DNS |
| udp/123 | NTP |
| tcp/80 for uid `_apt` only | Ubuntu mirrors |
| `healthlog_push_mgmt_vpn_egress` | whatever your management VPN needs (default: nothing) |
| `healthlog_push_egress_receivers` | your log and metric receivers, by address and port (default: nothing) |
| 169.254.169.254 tcp/80 | only when `firewall_allow_cloud_metadata`, and only for uid 0 |
| ICMP, ICMPv6 | errors, echo, neighbour discovery |
| everything else | dropped and counted |

The limit is by port, not by destination: tcp/443, DNS and NTP are open to any address for every process on
the host.

No rule logs packets. Drops go to named counters only:
`nft list counters table inet healthlog_push`.

## Cloud firewall

Run the provider firewall in front of the host firewall. The host rules work
on any provider; the cloud rules keep scans off the host in the first place.
This repository does not call the provider API. The rule names below are
meant to be reused as they are in your infrastructure code.

| Name | Direction | Protocol | Port | Source / destination |
|---|---|---|---|---|
| `hlp-in-https` | in | tcp | 443 | `0.0.0.0/0`, `::/0` |
| `hlp-in-icmp` | in | icmp | | `0.0.0.0/0`, `::/0` |
| `hlp-out-https` | out | tcp | 443 | `0.0.0.0/0`, `::/0` |
| `hlp-out-http` | out | tcp | 80 | `0.0.0.0/0`, `::/0` (the host limits it to `_apt`) |
| `hlp-out-dns-udp` | out | udp | 53 | `0.0.0.0/0`, `::/0` |
| `hlp-out-dns-tcp` | out | tcp | 53 | `0.0.0.0/0`, `::/0` |
| `hlp-out-ntp` | out | udp | 123 | `0.0.0.0/0`, `::/0` |
| `hlp-out-icmp` | out | icmp | | `0.0.0.0/0`, `::/0` |
| `hlp-out-mgmt-vpn` | out | per `healthlog_push_mgmt_vpn_egress` | | only if you use one |
| `hlp-out-receivers` | out | per `healthlog_push_egress_receivers` | | receiver addresses only |

There is no inbound SSH rule: administrative access runs only over a private
management network. Add a temporary `hlp-in-ssh-bootstrap` rule for the
first run and remove it afterwards. Once an outbound rule exists, the cloud
firewall drops all other outbound traffic, which is the intent. DHCP and the
metadata service are not filtered by the cloud firewall.

## Deploying a release

```sh
ansible-playbook -i inventory.yml site.yml --tags healthlog_push \
  -e healthlog_push_image=ghcr.io/mbombeck/healthlog-push@sha256:<digest> \
  -e healthlog_push_release_tag=vX.Y.Z \
  -e @secrets.vault.yml --ask-vault-pass
```

Order inside the role:

1. Assert that the image is `ghcr.io/...@sha256:<64 hex>` and the tag is `vX.Y.Z`.
2. Write directories, secret files, the compose file and the backup lists; with `healthlog_push_apparmor_install`, install and load the AppArmor profiles of the release, and check that named profiles are loaded in enforce mode.
3. Install cosign at the pinned version; the download must match the pinned SHA-256.
4. `cosign verify <image> --certificate-identity https://github.com/MBombeck/healthlog-push/.github/workflows/release.yml@refs/tags/<tag> --certificate-oidc-issuer https://token.actions.githubusercontent.com`
5. `cosign verify-attestation <image> --type slsaprovenance1 --certificate-identity https://github.com/MBombeck/healthlog-push/.github/workflows/provenance.yml@refs/tags/<tag> --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-github-workflow-repository MBombeck/healthlog-push` (cosign 3, pinned in `defaults/main.yml` with the SHA-256 of both architectures; releases before v1.0.1 carry the older provenance format and do not pass this step)
6. Only now: render `.env` with the new image and `HLP_SECRETS_REV`, a SHA-256 fingerprint of all secrets, `docker compose pull`, `docker compose up -d`. Because the fingerprint is part of the compose environment of both containers, compose recreates them whenever a secret differs from what they were started with, also when an earlier run wrote the secret files and then failed.
7. Wait until `docker compose exec relay /healthlog-push healthcheck` exits 0 (status `ok`) and the signer reports healthy, then check that each container runs under the AppArmor profile set in `healthlog_push_apparmor_relay` and `healthlog_push_apparmor_signer`.
8. Write the image to `/srv/healthlog-push/deployed-digest`.

A failure in steps 3 to 5 aborts before compose is touched. A failure in
steps 6 or 7 restores the image recorded in `deployed-digest`, waits for it to
become healthy, and then fails the play, so a red run never looks green.
To prove the verification works, run once with a digest that was not signed
by the release workflow; the play must stop at step 4.

Forks that publish their own image set `healthlog_push_source_repo` and
`healthlog_push_image` to their own repository.

## Optional pieces

- **Prepare without starting.** `healthlog_push_start: false` verifies the
  release, writes every file and pulls the image, but leaves the containers
  stopped. Used when preparing a new host (`docs/migration.md`).
- **Wallet passes.** `healthlog_push_wallet_enabled: true` with `healthlog_push_wallet_pass_type_id`,
  `healthlog_push_wallet_team_id` and the two Wallet secrets above writes `secrets/wallet`, adds
  `COMPOSE_PROFILES=wallet`, `HLP_WALLET_DIR` and the identifiers to `.env`, installs and checks the
  `healthlog-push-wallet` AppArmor profile when `healthlog_push_apparmor_wallet` names it (set it together
  with `healthlog_push_apparmor_relay`, the two profiles name each other), and waits until the wallet
  process answers on its socket (`healthcheck --wallet`). `false` stops and removes the wallet container and
  deletes `secrets/wallet`.
- **Export timer.** The relay writes `/export/registry.json` daily by itself.
  `healthlog_push_export_timer_enabled: true` adds a systemd timer that also
  runs `docker compose exec -T relay /healthlog-push admin export` once a day.
- **Log shipping.** `healthlog_push_log_shipping_tasks` names a task file on
  the control node that the role includes after a healthy deploy. See
  `examples/log-shipper.md` for the address-dropping filter every shipper on
  this host should apply, and `examples/log-shipper-tasks.example.yml`.

## Checks

```sh
ansible-playbook --syntax-check -i deploy/ansible/inventory.example.yml deploy/ansible/site.yml
yamllint -c deploy/.yamllint deploy/
(cd deploy/ansible && ansible-lint --offline)
docker compose -f deploy/compose/compose.yaml --env-file deploy/compose/.env.example config -q
```

CI runs the first three in the `deploy-lint` job. The linters are installed with
`pip install --require-hashes --no-deps -r .github/deploy-lint-requirements.txt`: every package, the
dependencies included, is pinned by version and SHA-256. To update them, edit
`.github/deploy-lint-requirements.in` and regenerate the file with `pip-compile --generate-hashes
--allow-unsafe`.

Moving to another host: `docs/migration.md`.
