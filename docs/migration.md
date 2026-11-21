# Moving the relay to a new host

This procedure moves a running healthlog-push relay to a new machine: a
larger plan at the same provider (for example Hetzner Cloud CPX11 to CX23) or
a different provider altogether. It keeps the public name, the relay
identity, every issued token, and the registry of instances. It does not
carry over device bindings; those come back on their own.

Example values: public name `push.example.org`, old host `203.0.113.10` /
`2001:db8::10`, new host `203.0.113.20` / `2001:db8::20`.

## What moves and what does not

| Item | How it reaches the new host |
|---|---|
| Image | The same digest, deployed by the Ansible role, verified again by cosign |
| Relay identity key, token MAC keys, ACME account key | From the secret store, same values. Pinned relay keys and token MACs stay valid. |
| APNs key | From the secret store, into the signer path only |
| Instance registry and denylist | `/srv/healthlog-push/export/registry.json`, the only file copied from the old host |
| bbolt database (`/data`) | **Not moved.** The new host starts with an empty `/data`. |
| TLS certificate and key (`/acme`) | **Not moved.** The new host obtains a fresh certificate via TLS-ALPN-01. |
| Device bindings | **Not moved.** They return through the rebind path. |

Because the ACME account key comes from the secret store, the new host
registers with the same ACME account. The CAA record, which names that
account, therefore stays the same. Never take the account key, or anything
else under `secrets/` or `acme/`, from the old disk.

## Before the day

1. **Lower the DNS TTL** of the A and AAAA records of `push.example.org` to
   60 seconds. Wait at least one old TTL before you continue.
2. Note the image digest that is live: `curl -s https://push.example.org/version`.
   The new host gets exactly this digest. Upgrades and moves are separate
   changes.
3. Check that the secret store holds the current relay identity key, token
   MAC key (and the previous one if a rotation is in progress), ACME account
   key, APNs key, key id and team id.
4. Check the last daily export on the old host:
   `ls -l /srv/healthlog-push/export/registry.json`.

## Provision the new host

5. Create the new host. Apply the same cloud firewall rules
   (see `deploy/ansible/README.md`), with the temporary bootstrap SSH rule if
   you need it.
6. Add it to the inventory with its own `ansible_host`, and run the full
   playbook with the same `healthlog_push_image` and
   `healthlog_push_release_tag` as the old host, but without starting the
   containers. The public name still points at the old host, so the new
   relay could not obtain a certificate yet, and its `/data` must stay empty
   until the export is in place:

   ```sh
   ansible-playbook -i inventory.yml site.yml --limit push-02 \
     -e healthlog_push_image=ghcr.io/mbombeck/healthlog-push@sha256:<live digest> \
     -e healthlog_push_release_tag=<live tag> \
     -e healthlog_push_start=false \
     -e @secrets.vault.yml --ask-vault-pass
   ```

   This run still verifies the signature and the provenance, writes all
   files and pulls the image. Check that `/srv/healthlog-push/data` is empty.

## Cut over

The relay is unavailable from step 7 until step 11. Instances queue or fall
back; nothing is lost on their side.

7. **Stop the old relay** so no further registrations land there:

   ```sh
   # old host
   cd /srv/healthlog-push/compose
   docker compose -p healthlog-push exec -T relay /healthlog-push admin export
   docker compose -p healthlog-push stop relay
   ```

   Run the export first, while the admin socket is still served, then stop.
   The export written in that moment is the final state.
8. **Copy only the export.** Nothing else leaves the old host.

   ```sh
   # from the control node
   scp old:/srv/healthlog-push/export/registry.json ./registry.json
   sha256sum registry.json
   scp ./registry.json new:/tmp/registry.json
   # new host
   install -o 65532 -g 65530 -m 0640 /tmp/registry.json /srv/healthlog-push/export/registry.json
   shred -u /tmp/registry.json
   ```

   Compare the checksum on both ends. Delete the copy on the control node
   afterwards.
9. **Switch DNS**: A to `203.0.113.20`, AAAA to `2001:db8::20`. Leave the CAA
   record as it is.
10. **Start the new relay** through the role, so the health gate applies.
    With an empty `/data` and a present `/export/registry.json` the relay
    imports the registry and opens the 14-day recovery window:

    ```sh
    ansible-playbook -i inventory.yml site.yml --limit push-02 --tags healthlog_push \
      -e healthlog_push_image=ghcr.io/mbombeck/healthlog-push@sha256:<live digest> \
      -e healthlog_push_release_tag=<live tag> \
      -e @secrets.vault.yml --ask-vault-pass
    # new host
    docker compose --project-directory /srv/healthlog-push/compose -p healthlog-push logs relay --since 5m
    ```

    Once DNS answers with the new address, the relay obtains its certificate
    through TLS-ALPN-01 on port 443. If the play reports the relay unhealthy
    only because DNS has not propagated yet, rerun the same command a few
    minutes later; on a first deploy there is no previous image to roll back to.
11. **Verify** from outside:

    ```sh
    curl -s https://push.example.org/healthz      # "status":"ok"
    curl -s https://push.example.org/version      # imageDigest equals the live digest from step 2
    openssl s_client -connect push.example.org:443 -servername push.example.org </dev/null 2>/dev/null \
      | openssl x509 -noout -issuer -dates         # fresh certificate, issued today
    ```

    Then fetch `/v1/status` with a client that checks the response signature
    against the pinned relay key (any HealthLog server does this; a missing
    or wrong signature is a transport error). Finally send one real push to a
    test device and confirm it arrives.

    On the new host, `docker compose -p healthlog-push exec -T relay /healthlog-push admin stats`
    must show the imported instances.

## Bindings come back by themselves

Device bindings live in `/data`, which is never copied. The first push for a
device after the move is answered with `404 binding_unknown`. The instance
then submits the stored device statement again; if that statement is older
than 300 seconds, the app supplies a fresh one on its next `/api/auth/me`.
Bindings revoked before the move stay revoked, because they are not in the
export at all. Expect the number of bindings to climb back over a few hours.

During the 14-day recovery window, instances that register again with a
public key present in the export get their old identity and tier back.
Nothing needs to be done by hand.

## Rollback

Any time before the old host is wiped:

1. Stop the new relay: `docker compose -p healthlog-push stop relay` on the new host.
2. Point A and AAAA back to `203.0.113.10` and `2001:db8::10`.
3. Start the old relay: `docker compose -p healthlog-push start relay` on the old host.
   Its `/data` and `/acme` are untouched, so it resumes with its own
   certificate and bindings. Registrations made on the new host in the
   meantime are lost; those instances register again.
4. Verify `/healthz`, `/version` and one push as in step 11.

Do not run both relays behind the public name at the same time.

## Retire the old host

After the new host has run cleanly for at least one full day and a daily
export has been written there:

1. Stop the stack: `docker compose -p healthlog-push down`.
2. Shred the secrets, then remove state:

   ```sh
   find /srv/healthlog-push/secrets -type f -exec shred -u {} +
   shred -u /srv/healthlog-push/acme/* 2>/dev/null || true
   rm -rf /srv/healthlog-push
   docker volume rm healthlog-push_jwt healthlog-push_jwt-refresh 2>/dev/null || true
   ```

3. Delete the server and its addresses at the provider (no snapshot, no
   image of it).
4. Remove the old host from the inventory, from your backup tool and from
   monitoring.
5. Record the move in your change log: date, old and new host, digest,
   export checksum, result of the verification.
6. Raise the DNS TTL back to its normal value.

Shredding on virtual disks is best effort. The real protection is that the
old host never held anything that is not also in the secret store, and that
the provider deletes the volume.

## Checklist

- [ ] TTL lowered at least one old TTL in advance
- [ ] Live digest and tag noted from `/version`
- [ ] Secret store holds all relay and signer values
- [ ] New host provisioned with the role, same digest, cosign verification green
- [ ] New host prepared with `healthlog_push_start=false`, `/data` empty
- [ ] Final `admin export` on the old host, old relay stopped
- [ ] Only `registry.json` copied, checksum matches on both ends
- [ ] A and AAAA switched, CAA unchanged
- [ ] New relay started, import and recovery window in the log
- [ ] `/healthz` ok, `/version` digest matches, fresh certificate
- [ ] Signed `/v1/status` accepted by a client with the pinned key
- [ ] One real push delivered
- [ ] `admin stats` shows the imported instances
- [ ] Backup tool points at the new host's include and exclude lists
- [ ] After one day: old host stopped, secrets shredded, server deleted
- [ ] Move recorded, TTL raised again
