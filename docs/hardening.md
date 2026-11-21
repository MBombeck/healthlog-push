# Hardening statement

How the host of the hosted relay at `push.healthlog.dev` is hardened. Measured on 2026-11-21 on the prepared
host (Hetzner Cloud CX23, Falkenstein, Germany). Statements about the containers, image scanning and the
external availability check apply to the deployed relay. For the threat model and the guarantees of the
relay software itself see [threat-model.md](threat-model.md); hosting and certifications of the provider are
in section 13 of [privacy.md](privacy.md#13-hosting-and-certifications).

The relay runs on its own virtual server. Nothing else runs on it, and it holds no health records: it only ever sees
encrypted envelopes and the delivery metadata described in the privacy notice.

**Operating system.** Ubuntu 24.04 LTS, measured against the CIS Ubuntu Linux 24.04 Benchmark, Level 1 Server, with
selected Level 2 settings. The latest audit with the Ubuntu Security Guide (21 November 2026) scored 93.3 % for Level 1 Server against the full profile, and 97.9 % against our documented tailoring, which switches off only the rules we deliberately do not follow. An independent check with OpenSCAP and the ComplianceAsCode content had measured 70.7 % on the stock image. Every rule we do not
follow is listed with its reason in our operations notes; the main ones are named below.

**Network.** The only public port is 443, served by the relay itself with TLS 1.3 (TLS 1.2 is accepted only for
the certificate authority's validation handshake) and a certificate that only the
relay's own certificate account may obtain (CAA). There is no public SSH. Administrative access is possible only over
a private management network, with keys; there is no password login and no root login. Outbound traffic is limited
per service: the relay may only open connections on port 443 (to Apple's push service and the certificate
authority). The host cannot reach any other system except the endpoints that receive its logs and metrics, and those
accept writes only. This holds even if someone gains full control of the host: the restriction is enforced outside
the machine as well as on it.

**No keys to anything else.** The host holds no credentials for our other systems: no deployment keys, no cloud or
DNS tokens, no access to our password manager. The only credentials on it are the relay's own keys and a backup key
that can write to one storage location reserved for this host.

**Sandboxing.** The relay and the component that holds the Apple signing key run in separate containers as
unprivileged users, with a read-only root filesystem, all Linux capabilities dropped (the relay listens on an unprivileged port and the host firewall
forwards port 443 to it), no privilege escalation, the default seccomp filter and AppArmor profiles. The signing component
has no network access at all; the relay never sees the signing key, only short-lived tokens.

**Kernel.** Kernel lockdown (integrity mode), restricted kernel pointers and logs, unprivileged BPF disabled, no IP
forwarding, strict reverse-path filtering, core dumps disabled, unused filesystems and USB storage blocked.

**Updates.** Security updates install automatically every day, including extended security maintenance for the
wider package set. Kernel security fixes are applied to the running kernel through live patching; full kernel updates
take effect in a weekly maintenance window with an automatic reboot.

**Monitoring.** An audit trail records changes to accounts, sudo use, SSH configuration, the relay's key files,
container configuration and the firewall. File integrity is checked continuously, container images are scanned for
known vulnerabilities, and availability is checked from outside. None of this records the IP addresses of relay
users: the relay writes no access log, the system does not log martian packets, and the intrusion detection only
reads system and SSH logs. A community blocklist of known attacking addresses is applied at the firewall.

**Backups.** Only a daily export of registered instances, the denylist and the blocks (device opt-outs and
operator token blocks, as keyed hashes) is backed up, encrypted, to a separate
storage account in Germany. Device bindings, counters, TLS keys and the signing key are never backed up. The server is
not snapshotted; it is rebuilt from code.

**What is not guaranteed.** Anyone with full control of the host could read the relay's keys and the metadata passing
through it at that moment, though not the content of notifications. The hosting provider can see connection metadata
to the server. The service has a single instance with a target of 99.5 % availability over 30 days, without a
service-level agreement. Deviations from the CIS benchmark include: file integrity is checked with our own tool instead of AIDE; no boot loader password (console access is
protected by the hosting account), no immutable audit rules (so they can be updated without a reboot), no user
namespace remapping in the container runtime (incompatible with the host network the relay needs to apply per-address
limits), and logging of martian packets disabled (it would record client addresses).
