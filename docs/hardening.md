# Hardening statement

How the host of the hosted relay at `push.healthlog.dev` is hardened. Measured on 2026-11-21 on the prepared
host, a dedicated cloud server in Germany. Statements about the containers and the external availability
check apply to the deployed relay. For the threat model and the guarantees of the
relay software itself see [threat-model.md](threat-model.md); hosting and certifications of the provider are
in section 13 of [privacy.md](privacy.md#13-hosting-and-certifications).

The relay runs on its own virtual server. Nothing else runs on it, and it holds no health records: it only ever sees
encrypted envelopes and the delivery metadata described in the privacy notice.

**Operating system.** Ubuntu 24.04 LTS, measured against the CIS Ubuntu Linux 24.04 Benchmark, Level 1 Server, with
selected Level 2 settings. The latest audit with the Ubuntu Security Guide (21 November 2026) scored 93.3 % for Level 1 Server against the full profile, and 97.9 % against our documented tailoring, which switches off only the rules we deliberately do not follow. An independent check with OpenSCAP and the ComplianceAsCode content had measured 70.7 % on the stock image. Every rule we do not
follow is recorded with its reason; those that matter for users of the relay are named below.

**Network.** The only public port is 443, served by the relay itself with TLS 1.3 (TLS 1.2 is offered only to a
handshake that asks for nothing but the certificate authority's validation protocol) and a certificate that only the
relay's own certificate account may obtain (CAA). There is no public SSH. Administrative access is possible only over
a private management network, with keys; there is no password login and no root login. Outbound connections are
limited to ports 443, 53 and 123 plus the log and metric receivers and the management network; plain HTTP only for
the package manager. The limit is by port, not by destination and not per service: any process on the host may open
a connection on port 443 to any address. The cloud metadata endpoint is reachable only for root. The log and metric
receivers accept writes only. The outbound limit is also enforced outside the machine, so it holds even if someone
gains full control of the host.

**Why SSL Labs grades the relay A, not A+.** Qualys SSL Labs grades the public port A with no warnings. Since the
grading change of March 2025, a server that speaks only TLS 1.3 cannot be tested for downgrade protection
(`TLS_FALLBACK_SCSV` needs two protocol versions), and SSL Labs then does not count the configuration as
exceptional, which is what A+ means. HSTS, the CAA record and the certificate are not what holds it back. Offering
TLS 1.2 as well would raise the grade and nothing else: HealthLog servers and the app speak TLS 1.3, and what clients
trust is the relay's signed answers and the end-to-end encrypted envelopes, not the grade. A second protocol version
for a scanner's grade would only add surface, so the relay stays at TLS 1.3 and at A.

**No keys to anything else.** The host holds no credentials for our other systems: no deployment keys, no cloud or
DNS tokens, no access to our password manager. The only credentials on it are the relay's own keys and a backup key
that can write to one storage location reserved for this host.

**Sandboxing.** The relay and the component that holds the Apple signing key run in separate containers as
unprivileged users, with a read-only root filesystem, all Linux capabilities dropped (the relay listens on an unprivileged port and the host firewall
forwards port 443 to it), no privilege escalation, the default seccomp filter and an AppArmor profile of its own for each container (`deploy/apparmor/`). The small in-memory volumes the two
containers share are mounted `noexec`, `nosuid` and `nodev`. The signing component
has no network access at all; the relay never sees the signing key, only short-lived tokens. The Wallet
component, once switched on, runs the same way in a third container (its own user, no network, read-only
root, no capabilities, 64 MiB, its own AppArmor profile): it holds the Wallet pass key, which the relay
never reads, and reaches Apple only through a tunnel of the relay that dials Apple's push host and nothing
else, with TLS from the Wallet component to Apple.

**Kernel.** Kernel lockdown (integrity mode), restricted kernel pointers and logs, unprivileged BPF disabled, no IP
forwarding, strict reverse-path filtering, core dumps disabled, unused filesystems and USB storage blocked.

**Updates.** Security updates install automatically every day, including extended security maintenance for the
wider package set. Kernel security fixes are applied to the running kernel through live patching. When an update needs a reboot,
the host reboots automatically at a fixed early-morning time, checked daily; there is no weekly window.

**Monitoring.** An audit trail records changes to accounts, privileged access, the relay's key files, container
configuration and the firewall. File integrity is checked and availability is checked from outside. The relay image
is scanned for known vulnerabilities with Grype in the published workflows: on every pull request and push to
`main`, before a release is published (by digest) and weekly against the latest release; a HIGH or CRITICAL
finding that has a fix fails the run. The host does not scan the running containers itself. None of this records the IP addresses of relay users: the relay writes no
access log, the system does not log martian packets, and no monitoring component reads the relay's traffic. A community
blocklist of known attacking addresses is applied at the firewall.

**What the published code covers.** The kernel measures (apart from disabling core dumps), the audit trail, file
integrity checking, live patching and the address blocklist belong to the operator's host baseline
and are not part of the published Ansible roles, so they cannot be verified from this repository.

**Backups.** Only a daily export of registered instances (suspended and revoked ones with their tier and reason) and
the blocks (device opt-outs, opt-out key pins and operator token blocks, as keyed hashes) is backed up, encrypted, to a
separate storage account in Germany. The export is signed with the relay's identity key, and the relay refuses to
import an export that was changed. Device bindings, counters, the Wallet signing ledger, TLS keys and the signing keys are never backed up. The server is
not snapshotted; it is rebuilt from code.

**What is not guaranteed.** Anyone with full control of the host could read the relay's keys and the metadata passing
through it at that moment, though not the content of notifications. The hosting provider can see connection metadata
to the server. The service has a single instance with a target of 99.5 % availability over 30 days, without a
service-level agreement. Two deviations from the CIS benchmark follow from how the relay works: there is no user
namespace remapping in the container runtime (incompatible with the host network the relay needs to apply per-address
limits), and logging of martian packets is disabled (it would record client addresses).
