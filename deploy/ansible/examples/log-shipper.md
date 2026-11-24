# Shipping relay logs without addresses

The relay does not log client addresses. This page adds a second line of
defence for whatever log shipper you run on the host: any line that still
looks like it carries an IPv4 or IPv6 address is dropped before it leaves the
machine. Dropping a harmless line is the safe failure; shipping an address is
not.

## Source

Docker writes container output to
`/var/lib/docker/containers/<id>/<id>-json.log` (json-file driver, 10 MB x 3).
Each line is a JSON object:

```json
{"log":"<the relay's own JSON log line>\n","stream":"stderr","attrs":{"com.docker.compose.service":"relay"},"time":"2026-01-01T00:00:00.000000000Z"}
```

The compose file sets the `labels` log option, so `attrs` names the service
(`relay` or `signer`). Read these files as root; do not give the shipper the
Docker socket.

With `healthlog_push_log_driver: journald` the lines go to the systemd journal
instead (`deploy/compose/compose.journald.yaml`): read them with the shipper's
journal source, filtered on `CONTAINER_NAME` or `COM_DOCKER_COMPOSE_SERVICE`.
The relay's alert lines carry `"level":"alert"` and have the journal priority
`err`. The address filter below applies to the journal `MESSAGE` the same way.

## Pipeline

1. Parse the Docker JSON envelope and keep `log` as the line, `stream` and
   `attrs."com.docker.compose.service"` as labels. Use the envelope `time` as
   the timestamp.
2. Drop the line when the `log` content matches either expression below.
   Match against the content, not the envelope, so the envelope timestamp
   cannot trigger the IPv6 rule.
3. Ship to your receiver. The firewall only lets the host reach the
   receivers listed in `healthlog_push_egress_receivers`.

IPv4 (dotted quad, with or without a port):

```
(^|[^0-9.])(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])([.](25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}([^0-9.]|$)
```

IPv6 (three or more colon-separated hex groups, or any `::` form, including
IPv4-mapped addresses):

```
(?i)(^|[^0-9a-f:])(([0-9a-f]{1,4}:){3,7}[0-9a-f]{0,4}|[0-9a-f]{0,4}(:[0-9a-f]{1,4})*::([0-9a-f]{1,4}(:[0-9a-f]{1,4})*)?)([^0-9a-f:]|$)
```

Both expressions are RE2 compatible. A time of day such as `12:30:45` has only
two colon-separated groups and does not match; a version string such as
`1.2.3.4` does and is dropped, which is acceptable.

## Generic config sketch

Most shippers express the steps above in a few lines. In pseudo-config:

```
source  files  "/var/lib/docker/containers/*/*-json.log"
parse   docker-json  -> line = .log, labels = {service: .attrs["com.docker.compose.service"], stream: .stream}
drop    if line =~ IPV4_EXPRESSION
drop    if line =~ IPV6_EXPRESSION
send    to receiver
```

## Hook into the role

Write the shipper's configuration as an Ansible task file on the control node
(see `log-shipper-tasks.example.yml`) and point the role at it:

```yaml
healthlog_push_log_shipping_tasks: "{{ playbook_dir }}/local/log-shipper-tasks.yml"
```

The role includes it after a successful deploy.

## Test before you rely on it

Feed the shipper a file with these lines and check that only the first one
arrives:

```
{"log":"{\"level\":\"info\",\"msg\":\"delivered\",\"class\":\"alert\"}\n","stream":"stderr","time":"2026-01-01T12:30:45Z"}
{"log":"accepted from 203.0.113.10:51515\n","stream":"stderr","time":"2026-01-01T12:30:45Z"}
{"log":"accepted from [2001:db8::10]:51515\n","stream":"stderr","time":"2026-01-01T12:30:45Z"}
{"log":"accepted from ::ffff:203.0.113.10\n","stream":"stderr","time":"2026-01-01T12:30:45Z"}
```
