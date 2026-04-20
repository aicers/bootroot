# Remote Bootstrap Operator Guide

This guide covers the **remote-bootstrap** delivery mode for services
running on a machine other than the one hosting step-ca, OpenBao, and
the HTTP-01 responder (the **control node**).

## When to use remote-bootstrap vs local-file

`bootroot service add` offers two delivery modes via `--delivery-mode`:

| Mode | Use when | What happens |
| --- | --- | --- |
| `local-file` (default) | Service runs on the **same** machine as step-ca/OpenBao | `service add` writes configs directly to disk |
| `remote-bootstrap` | Service runs on a **different** machine | `service add` produces a JSON artifact; operator ships it to the service host and runs `bootroot-remote bootstrap` there |

Choose `remote-bootstrap` whenever the service machine cannot share a
filesystem with the control node.

## Prerequisites on the remote host

1. **`bootroot-remote` binary installed.** Pre-built release binaries are
    not yet available; build from source with
    `cargo build --release --bin bootroot-remote` and distribute the binary
    to each service machine. See [Installation](installation.md) for details.

2. **Network reachability.** The remote host must reach:

    - OpenBao's API endpoint (the `--openbao-url` value, typically
      `https://openbao.internal:8200` or your environment's equivalent).
    - step-ca's HTTPS ACME directory (the `--agent-server` value, e.g.
      `https://stepca.internal:9000/acme/acme/directory`).
    - The HTTP-01 responder (the `--agent-responder-url` value, e.g.
      `http://responder.internal:8080`).

3. **DNS / name resolution.** The SAN (Subject Alternative Name) for the
    service certificate must resolve from whatever DNS, `/etc/hosts`, or
    cloud-internal DNS the environment uses.

    !!! note
        The in-compose DNS alias automation tracked by
        [#472](https://github.com/aicers/bootroot/issues/472) only covers
        traffic between bundled containers on the Docker bridge network.
        Remote hosts need real DNS or equivalent entries configured by the
        operator.

4. **Filesystem layout.** Directories for secrets, certs, and agent config
    must exist (or be creatable) on the remote host. The paths are defined
    in the bootstrap artifact and passed to `bootroot-remote bootstrap`.

## The transport boundary

By design, bootroot does **not** ship files to remote hosts.
`bootroot service add --delivery-mode remote-bootstrap` produces a JSON
artifact and credential files; the operator chooses the transport mechanism
that fits their environment.

The files that must reach the remote host depend on whether response
wrapping is enabled (the default):

**With wrapping (default):**

| File | Source path (control node) | Purpose |
| --- | --- | --- |
| `bootstrap.json` | `secrets/remote-bootstrap/services/<service>/bootstrap.json` | Machine-readable artifact containing a `wrap_token` that `bootroot-remote` unwraps to obtain `secret_id` (**sensitive**) |
| `role_id` | `secrets/services/<service>/role_id` | AppRole identity (long-lived) |

**Without wrapping (`--no-wrap`):**

| File | Source path (control node) | Purpose |
| --- | --- | --- |
| `bootstrap.json` | `secrets/remote-bootstrap/services/<service>/bootstrap.json` | Machine-readable artifact consumed by `bootroot-remote bootstrap` |
| `role_id` | `secrets/services/<service>/role_id` | AppRole identity (long-lived) |
| `secret_id` | `secrets/services/<service>/secret_id` | AppRole credential (**sensitive**) |

### Option 1: SSH + shell script (recommended starting point)

Best for small deployments with a handful of service machines. The
example below uses `--artifact`, the recommended invocation that avoids
exposing sensitive tokens in shell command lines and `ps` output.

```bash
#!/usr/bin/env bash
set -euo pipefail

SERVICE=edge-remote
CONTROL_SECRETS=./secrets
REMOTE_HOST=edge-node-02
REMOTE_USER=deploy
REMOTE_BASE=/srv/bootroot
ARTIFACT="$CONTROL_SECRETS/remote-bootstrap/services/$SERVICE/bootstrap.json"

# 1. Register the service on the control node
bootroot service add \
  --service-name "$SERVICE" \
  --deploy-type daemon \
  --delivery-mode remote-bootstrap \
  --hostname "$REMOTE_HOST" \
  --domain trusted.domain \
  --agent-config "$REMOTE_BASE/agent.toml" \
  --cert-path "$REMOTE_BASE/certs/$SERVICE.crt" \
  --key-path "$REMOTE_BASE/certs/$SERVICE.key" \
  --root-token "$OPENBAO_ROOT_TOKEN"

# 2. Create the destination directory and ship the artifact + role_id
ssh "$REMOTE_USER@$REMOTE_HOST" \
  mkdir -p "$REMOTE_BASE/secrets/services/$SERVICE"

scp -p \
  "$ARTIFACT" \
  "$CONTROL_SECRETS/services/$SERVICE/role_id" \
  "$REMOTE_USER@$REMOTE_HOST:$REMOTE_BASE/secrets/services/$SERVICE/"

# 3. Validate schema_version before running bootstrap
if ! jq -e '.schema_version == 2' "$ARTIFACT" > /dev/null; then
  echo "ERROR: unsupported schema_version in $ARTIFACT" >&2
  exit 1
fi

# 4. Run bootstrap on the remote host using --artifact
#    The artifact carries the wrap_token; bootroot-remote unwraps it
#    to obtain secret_id at runtime.
ssh "$REMOTE_USER@$REMOTE_HOST" \
  bootroot-remote bootstrap \
    --artifact "$REMOTE_BASE/secrets/services/$SERVICE/bootstrap.json" \
    --output json
```

> **Note:** With wrapping enabled (the default), `bootstrap.json`
> contains a `wrap_token` and is a **sensitive credential file**. Apply
> the same handling as `secret_id`: restrict file permissions, transfer
> over encrypted channels, and delete from the control node after
> delivery if your threat model requires it.
>
> If wrapping is disabled (`--no-wrap`), you must also copy
> `secret_id` to the remote host and can use per-field CLI flags
> instead of `--artifact` for backward compatibility.

### Option 2: systemd-credentials (`--no-wrap`)

> **Legacy / backward-compatible path.** This option uses per-field CLI
> flags and a raw `secret_id` file. It applies when wrapping is disabled
> (`--no-wrap` on `bootroot service add`). For new deployments, prefer
> Option 1 with `--artifact` and wrapping enabled (the default).

For single-host setups where the secret should never hit a plain filesystem.
Use `systemd-creds encrypt` on the control node and `LoadCredential=` in
the service unit on the remote host.

```ini
# /etc/systemd/system/bootroot-remote-bootstrap.service
[Service]
Type=oneshot
LoadCredential=secret_id:/etc/credstore/bootroot-edge-remote-secret-id
ExecStart=/usr/local/bin/bootroot-remote bootstrap \
    --openbao-url https://openbao.internal:8200 \
    --service-name edge-remote \
    --secret-id-path %d/secret_id \
    --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id \
    --eab-file-path /srv/bootroot/secrets/services/edge-remote/eab.json \
    --agent-config-path /srv/bootroot/agent.toml \
    --agent-server https://stepca.internal:9000/acme/acme/directory \
    --agent-domain trusted.domain \
    --agent-responder-url http://responder.internal:8080 \
    --profile-hostname edge-node-02 \
    --profile-cert-path /srv/bootroot/certs/edge-remote.crt \
    --profile-key-path /srv/bootroot/certs/edge-remote.key \
    --ca-bundle-path /srv/bootroot/certs/ca-bundle.pem \
    --output json
```

### Option 3: Ansible (`--no-wrap`)

> **Legacy / backward-compatible path.** This option uses per-field CLI
> flags and copies a raw `secret_id` file. It applies when wrapping is
> disabled (`--no-wrap` on `bootroot service add`). For new deployments,
> prefer Option 1 with `--artifact` and wrapping enabled (the default).
> To adapt this playbook for the wrapped flow, copy `bootstrap.json`
> instead of `secret_id` and invoke with `--artifact`.

For larger fleets with existing configuration management.

```yaml
# playbook: bootroot-remote-bootstrap.yml
- name: Bootstrap remote service via bootroot-remote
  hosts: edge_nodes
  become: true
  vars:
    service_name: edge-remote
    control_secrets: ./secrets
    remote_base: /srv/bootroot
    # Required: set these to remote-reachable endpoints.
    # The artifact may contain localhost placeholders that are only
    # valid on the control node.
    agent_server: https://stepca.internal:9000/acme/acme/directory
    agent_responder_url: http://responder.internal:8080
  tasks:
    - name: Read bootstrap artifact from control node
      ansible.builtin.slurp:
        src: "{{ control_secrets }}/remote-bootstrap/services/{{ service_name }}/bootstrap.json"
      delegate_to: localhost
      become: false
      register: artifact_b64

    - name: Parse bootstrap artifact
      ansible.builtin.set_fact:
        artifact: "{{ artifact_b64.content | b64decode | from_json }}"

    - name: Validate schema_version
      ansible.builtin.assert:
        that:
          - artifact.schema_version == 2
        fail_msg: >-
          Unsupported schema_version {{ artifact.schema_version }};
          this playbook supports version 2 only.

    - name: Ensure secrets directory
      ansible.builtin.file:
        path: "{{ remote_base }}/secrets/services/{{ service_name }}"
        state: directory
        mode: "0700"

    - name: Copy role_id
      ansible.builtin.copy:
        src: "{{ control_secrets }}/services/{{ service_name }}/role_id"
        dest: "{{ artifact.role_id_path }}"
        mode: "0600"

    - name: Copy secret_id
      ansible.builtin.copy:
        src: "{{ control_secrets }}/services/{{ service_name }}/secret_id"
        dest: "{{ artifact.secret_id_path }}"
        mode: "0600"

    - name: Build optional flags
      ansible.builtin.set_fact:
        instance_id_flag: >-
          {{ '--profile-instance-id ' ~ artifact.profile_instance_id
             if artifact.profile_instance_id | default('') | length > 0
             else '' }}

    - name: Run bootroot-remote bootstrap
      ansible.builtin.command:
        cmd: >-
          bootroot-remote bootstrap
          --openbao-url {{ artifact.openbao_url }}
          --kv-mount {{ artifact.kv_mount }}
          --service-name {{ artifact.service_name }}
          --role-id-path {{ artifact.role_id_path }}
          --secret-id-path {{ artifact.secret_id_path }}
          --eab-file-path {{ artifact.eab_file_path }}
          --agent-config-path {{ artifact.agent_config_path }}
          --agent-email {{ artifact.agent_email }}
          --agent-server {{ agent_server }}
          --agent-domain {{ artifact.agent_domain }}
          --agent-responder-url {{ agent_responder_url }}
          --profile-hostname {{ artifact.profile_hostname }}
          {{ instance_id_flag }}
          --profile-cert-path {{ artifact.profile_cert_path }}
          --profile-key-path {{ artifact.profile_key_path }}
          --ca-bundle-path {{ artifact.ca_bundle_path }}
          --output json
      changed_when: true
```

### Option 4: cloud-init (`--no-wrap`)

> **Legacy / backward-compatible path.** This option uses per-field CLI
> flags and writes a raw `secret_id` into cloud-init user data. It
> applies when wrapping is disabled (`--no-wrap` on
> `bootroot service add`). For new deployments, prefer Option 1 with
> `--artifact` and wrapping enabled (the default). With wrapping, embed
> `bootstrap.json` in `write_files` and invoke with `--artifact`.

For first-boot provisioning of cloud VMs.

```yaml
#cloud-config
write_files:
  - path: /srv/bootroot/secrets/services/edge-remote/role_id
    permissions: "0600"
    content: |
      <ROLE_ID_VALUE>
  - path: /srv/bootroot/secrets/services/edge-remote/secret_id
    permissions: "0600"
    content: |
      <SECRET_ID_VALUE>
runcmd:
  - >-
    /usr/local/bin/bootroot-remote bootstrap
    --openbao-url https://openbao.internal:8200
    --service-name edge-remote
    --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id
    --secret-id-path /srv/bootroot/secrets/services/edge-remote/secret_id
    --eab-file-path /srv/bootroot/secrets/services/edge-remote/eab.json
    --agent-config-path /srv/bootroot/agent.toml
    --agent-server https://stepca.internal:9000/acme/acme/directory
    --agent-domain trusted.domain
    --agent-responder-url http://responder.internal:8080
    --profile-hostname edge-node-02
    --profile-cert-path /srv/bootroot/certs/edge-remote.crt
    --profile-key-path /srv/bootroot/certs/edge-remote.key
    --ca-bundle-path /srv/bootroot/certs/ca-bundle.pem
    --output json
```

## Wrap token recovery

When wrapping is enabled (the default), `bootstrap.json` contains a
single-use `wrap_token` with a limited TTL (default 30 minutes). Two
failure modes can occur during `bootroot-remote bootstrap --artifact`:

### Expired wrap token

The `wrap_token` TTL has elapsed before `bootroot-remote` could unwrap
it. `bootroot-remote` detects this by comparing `wrap_expires_at` with
the current time and reports an **expired** error with recovery
instructions.

**Recovery:**

1. Re-run `bootroot service add` with the same arguments on the control
   node. This is an idempotent rerun: it issues a fresh `secret_id` with
   wrapping and regenerates the bootstrap artifact with a new
   `wrap_token`.
2. Ship the updated `bootstrap.json` to the remote host.
3. Run `bootroot-remote bootstrap --artifact <path>`.

### Already-unwrapped wrap token

The token was already consumed. This means a third party unwrapped it
before the legitimate `bootroot-remote` call. `bootroot-remote` flags
this as a **potential security incident**.

**Recovery:**

1. Investigate who or what consumed the token.
2. Rotate the service's `secret_id` immediately:
   `bootroot rotate approle-secret-id --service-name <service>`.
3. Re-run `bootroot service add` with the same arguments to generate a
   new `wrap_token`.
4. Ship the artifact and run `bootroot-remote bootstrap` on the remote
   host.

## Force-reissue (control plane → remote agent)

The control plane has no push channel into the remote host, so
`bootroot rotate force-reissue` cannot delete the remote's cert files
directly. Instead, for `--delivery-mode remote-bootstrap` services, the
command writes a versioned reissue request to OpenBao KV at
`{kv_mount}/data/bootroot/services/<service>/reissue`:

```json
{
  "requested_at": "2026-04-19T12:34:56Z",
  "requester": "<operator label>"
}
```

The remote `bootroot-agent` consumes the request through a fast-poll
loop that authenticates via AppRole and polls each registered service's
reissue path on `fast_poll_interval` (default `30s`). Whenever the KV
v2 version is newer than the version the agent last applied (tracked
per-service in `state_path`), the agent triggers an immediate ACME
renewal and writes back `completed_at` and `completed_version` so the
control plane can observe end-to-end latency.

The loop is driven by the `[openbao]` section of `agent.toml`. This
section is **required** on every remote-bootstrap host: without it the
agent has no consumer for the control plane's KV request, and a
`force-reissue` would sit queued until the certificate neared natural
expiry. `bootroot-remote bootstrap` auto-populates the connection
fields (`url`, `kv_mount`, `role_id_path`, `secret_id_path`,
`ca_bundle_path`) on every run, so operators do not normally edit it
by hand. If a legacy remote upgrades bootroot without rerunning
`bootroot-remote bootstrap`, the section will be absent and
`force-reissue` requests will not be observed until the next bootstrap
populates it.

```toml
# agent.toml — auto-populated by `bootroot-remote bootstrap`
[openbao]
url = "https://openbao.internal:8200"
kv_mount = "secret"
role_id_path = "/etc/bootroot/role_id"
secret_id_path = "/etc/bootroot/secret_id"
ca_bundle_path = "/etc/bootroot/ca-bundle.pem"   # required for https://
fast_poll_interval = "30s"                        # optional; default 30s
state_path = "/etc/bootroot/bootroot-agent-state.json" # provisioned by bootstrap
```

`state_path` holds the agent's `last_reissue_seen_version`,
`in_flight_renewals`, and `pending_completion_writes` maps across
restarts — the state this feature relies on to avoid duplicate
renewals and to retry completion acknowledgements. Bootstrap
provisions it to an absolute path adjacent to `agent.toml` whenever
the current value is missing *or relative*, so the fast-poll state
does not end up at a cwd-relative location under a systemd-style
supervisor (where cwd is not contractually writable or stable).
Rerunning `bootroot-remote bootstrap` therefore repairs a legacy
config whose `state_path` was the in-tree relative default, matching
the remediation hint that config validation prints on startup.
Operators can override with any absolute path; subsequent bootstrap
reruns preserve a custom absolute value. Config validation
additionally rejects a relative `state_path` (including the case
where it is omitted entirely and falls through to an in-tree
default), so a misconfiguration is caught at `bootroot-agent`
startup instead of silently running with a fragile state file.

This mechanism uses the same AppRole credentials the remote agent
already has, adds one KV read per service per `fast_poll_interval`, and
shrinks worst-case force-reissue latency from one `check_interval`
(default 1h) to roughly one fast-poll interval.

Operators can pass `--wait` (and optionally `--wait-timeout`) on
`bootroot rotate force-reissue` to block until the remote agent reports
completion. A `--wait` timeout is not an error — the request stays
queued and is applied on the next fast-poll tick.

When a remote host runs multiple `[[profiles]]` for the same
`service_name` (e.g. several instances of one service on the same
machine), each fast-poll tick fans the renewal trigger out across
every matching profile before marking the KV version consumed, so a
single force-reissue rotates every instance. If any profile in the
fan-out fails, the profiles that already succeeded for that request
are recorded as per-service `in_flight_renewals` progress in
`state_path`. The next tick retries *only* the failed sibling(s)
against the same KV version — the profiles that already renewed are
skipped and are not forced through a second renewal. The version is
marked consumed only once every profile has succeeded; stale
per-profile progress is dropped automatically when a newer reissue
request supersedes it or when the request disappears from KV.

Operators who want to pin `--wait` to a specific KV version should
rely on the version returned by the publish POST: `rotate force-reissue`
captures it directly from the write response rather than doing a
follow-up GET, so the agent's own completion write cannot advance
the metadata version in the interim and cause `--wait` to hang.

If the remote agent renews the certificate but the subsequent write
of `completed_at` back to OpenBao fails (transient KV outage, network
blip, etc.), it persists a `pending_completion_writes` entry in
`state_path` and retries just the completion write on the next tick.
This avoids leaving `bootroot rotate force-reissue --wait` stuck
without an acknowledgement after the certificate has actually been
rotated. Pending entries are dropped automatically when a newer
reissue request supersedes them or when the request is removed from
KV entirely.

## Idempotent service add rerun

Re-running `bootroot service add` on an existing `remote-bootstrap`
service with the same arguments is safe. When wrapping is enabled (the
default), the rerun issues a fresh `secret_id` with wrapping and writes
an updated `bootstrap.json` containing a new `wrap_token`. The operator
must transfer the updated artifact to the remote host and re-run
`bootroot-remote bootstrap`.

If the rerun arguments differ only in policy fields (`--secret-id-ttl`,
`--secret-id-wrap-ttl`, `--no-wrap`), the command rejects the request
and directs the operator to use `bootroot service update` instead.

## `secret_id` hygiene checklist

The `secret_id` is the most sensitive artifact in the remote-bootstrap flow.
Treat it as a short-lived credential:

- **File permissions**: `0600`, owned by the service user.
    `bootroot service add` already writes it with restricted permissions.
- **Never log or commit**: exclude the file from version control
    (`.gitignore`) and ensure deployment scripts do not echo it to stdout
    or write it to log files.
- **Remove from control node after delivery**: once the `secret_id` has
    been shipped to the remote host, delete the local copy.
- **Short TTL / response wrapping**: use `--secret-id-ttl` on
    `bootroot service add` to limit `secret_id` lifetime, and keep
    response wrapping enabled (the default) so the bootstrap artifact
    carries a single-use `wrap_token` instead of the raw `secret_id`.
    This keeps wrap tokens out of command lines and `ps` output, and
    shortens the remote-transfer exposure window to seconds. Note that
    the control node still writes a raw `secret_id` to
    `secrets/services/<service>/secret_id` for local operations —
    protect and delete this file after delivery.
- **Rotation**: after `bootroot rotate approle-secret-id` on the control
    node, deliver the new `secret_id` via
    `bootroot-remote apply-secret-id` on the service machine. See
    [Operations](operations.md) for the rotation workflow.

## Network requirements

The remote host must have network connectivity to the following endpoints:

| Endpoint | Protocol | Purpose |
| --- | --- | --- |
| OpenBao API (`--openbao-url`) | HTTPS | Pull secrets (`secret_id`, responder HMAC, trust bundle, and EAB when present) during bootstrap |
| step-ca ACME directory (`--agent-server`) | HTTPS | Certificate issuance and renewal by `bootroot-agent` |
| HTTP-01 responder (`--agent-responder-url`) | HTTP | Publish ACME challenge tokens for domain validation |

The `--agent-server` and `--agent-responder-url` values in the bootstrap
artifact default to localhost placeholders. Replace them with
remote-reachable endpoints before running on a separate service machine.

!!! warning
    The automatic HTTP-01 DNS alias registration (added in the current
    unreleased version) only covers traffic between bundled containers on
    the Docker bridge network. For remote hosts, configure real DNS records
    or `/etc/hosts` entries so that the service's SAN resolves correctly
    from both the responder and the CA's perspective.

## `RemoteBootstrapArtifact` schema reference

The JSON artifact written to
`secrets/remote-bootstrap/services/<service>/bootstrap.json` follows a
versioned schema. Automation should check `schema_version` before parsing.

Current version: **2**

| Field | Type | Description | Consumed by |
| --- | --- | --- | --- |
| `schema_version` | `u32` | Schema version number. Bumped on breaking changes. | Parser pre-check |
| `openbao_url` | `string` | OpenBao API URL | `--openbao-url` |
| `kv_mount` | `string` | OpenBao KV v2 mount path | `--kv-mount` |
| `service_name` | `string` | Registered service name | `--service-name` |
| `role_id_path` | `string` | Path to AppRole `role_id` file on the remote host | `--role-id-path` |
| `secret_id_path` | `string` | Path to AppRole `secret_id` file on the remote host | `--secret-id-path` |
| `eab_file_path` | `string` | Path to EAB credentials JSON file. Bootroot writes this file only when the operator has provisioned EAB credentials in OpenBao KV. When the KV entry is absent, bootroot removes any stale `eab.json` left by a prior bootstrap so `bootroot-agent --eab-file` cannot forward obsolete credentials: the eab apply step reports `applied` when a stale file was removed and `skipped` when no file existed to begin with. | `--eab-file-path` |
| `agent_config_path` | `string` | Path to `agent.toml` on the remote host | `--agent-config-path` |
| `ca_bundle_path` | `string` | Path to CA trust bundle PEM file on the remote host | `--ca-bundle-path` |
| `ca_bundle_pem` | `string` | Inline PEM content of the control-plane CA trust anchor. Written to `ca_bundle_path` during bootstrap. When `openbao_url` uses HTTPS, this CA is used as the TLS trust anchor instead of the system trust store. Shared primitive — also consumed by the http01 admin client (#514). | Internal (TLS trust) |
| `openbao_agent_config_path` | `string` | Path to OpenBao Agent config (HCL) | Internal |
| `openbao_agent_template_path` | `string` | Path to OpenBao Agent template | Internal |
| `openbao_agent_token_path` | `string` | Path to OpenBao Agent token file | Internal |
| `agent_email` | `string` | ACME account email | `--agent-email` |
| `agent_server` | `string` | step-ca ACME directory URL (localhost placeholder by default) | `--agent-server` |
| `agent_domain` | `string` | Domain for certificate SAN | `--agent-domain` |
| `agent_responder_url` | `string` | HTTP-01 responder URL (localhost placeholder by default) | `--agent-responder-url` |
| `profile_hostname` | `string` | Hostname for the agent profile | `--profile-hostname` |
| `profile_instance_id` | `string` | Instance identifier (may be empty) | `--profile-instance-id` |
| `profile_cert_path` | `string` | Output path for the issued certificate | `--profile-cert-path` |
| `profile_key_path` | `string` | Output path for the private key | `--profile-key-path` |
| `post_renew_hooks` | `array` | Post-renew hook entries (omitted when empty). Each entry has `command`, `args`, `timeout_secs`, `on_failure`. | `--post-renew-command` and related flags |
| `wrap_token` | `string?` | Response-wrapped `secret_id` token (omitted when wrapping is disabled via `--no-wrap`). Sensitive — treat as a credential. | `bootroot-remote` unwrap path |
| `wrap_expires_at` | `string?` | RFC 3339 timestamp when `wrap_token` expires (omitted when wrapping is disabled). | `bootroot-remote` unwrap error classification |

### Version history

| Version | Change |
| --- | --- |
| 2 | Added required `ca_bundle_pem` field (inline PEM of the control-plane CA anchor). |
| 1 | Initial schema. |

### Versioning rules

- **Breaking change** (field removed, renamed, or type changed): bump
    `schema_version`.
- **Additive change** (new optional field with `skip_serializing_if`):
    no bump required. Existing parsers ignore unknown keys.
- **Consumer contract**: check `schema_version >= 1` and
    `schema_version <= <max supported>` before accessing fields. Fail
    explicitly on unsupported versions. `bootroot-remote` enforces this
    check automatically when using `--artifact`.
