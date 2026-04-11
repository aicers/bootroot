# CLI Examples

This section walks through a **production-like flow** using the `bootroot`
CLI. Outputs include as much of the CLI result as possible, and your
environment may differ.

## Prerequisites

- Docker/Docker Compose installed
- Ports 80/443/8200/9000/5432/8080 available

The Docker daemon should be configured to **start on reboot**. bootroot's
containers use restart policies, but Docker itself must be managed by the OS
(for example, via systemctl).

> Note: The example assumes OpenBao/PostgreSQL/HTTP-01 responder run on the
> **same machine as step-ca**.

## 1) infra install

```bash
bootroot infra install
```

This is the first command to run on a fresh clone. It generates `.env` with a
random PostgreSQL password, creates `secrets/` and `certs/` directories,
pulls/builds images, and starts Docker Compose services. No manual environment
variable setup or image prep is needed.

Sample output:

```text
bootroot infra up: readiness summary
- openbao: running (health: healthy)
- postgres: running (health: healthy)
- bootroot-http01: running (health: healthy)
- step-ca: not checked (will be bootstrapped by init)
bootroot infra install: completed
```

To restart an already-configured environment later, use `bootroot infra up`
instead.

## 2) init

> Minimum input summary:
>
> - If OpenBao is **not initialized**, initialize it first and use the
>   generated `root token` and `unseal keys`
> - If OpenBao is **initialized but sealed**, you need `unseal keys`
> - After `bootroot infra install`, DB credentials come from `.env`
>   automatically — use `--enable db-provision` to auto-provision the
>   PostgreSQL role and database (no manual `--db-dsn` needed)
> - step-ca password can be auto-generated with `--enable auto-generate`
> - `--responder-url` enables responder validation (otherwise skipped)
> - step-ca bootstrap (`step ca init`) runs automatically inside `init`

```bash
bootroot init --enable auto-generate,db-provision \
  --summary-json ./tmp/init-summary.json \
  --responder-url "http://localhost:8080"
```

Sample dialog/output (full):

```text
OpenBao root token: ********
OpenBao unseal key (comma-separated): key-1,key-2,key-3
Overwrite password.txt? [y/N]: y
Overwrite ca.json? [y/N]: y
Proceed with init? [y/N]: y

bootroot init: summary
- OpenBao URL: http://localhost:8200
- KV mount: secret
- Secrets dir: secrets
- OpenBao init: completed (shares=5, threshold=3)
- root token: ********
- unseal key 1: ********
- unseal key 2: ********
- unseal key 3: ********
- step-ca password: ********
- db dsn: ********
- db provision: completed
- responder hmac: ********
- eab: not configured
- step-ca init: completed
- responder check: ok
- db host resolution: localhost -> postgres
- OpenBao KV paths:
  - bootroot/stepca/password
  - bootroot/stepca/db
  - bootroot/http01/hmac
  - bootroot/ca
  - bootroot/agent/eab
- summary json: ./tmp/init-summary.json
Save unseal keys to file for automatic unseal? [y/N]: y
next steps:
  - Attach AppRole/secret_id to the service.
  - Prepare OpenBao Agent/bootroot-agent execution.
```

For automation, read sensitive fields (for example root token) from
`./tmp/init-summary.json` instead of parsing human-readable text output.

## 3) service add

`--delivery-mode` in `bootroot service add` selects how service configuration is
applied.

- default: `local-file`
- `local-file`: use when the service is added on the **same machine** as
  step-ca/OpenBao/responder
- `remote-bootstrap`: use when the service is added on a **different machine**
  from step-ca/OpenBao/responder
- `--dry-run`, `--print-only`: both run in preview mode and do not write files
  or state.
- To show trust snippets in preview, also provide `--root-token`.
- If preview runs without `--root-token`, the CLI prints why trust snippets are
  unavailable.

Sections 3-1 and 3-2 below are default (`local-file`) examples, and 3-3 is a
`remote-bootstrap` example.

> Note: `secrets/...` paths in sample outputs assume the default
> `--secrets-dir secrets`. If you use another secrets root in production
> (for example `/etc/bootroot/secrets`), read them with the same relative
> structure.

### 3-1) local-file (default): daemon service

```bash
bootroot service add \
  --service-name edge-proxy \
  --deploy-type daemon \
  --hostname edge-node-01 \
  --domain trusted.domain \
  --agent-config /etc/bootroot/agent.toml \
  --cert-path /etc/bootroot/certs/edge-proxy.crt \
  --key-path /etc/bootroot/certs/edge-proxy.key \
  --instance-id 001 \
  --root-token <OPENBAO_ROOT_TOKEN>
```

Sample dialog/output (full):

```text
OpenBao root token: ********

bootroot service add: plan
- service name: edge-proxy
- deploy type: daemon
- hostname: edge-node-01
- domain: trusted.domain
- instance_id: 001
- agent config: /etc/bootroot/agent.toml
- cert path: /etc/bootroot/certs/edge-proxy.crt
- key path: /etc/bootroot/certs/edge-proxy.key
next steps:
  - AppRole: bootroot-service-edge-proxy
  - secret_id path: secrets/services/edge-proxy/secret_id
  - OpenBao path: bootroot/services/edge-proxy
  - OpenBao Agent (per-service instance):
    - config: secrets/openbao/services/edge-proxy/agent.hcl
    - role_id file: secrets/services/edge-proxy/role_id
    - secret_id file: secrets/services/edge-proxy/secret_id
    - ensure secrets/services/edge-proxy is 0700 and
      role_id/secret_id files are 0600
    - run the service-specific OpenBao Agent on the host with
      secrets/openbao/services/edge-proxy/agent.hcl
  - Add profile for edge-proxy (instance_id=001, hostname=edge-node-01,
    domain=trusted.domain, cert=/etc/bootroot/certs/edge-proxy.crt,
    key=/etc/bootroot/certs/edge-proxy.key) to /etc/bootroot/agent.toml
    and reload bootroot-agent.
```

The generated `agent.toml` is a complete, ready-to-run config: it includes
the managed profile, `[trust]` section, top-level `domain` (from `--domain`),
and `[acme].http_responder_hmac` (from the responder HMAC stored in OpenBao).
The HTTP-01 validation FQDN is also registered as a DNS alias on
`bootroot-http01` automatically.
No manual editing is required before running `bootroot-agent`.

In current CLI output, the same information is also grouped under
`Bootroot-managed` and `Operator-managed (required/recommended/optional)` labels
to make ownership boundaries explicit.

Example (label-focused):

```text
Bootroot-managed:
- auto-applied bootroot-agent config: ...
- auto-applied OpenBao Agent config: ...

Operator-managed (required):
- run OpenBao Agent
- run/reload bootroot-agent

Operator-managed (optional):
- apply manual trust pin/override instead of auto-applied trust values
```

### 3-2) local-file (default): docker service

```bash
bootroot service add \
  --service-name web-app \
  --deploy-type docker \
  --hostname web-01 \
  --domain trusted.domain \
  --agent-config /srv/bootroot/agent.toml \
  --cert-path /srv/bootroot/certs/web-app.crt \
  --key-path /srv/bootroot/certs/web-app.key \
  --instance-id 001 \
  --container-name web-app \
  --root-token <OPENBAO_ROOT_TOKEN>
```

Sample dialog/output (full):

```text
OpenBao root token: ********

next steps:
  - Run sidecar for web-app (container=web-app, instance_id=001,
    hostname=web-01, domain=trusted.domain) with config
    /srv/bootroot/agent.toml, AppRole bootroot-service-web-app, and
    secret_id file secrets/services/web-app/secret_id.
```

### 3-3) remote-bootstrap delivery mode + one-shot bootstrap

Control node onboarding (artifact generation):

```bash
bootroot service add \
  --service-name edge-remote \
  --deploy-type daemon \
  --delivery-mode remote-bootstrap \
  --hostname edge-node-02 \
  --domain trusted.domain \
  --agent-config /srv/bootroot/agent.toml \
  --cert-path /srv/bootroot/certs/edge-remote.crt \
  --key-path /srv/bootroot/certs/edge-remote.key \
  --instance-id 101 \
  --root-token <OPENBAO_ROOT_TOKEN>
```

Remote node one-shot bootstrap:

```bash
bootroot-remote bootstrap \
  --openbao-url http://127.0.0.1:8200 \
  --kv-mount secret \
  --service-name edge-remote \
  --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id \
  --secret-id-path /srv/bootroot/secrets/services/edge-remote/secret_id \
  --eab-file-path /srv/bootroot/secrets/services/edge-remote/eab.json \
  --agent-config-path /srv/bootroot/agent.toml \
  --agent-email admin@example.com \
  --agent-server https://stepca.internal:9000/acme/acme/directory \
  --agent-domain trusted.domain \
  --agent-responder-url http://responder.internal:8080 \
  --profile-hostname edge-node-02 \
  --profile-instance-id 101 \
  --profile-cert-path /srv/bootroot/certs/edge-remote.crt \
  --profile-key-path /srv/bootroot/certs/edge-remote.key \
  --ca-bundle-path /srv/bootroot/certs/ca-bundle.pem \
  --summary-json /srv/bootroot/tmp/edge-remote-summary.json \
  --output json
```

`bootroot-remote bootstrap` performs a one-shot pull and apply of the service
configuration bundle (`secret_id`, `eab`, `responder_hmac`, `trust`).
In operations, start from the `remote run command template` printed by
`bootroot service add`, then replace `--agent-server` and
`--agent-responder-url` with remote-reachable endpoints such as
`stepca.internal` and `responder.internal`.

After secret_id rotation on the control node, deliver the new secret_id to the
remote node:

```bash
bootroot-remote apply-secret-id \
  --openbao-url http://127.0.0.1:8200 \
  --kv-mount secret \
  --service-name edge-remote \
  --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id \
  --secret-id-path /srv/bootroot/secrets/services/edge-remote/secret_id
```

## 4) DNS resolution for HTTP-01 validation

`bootroot service add` automatically registers each service's validation FQDN
(`<instance_id>.<service_name>.<hostname>.<domain>`) as a Docker network alias
on the `bootroot-http01` container. This lets step-ca resolve the FQDN to the
responder without any manual configuration.

If `bootroot-http01` is restarted (e.g. `docker compose down` / `up`),
`bootroot infra up` replays all aliases from `state.json` automatically.

For non-Compose environments or when manual resolution is needed, add
`/etc/hosts` entries inside the step-ca container:

```bash
RESPONDER_IP="$(docker inspect -f \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  bootroot-http01)"
docker exec bootroot-ca sh -c \
  "printf '%s %s\n' \"$RESPONDER_IP\" \
  '001.edge-proxy.edge-node-01.trusted.domain' >> /etc/hosts"
```

## 5) service verify

```bash
bootroot verify --service-name edge-proxy
```

To verify DB connectivity/auth as well:

```bash
bootroot verify --service-name edge-proxy --db-check
```

Sample dialog/output (full):

```text
bootroot verify: summary
- service name: edge-proxy
- result: ok
```

`bootroot verify` performs a one-shot issuance check. For **continuous
renewal**, run bootroot-agent in daemon mode (without `--oneshot`).

## 6) Run services (continuous mode)

“Continuous mode” means the daemon keeps running to renew certificates
periodically, rather than a one-shot verification run.

daemon:

- bootroot-agent: daemon mode
- OpenBao Agent: per-service daemon

bootroot-agent runs **one per machine**, not per service. Update `agent.toml`
when adding profiles and reload the daemon. Configure systemd so the process
restarts automatically (set `Restart=always` or `on-failure`).

```bash
openbao agent -config /etc/bootroot/secrets/openbao/services/edge-proxy/agent.hcl
```

```bash
bootroot-agent --config /etc/bootroot/agent.toml
```

Sample output:

```text
Loaded 1 profile(s).
Issuing certificate for 001.edge-proxy.edge-node-01.trusted.domain
Certificate issued successfully.
```

docker:

- OpenBao Agent: sidecar (per-service Docker container)
- bootroot-agent: sidecar (per-service Docker container)

Docker services may also use the shared bootroot-agent daemon, but this is
supported and not recommended. The sidecar pattern is preferred for isolation
and lifecycle alignment.

```bash
AGENT_HCL=/srv/bootroot/secrets/openbao/services/web-app/agent.hcl
docker run --rm \
  --name openbao-agent-web-app \
  -v "$AGENT_HCL":/app/agent.hcl:ro \
  -v /srv/bootroot/secrets:/app/secrets \
  openbao/bao:latest \
  agent -config /app/agent.hcl
```

```bash
docker run --rm \
  --name web-app \
  -v /srv/bootroot/agent.toml:/app/agent.toml:ro \
  -v /srv/bootroot/certs:/app/certs \
  <bootroot-agent-image> \
  bootroot-agent --config /app/agent.toml
```

Sample output:

```text
Loaded 1 profile(s).
Issuing certificate for 001.web-app.web-01.trusted.domain
Certificate issued successfully.
```

## 7) Secret rotation (examples)

bootroot provides rotation commands for **secrets** (step-ca password, EAB,
DB credentials, HMAC, AppRole). **Certificate renewal** is handled by
`bootroot-agent`.

Example that rotates all secrets:

```bash
bootroot rotate stepca-password
bootroot rotate eab
bootroot rotate db \
  --db-admin-dsn "postgresql://admin:***@127.0.0.1:5432/postgres"
bootroot rotate responder-hmac
bootroot rotate openbao-recovery --rotate-root-token
bootroot rotate approle-secret-id --service-name edge-proxy
bootroot rotate approle-secret-id --service-name web-app

# Sync CA trust data to OpenBao and all services
bootroot rotate trust-sync

# Force certificate reissue for a specific service
bootroot rotate force-reissue --service-name edge-proxy
```

Rotate OpenBao recovery credentials manually (unseal keys + root token):

```bash
bootroot rotate \
  --openbao-url http://localhost:8200 \
  --root-token "$OPENBAO_ROOT_TOKEN" \
  --yes \
  openbao-recovery \
  --rotate-unseal-keys \
  --rotate-root-token \
  --unseal-key-file ./secure/openbao-unseal-keys.txt \
  --output ./secure/openbao-recovery-rotated.json
```

CA key rotation (intermediate-only):

```bash
bootroot rotate \
  --compose-file docker-compose.yml \
  --openbao-url http://localhost:8200 \
  --auth-mode approle \
  --approle-role-id "$ROTATE_ROLE_ID" \
  --approle-secret-id "$ROTATE_SECRET_ID" \
  --yes \
  ca-key --cleanup
```

CA key rotation (full — root + intermediate):

```bash
bootroot rotate \
  --compose-file docker-compose.yml \
  --openbao-url http://localhost:8200 \
  --auth-mode approle \
  --approle-role-id "$ROTATE_ROLE_ID" \
  --approle-secret-id "$ROTATE_SECRET_ID" \
  --yes \
  ca-key --full --cleanup
```

After CA key rotation, force-reissue certificates for all services:

```bash
bootroot rotate force-reissue --service-name edge-proxy
bootroot rotate force-reissue --service-name web-app
```

Scheduled execution (cron example, script to run all rotations):

```bash
#!/usr/bin/env bash
set -euo pipefail

bootroot rotate stepca-password --yes
bootroot rotate eab --yes
bootroot rotate db --yes \
  --db-admin-dsn "postgresql://admin:***@127.0.0.1:5432/postgres"
bootroot rotate responder-hmac --yes
```

```crontab
# every day at 03:00
0 3 * * * /usr/local/bin/bootroot-rotate-all.sh
```

> Adjust schedules and targets to match your policy.

## 8) Monitoring (examples)

Start monitoring with LAN-only access:

```bash
bootroot monitoring up --profile lan --grafana-admin-password admin
```

Start monitoring with public access:

```bash
bootroot monitoring up --profile public --grafana-admin-password admin
```

Check status:

```bash
bootroot monitoring status
```

Access URLs:

- `lan`: `http://<lan-ip>:3000` (or `http://127.0.0.1:3000` if using default)
- `public`: `http://<public-ip>:3000`

Reset Grafana admin password and restart:

```bash
bootroot monitoring down --reset-grafana-admin-password
bootroot monitoring up --profile lan --grafana-admin-password newpass
```
