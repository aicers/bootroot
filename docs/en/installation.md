# Installation

This section explains installation and placement principles for step-ca,
PostgreSQL, OpenBao Agent, bootroot-agent, and the HTTP-01 responder.
In real operations you will typically use `bootroot` CLI automation, but this
page is intentionally written from a **manual (non-CLI) perspective** to improve
understanding.
In other words, it helps you understand what the CLI automation is doing under
the hood.

For automated command flow, also see [CLI](cli.md) and
[CLI Examples](cli-examples.md).

Operations policy summary:

- recommended runtime differs by deployment target:
  step-ca/OpenBao/HTTP-01 responder run as independent services
  (Compose or systemd). They are the only components the compose stack
  brings up.
  `bootroot-agent` ships no container image at all: for services added via
  `bootroot service add` it runs as a host daemon (systemd) — including
  when the consuming application itself runs in a container.
- in all paths, always-on/restart/dependency guarantees are operator
  responsibilities.
- bootroot automates config/material generation, but binary installation and
  process lifecycle management remain operator-owned.

## step-ca

### Docker

The repo includes a compose setup that builds step-ca with PostgreSQL support.
This is the easiest path for local or lab usage.

```bash
docker compose up --build -d step-ca
```

#### Initialize step-ca (first run)

The recommended way to perform first-time setup is:

```bash
bootroot infra install
```

This command generates `.env` with a random PostgreSQL password, creates
`secrets/` and `certs/` directories, and brings up Docker Compose services
(including building local images). No manual file creation or editing is
required.

To restart an already-configured environment later, use:

```bash
bootroot infra up
```

After `bootroot infra install`, `bootroot init` handles step-ca bootstrap
automatically (no need to manually run `step ca init`).

**Manual alternative** (for advanced users who need full control):

If you are not using `bootroot infra install`, you can initialize manually:

```bash
mkdir -p secrets
printf "%s" "<your-password>" > secrets/password.txt

# Run init inside a container (example)
docker run --user root --rm -v $(pwd)/secrets:/home/step smallstep/step-ca \
  step ca init \
  --name "Bootroot CA" \
  --provisioner "admin" \
  --dns "localhost,bootroot-ca" \
  --address ":9000" \
  --password-file /home/step/password.txt \
  --provisioner-password-file /home/step/password.txt \
  --acme
```

`<your-password>` protects (encrypts) the CA keys. In production use a strong
password and keep this file out of logs and repositories. In production we
recommend injecting this value via a Secret Manager (for example, OpenBao).

After initialization, these files are created (examples):

- `secrets/config/ca.json`
- `secrets/certs/root_ca.crt`
- `secrets/certs/intermediate_ca.crt`
- `secrets/secrets/root_ca_key`
- `secrets/secrets/intermediate_ca_key`

`bootroot init` stores CA fingerprints in OpenBao, so
`secrets/certs/root_ca.crt` and `secrets/certs/intermediate_ca.crt` must
exist. If they are missing, `bootroot init` will fail.
Because the example mounts `-v $(pwd)/secrets:/home/step`, the files are
created under `/home/step` in the container and appear under `./secrets/` on
the host. Keep them in `./secrets/` so `secrets/config/ca.json` stays valid.

In Bootroot's default deployment, step-ca may present its CA certificate
directly on the HTTPS endpoint. During `bootroot init`, Bootroot stores the CA
bundle and matching SHA-256 fingerprints in OpenBao so bootroot-agent can
later verify that endpoint using this managed trust material.

If using the manual path, update `secrets/config/ca.json` for your
environment:

1. Set `db.type` to `postgresql`
2. Replace `db.dataSource` with the real DSN
3. Restart step-ca

Restart commands:

- Docker Compose:

  ```bash
  docker compose restart step-ca
  ```

- systemd (bare metal):

  ```bash
  sudo systemctl restart step-ca
  ```

`db.dataSource` is the PostgreSQL DSN (Data Source Name). Format:

```text
postgresql://<user>:<password>@<host>:<port>/<db>?sslmode=<mode>
```

Examples:

- Docker Compose:
  `postgresql://step:step-pass@postgres:5432/stepca?sslmode=disable`
- Production (TLS enforced):
  `postgresql://step:<secret>@db.internal:5432/stepca?sslmode=require`

The `sslmode=disable` example is only for the default topology where step-ca
and PostgreSQL stay on the same machine and inside the same local trust
boundary. If PostgreSQL moves to another machine or another network trust
boundary, do not reuse the local-only example. Switch to PostgreSQL TLS with
an appropriate `sslmode`.

**Important**: When step-ca runs in a container, the `db.dataSource` host is
**inside the container network**. The effective host must be the Compose
service name (for example, `postgres`).

In `bootroot init`, `--db-dsn`/`--db-admin-dsn` inputs can use
`localhost`/`127.0.0.1`/`::1`; init normalizes them to `postgres`.
Remote hosts like `db.internal` fail during init.

`<secret>` is your real database password.

`step-pass` is the development default for this repo. It must match
`POSTGRES_PASSWORD` in `.env`, which is why the local/Compose examples use the
same value. In production, replace it with a strong password. In production
we recommend injecting this DB password via a Secret Manager.

Note: automatic DB password generation applies only when `bootroot init` runs
with both `--enable db-provision` and `--enable auto-generate` (or combined as
`--enable db-provision,auto-generate`). In the `--db-dsn` path, the password
embedded in the DSN is used as-is.

Example `.env` (generated automatically by `bootroot infra install`;
manual creation is needed only for the manual alternative path):

```text
POSTGRES_USER=step
POSTGRES_PASSWORD=<random-32-byte-hex>
POSTGRES_DB=stepca
GRAFANA_ADMIN_PASSWORD=admin
```

Choose `sslmode` based on your environment:

- `require`: TLS enabled, but hostname verification is skipped
- `verify-full`: TLS enabled and the server cert and hostname are verified

Selection guide:

- Production / security first: `verify-full`
- Internal test or lab: `require`

When using `bootroot infra install` followed by `bootroot init
--enable db-provision`, the DB DSN is written to `secrets/config/ca.json`
automatically.

### Single-Host Guardrails

When using the non-TLS local model (`sslmode=disable`), bootroot enforces
single-host guardrails:

- PostgreSQL host in DSN must be local-only (`postgres`, `localhost`,
  `127.0.0.1`, or `::1`).
- init summary prints DB host resolution (for example,
  `localhost -> postgres`).
- PostgreSQL port publishing in Compose must stay localhost-bound (for example,
  `127.0.0.1:5433:5432` — the published default; override with
  `POSTGRES_HOST_PORT`), not `0.0.0.0` or bare `5433:5432`.

If these conditions are violated, `bootroot init`, `bootroot infra up`, and
`bootroot rotate db` fail fast.

When moving beyond a single-host trust boundary, switch to TLS-based DB
transport (`sslmode=require` or `sslmode=verify-full`). In other words,
`sslmode=disable` is documented only for the same-machine default topology,
not for split step-ca/PostgreSQL deployments.

### Bare Metal

Bare metal means installing directly on the host OS (no containers).

1. Install step-ca and step-cli (per your OS packaging).
2. Create a working directory, for example `/etc/step-ca`.
3. Run `step ca init` with your desired parameters.
4. Run the service via systemd or a supervisor.

The important outputs are the CA config and keys. The CA config must use
`db.type = "postgresql"` when PostgreSQL is enabled.

## PostgreSQL for step-ca

A durable CA should use PostgreSQL. See the step-ca sections above for DSN
examples and how to update `secrets/config/ca.json`.

## OpenBao Agent

OpenBao Agent renders secrets from OpenBao to files. It serves only the
infrastructure components: step-ca and the HTTP-01 responder use the
`agent.hcl` files produced by `bootroot init`. Services do **not** run a
per-service OpenBao Agent — each service's `bootroot-agent` authenticates
to OpenBao itself and keeps its secrets current via its fast-poll loop
(see [Concepts > Secret delivery flows](concepts.md#secret-delivery-flows)).

### Docker

In the default topology, `bootroot init` enables the two infra agents
(`openbao-agent-stepca`, `openbao-agent-responder`) via compose override —
no manual step is needed.

The raw `docker run` invocations below are kept for reference (e.g.
debugging or environments where the compose-managed agents cannot be
used). Substitute `<network>` with the actual docker network — by
default `<project>_default`, where `<project>` is the
`com.docker.compose.project` label on `bootroot-openbao`. You can
inspect it with:

```bash
docker inspect bootroot-openbao \
  --format '{{index .Config.Labels "com.docker.compose.project"}}'
```

OpenBao Agent for step-ca (example):

```bash
docker run --rm \
  --name openbao-agent-stepca \
  --network <network> \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://bootroot-openbao:8200 \
  openbao/openbao:2.5.5 \
  agent -config /openbao/secrets/openbao/stepca/agent.hcl
```

OpenBao Agent for responder (example):

```bash
docker run --rm \
  --name openbao-agent-responder \
  --network <network> \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://bootroot-openbao:8200 \
  openbao/openbao:2.5.5 \
  agent -config /openbao/secrets/openbao/responder/agent.hcl
```

Why not `VAULT_ADDR=http://localhost:8200` here:
inside a container, `localhost` points to the agent container itself, not the
OpenBao container. On Docker networks, use the OpenBao container name
(`bootroot-openbao`).

Note: in the bootroot default topology where
OpenBao/PostgreSQL/step-ca/HTTP-01 responder are deployed on one machine,
`bootroot init` generates step-ca/responder OpenBao Agent configs and enables
dedicated OpenBao Agent containers (`openbao-agent-stepca`,
`openbao-agent-responder`) via compose override.

### Host run

```bash
openbao agent -config /etc/bootroot/openbao/stepca/agent.hcl
```

Recommended deployment policy:

- step-ca/responder: in the bootroot default topology where
  OpenBao/PostgreSQL/step-ca/HTTP-01 responder run on one machine, run a
  dedicated OpenBao Agent container per component. Attach
  `openbao-agent-stepca` to step-ca and
  `openbao-agent-responder` to responder so each component renders only its
  own required secrets.
- services: no OpenBao Agent. The `bootroot-agent` host daemon's
  fast-poll loop is the secret-delivery mechanism.

For the service `bootroot-agent` flow, `role_id`/`secret_id` (and, when
EAB is configured, `eab.json`) live under `secrets/services/<service>/`.
Keep the directory `0700` and the files `0600`.

## Full reset (dev/test)

If your local environment is in a bad state or you want to regenerate all
secrets from scratch, use `bootroot clean` for a full teardown. **All existing
keys/tokens/certs will be discarded.**

```bash
bootroot clean
```

This stops containers, removes volumes, and clears generated secrets and
outputs. After cleaning, re-run the first-time install flow:

```bash
bootroot infra install
bootroot init
```

Then start services, re-add a service, and verify issuance:

```bash
docker compose up -d
bootroot service add --service-name edge-proxy --hostname edge-node-01 \
  --domain trusted.domain --instance-id 001 \
  --agent-config "$(pwd)/tmp/agent-edge-proxy.toml" \
  --cert-path "$(pwd)/certs/edge-proxy.crt" \
  --key-path "$(pwd)/certs/edge-proxy.key"
bootroot verify --service-name edge-proxy \
  --agent-config "$(pwd)/tmp/agent-edge-proxy.toml"
```

`bootroot verify` runs a one-shot issuance with the bootroot-agent binary. If
it reports `result: ok` and `certs/edge-proxy.crt` is created, issuance is
working.

If the responder HMAC mismatches, ensure the OpenBao HMAC secret matches the
responder config and restart the responder.

**Manual reset alternative** (without `bootroot clean`):

1. Stop containers and remove volumes:

   ```bash
   docker compose down -v --remove-orphans
   ```

2. Remove secrets and outputs (keep templates):

   ```bash
   rm -rf certs tmp state.json \
     secrets/certs secrets/config secrets/db secrets/openbao \
     secrets/responder secrets/secrets
   rm -f secrets/password.txt
   ```

   If you removed `secrets/templates`, restore it with
   `git checkout -- secrets/templates`.

## bootroot-agent

Recommended deployment policy:

- bootroot-agent runs as a **host daemon** (systemd). This is the only
  supported run model for onboarded services — bootroot-agent is not run
  as a Docker sidecar.
- one `bootroot-agent` process plus one agent config per **distinct
  service**: the `[openbao]` section holds a single AppRole credential,
  so distinct services cannot share one `agent.toml`. Multiple
  `[[profiles]]` in one config are only for instances of the same
  service (see
  [Operations > systemd operations procedure](operations.md#systemd-operations-procedure-recommended-for-bootroot-agent)).
- applications that consume the certificates may still run in containers:
  the host daemon writes certs to a host directory the app container
  bind-mounts, and a `--reload-style docker-restart --reload-target
  <container>` hook reloads it (see
  [Operations > Containerized consumer applications](operations.md#containerized-consumer-applications)).

### Binary

Build from source:

```bash
cargo build --release
./target/release/bootroot-agent --config agent.toml --oneshot
```

`--oneshot` issues once and exits. For daemon mode, omit it and pass the
provisioned EAB file path, as printed by `bootroot service add`:

```bash
bootroot-agent --config /etc/bootroot/agent.toml \
  --eab-file /path/to/secrets/services/<svc>/eab.json
```

`--eab-file` is required for EAB rotation to apply — without it, EAB KV
updates and `rotate eab-clear` are silent no-ops for that agent. See
**Configuration** for details and
[Operations > systemd operations procedure](operations.md#systemd-operations-procedure-recommended-for-bootroot-agent)
for a hardened unit example.

TLS verification override:

For detailed behavior and the recommended operating flow, see
[Configuration > Trust](configuration.md#trust).

- `--insecure` disables verification for that run (**insecure**, overrides
  normal behavior). In the normal managed onboarding flow, trust is prepared
  before the first `bootroot-agent` run so verification can already be on.

#### CA bundle consumer permissions

Services using mTLS must be able to read the CA bundle written to
`trust.ca_bundle_path`. The simplest setup is running bootroot-agent and the
service under the same user or group.

### Smoke-testing against the compose stack

bootroot-agent has no container image: it always runs as a host process, so
there is nothing to `docker compose up`. To exercise a **one-shot** issuance
against the compose stack, build the binary and point it at the ports the
stack publishes to the host:

```bash
cargo build --bin bootroot-agent
./target/debug/bootroot-agent --oneshot --insecure --config agent.toml.compose
```

`agent.toml.compose` is the config for exactly this run model — a native
binary talking to the compose stack over `localhost`. `--insecure` is needed
because the compose stack's CA is self-signed and this config carries no
trust bundle; the managed onboarding flow prepares trust first and does not
need it. This is a demo/smoke path, not an onboarding path: production
services run the bootroot-agent host daemon described above with the config
`bootroot service add` writes.

`scripts/preflight/extra/agent-scenarios.sh` drives the same binary the same
way across its scenarios.

## bootroot-remote (for remote service machines)

When a service is added on a machine different from where step-ca/OpenBao run,
install `bootroot-remote` on that service machine.

- Build/install: `cargo build --release --bin bootroot-remote`
- Runtime: `bootroot-remote bootstrap ...` (one-shot initial trust/bootstrap
  apply before the first agent run). The running `bootroot-agent` then pulls
  trust and secret_id rotations via its fast-poll loop, so
  `bootroot-remote apply-secret-id ...` is only a recovery path for an agent
  that was offline past its `secret_id_ttl`

For detailed arguments/examples in `remote-bootstrap` mode, see
`bootroot-remote bootstrap`/`apply-secret-id` in [CLI](cli.md) and the
[Remote Bootstrap Operator Guide](remote-bootstrap.md).

## HTTP-01 responder

### Docker (default)

HTTP-01 challenges are served by a separate responder image built from
`docker/http01-responder/Dockerfile`.

```bash
docker compose up --build -d bootroot-http01
```

The default `docker-compose.yml` in this project sets `restart: always` for
the HTTP-01 responder.

The responder reads `responder.toml.compose` and listens on port 80 for
`/.well-known/acme-challenge/` requests. bootroot-agent registers tokens via
an admin API on port 8080 using the shared HMAC secret.

#### DNS alias (automatic)

For HTTP-01 validation, the step-ca container must resolve each service's
challenge hostname to the responder.  `bootroot service add` handles this
automatically: it registers the validation FQDN
(`<instance_id>.<service_name>.<hostname>.<domain>`) as a Docker network
alias on the `bootroot-http01` container.  No manual
`docker-compose.override.yml` is required.

If the responder container is restarted (e.g. `docker compose down` / `up`),
run `bootroot infra up` to replay all aliases from `state.json`.

### Binary (optional)

If you must run it outside Docker, use the binary and manage it with systemd.

#### Step 1. Build the responder binary

```bash
cargo build --release --bin bootroot-http01-responder
sudo install -m 0755 ./target/release/bootroot-http01-responder /usr/local/bin/
```

#### Step 2. Create the configuration

Create `/etc/bootroot/responder.toml` and set the HMAC secret.

#### Step 3. Create a systemd unit

```ini
[Unit]
Description=Bootroot HTTP-01 Responder
After=network.target

[Service]
ExecStart=/usr/local/bin/bootroot-http01-responder --config /etc/bootroot/responder.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

#### Step 4. Start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bootroot-http01-responder
```

Port 80 requires root or `cap_net_bind_service`.
