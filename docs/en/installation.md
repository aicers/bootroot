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

## step-ca

### Docker

The repo includes a compose setup that builds step-ca with PostgreSQL support.
This is the easiest path for local or lab usage.

```bash
docker compose up --build -d step-ca
```

#### Initialize step-ca (first run)

If you are not using the pre-generated dev secrets, initialize the CA:

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

Next, update `secrets/config/ca.json` for your environment:

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
with both `--db-provision` and `--auto-generate`. In the `--db-dsn` path, the
password embedded in the DSN is used as-is.

Example `.env`:

```text
POSTGRES_USER=step
POSTGRES_PASSWORD=step-pass
POSTGRES_DB=stepca
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
```

Choose `sslmode` based on your environment:

- `require`: TLS enabled, but hostname verification is skipped
- `verify-full`: TLS enabled and the server cert and hostname are verified

Selection guide:

- Production / security first: `verify-full`
- Internal test or lab: `require`

In local Compose, set `.env` and run:

```bash
scripts/update-ca-db-dsn.sh
```

This script reads `POSTGRES_*` from `.env` and updates `db.type` and
`db.dataSource` in `secrets/config/ca.json`.

### Single-Host Guardrails

When using the non-TLS local model (`sslmode=disable`), bootroot enforces
single-host guardrails:

- PostgreSQL host in DSN must be local-only (`postgres`, `localhost`,
  `127.0.0.1`, or `::1`).
- init summary prints DB host resolution (for example,
  `localhost -> postgres`).
- PostgreSQL port publishing in Compose must stay localhost-bound (for example,
  `127.0.0.1:5432:5432`), not `0.0.0.0` or bare `5432:5432`.

If these conditions are violated, `bootroot init`, `bootroot infra up`, and
`bootroot rotate db` fail fast.

When moving beyond a single-host trust boundary, switch to TLS-based DB
transport (`sslmode=require` or `sslmode=verify-full`).

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

OpenBao Agent renders secrets from OpenBao to files. step-ca/responder use
the `agent.hcl` files produced by `bootroot init`, and services use the paths
printed by `bootroot service add`.

### Docker

OpenBao Agent for step-ca (example):

```bash
docker run --rm \
  --name openbao-agent-stepca \
  --network bootroot_default \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://bootroot-openbao:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/stepca/agent.hcl
```

OpenBao Agent for responder (example):

```bash
docker run --rm \
  --name openbao-agent-responder \
  --network bootroot_default \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://bootroot-openbao:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/responder/agent.hcl
```

OpenBao Agent for a service (example):

```bash
docker run --rm \
  --name openbao-agent-edge-proxy \
  --network bootroot_default \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://bootroot-openbao:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/services/edge-proxy/agent.hcl
```

Why not `VAULT_ADDR=http://localhost:8200` here:
inside a container, `localhost` points to the agent container itself, not the
OpenBao container. On Docker networks, use the OpenBao container name
(`bootroot-openbao`).

Note: in the bootroot default topology where step-ca/OpenBao/responder run on
one machine, `bootroot init` generates step-ca/responder OpenBao Agent configs
and a compose override, then starts `openbao-agent-stepca` and
`openbao-agent-responder`.

### Host run

```bash
openbao agent -config /etc/bootroot/openbao/services/<service>/agent.hcl
```

Recommended deployment policy:

- step-ca/responder: in the bootroot default topology where
  step-ca/OpenBao/responder run on one machine, run a dedicated OpenBao Agent
  sidecar per service. Attach `openbao-agent-stepca` to step-ca and
  `openbao-agent-responder` to responder so each service renders only its own
  required secrets.
- service OpenBao Agent (recommended):
    1. Docker services: use a per-service sidecar
    2. daemon services: run OpenBao Agent as a daemon **per service**

For service OpenBao Agent flow, `role_id`/`secret_id` live under
`secrets/services/<service>/`. Keep the directory `0700` and the files `0600`.

## Full reset (dev/test)

If your local environment is in a bad state or you want to regenerate all
secrets from scratch, use this clean reset. **All existing keys/tokens/certs
will be discarded.**

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

3. Re-initialize step-ca and update the DB DSN:

   - Repeat the `Initialize step-ca (first run)` steps above.
   - For local Compose, run `scripts/update-ca-db-dsn.sh` to refresh
     `secrets/config/ca.json`.

4. Initialize and unseal OpenBao:

   - Initialize OpenBao and capture the `root token` and `unseal keys`.
   - Unseal OpenBao.

5. Initialize bootroot:

   ```bash
   bootroot init --auto-generate \
     --db-dsn "postgresql://step:step-pass@postgres:5432/stepca?sslmode=disable"
   ```

6. Start services and verify issuance:

   ```bash
   docker compose up -d
   docker compose run --rm bootroot-agent
   ```

   If `certs/bootroot-agent.crt` is created, issuance is working.

If the responder HMAC mismatches, ensure the OpenBao HMAC secret matches the
responder config and restart the responder.

## bootroot-agent

Recommended deployment policy:

- daemon services: one shared bootroot-agent daemon per host (recommended)
- Docker services: per-service bootroot-agent sidecar (recommended)

Note: Docker services can use the shared daemon, but this is supported and
not recommended. A per-service sidecar gives better isolation, better lifecycle
alignment, and limits failure impact to a single service more easily.

### Binary

Use this when the **service itself runs as a host binary/daemon** and reads
certs/keys from the host filesystem.

Build from source:

```bash
cargo build --release
./target/release/bootroot-agent --config agent.toml --oneshot
```

`--oneshot` issues once and exits. For daemon mode, omit it. See
**Configuration** for details.

TLS verification override:

- `--verify-certificates` forces ACME server TLS verification on.
- `--insecure` disables verification (**insecure**, overrides config).

#### CA bundle consumer permissions

Services using mTLS must be able to read the CA bundle written to
`trust.ca_bundle_path`. The simplest setup is running bootroot-agent and the
service under the same user or group.

### Docker

Use this when the **service itself runs in a container** and can share
volumes with the bootroot-agent sidecar.

Use the provided compose service:

```bash
docker compose up --build -d bootroot-agent
```

The agent reads `agent.toml.compose` by default in the container.

In this project's default `docker-compose.yml`, bootroot-agent is launched with
`--oneshot` (issue once, then exit).
For production-style continuous renewal, run without `--oneshot` (daemon mode)
and configure an explicit restart policy (`restart: always` or
`restart: unless-stopped`).
If you prefer manual stop behavior, switch to `restart: unless-stopped`.
Also ensure Docker/Compose itself is managed by systemd (or an equivalent
service manager) so it survives host reboots.

## bootroot-remote (for remote service machines)

When a service is added on a machine different from where step-ca/OpenBao run,
install `bootroot-remote` on that service machine.

- Build/install: `cargo build --release --bin bootroot-remote`
- Runtime: `bootroot-remote sync ...`
- Operations: periodic execution via systemd timer or cron

For detailed arguments/examples in `remote-bootstrap` mode, see
`bootroot-remote pull/ack/sync` in [CLI](cli.md).

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
