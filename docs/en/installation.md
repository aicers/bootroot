# Installation

This section covers step-ca, PostgreSQL, bootroot-agent, and the HTTP-01 responder.
If you are using the CLI, see `docs/en/cli.md`. This document focuses on the
**manual setup** flow.

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

- `ca.json`
- `root_ca.crt`
- `intermediate_ca.crt`
- `secrets/ca_key`
- `secrets/intermediate_ca_key`

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
**inside the container network**. Use the Compose service name (for example,
`postgres`), not `127.0.0.1` or `localhost`.

`<secret>` is your real database password.

`step-pass` is the development default for this repo. It must match
`POSTGRES_PASSWORD` in `.env`, which is why the local/Compose examples use the
same value. In production, replace it with a strong password. In production
we recommend injecting this DB password via a Secret Manager.

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
the `agent.hcl` files produced by `bootroot init`, and apps use the paths
printed by `bootroot app add`.

### Docker

OpenBao Agent for step-ca (example):

```bash
docker run --rm \
  --name openbao-agent-stepca \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://localhost:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/stepca/agent.hcl
```

OpenBao Agent for responder (example):

```bash
docker run --rm \
  --name openbao-agent-responder \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://localhost:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/responder/agent.hcl
```

OpenBao Agent for an app (example):

```bash
docker run --rm \
  --name openbao-agent-edge-proxy \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://localhost:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/apps/edge-proxy/agent.hcl
```

### Host run

```bash
openbao agent -config /etc/bootroot/openbao/apps/<service>/agent.hcl
```

bootroot runs OpenBao Agent **only in Docker** by default. Host execution is
for reference.

`role_id`/`secret_id` live under `secrets/apps/<service>/`. Keep the
directory `0700` and the files `0600`.

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

### Binary

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

Use the provided compose service:

```bash
docker compose up --build -d bootroot-agent
```

The agent reads `agent.toml.compose` by default in the container.

The image runs the agent in **daemon mode by default** (no `--oneshot`).
For a sidecar, use a restart policy such as `restart: unless-stopped` to keep
the container running (the current compose example does **not** set a restart
policy for bootroot-agent by default). Also ensure Docker/Compose itself is
managed by systemd (or an equivalent service manager) so it survives host
reboots.

## HTTP-01 responder

### Docker

HTTP-01 challenges are served by a separate responder image built from
`docker/http01-responder/Dockerfile`.

```bash
docker compose up --build -d bootroot-http01
```

The responder reads `responder.toml.compose` and listens on port 80 for
`/.well-known/acme-challenge/` requests. bootroot-agent registers tokens via
an admin API on port 8080 using the shared HMAC secret.

### systemd (bare metal)

You can also run the responder as a systemd service on a host.

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
