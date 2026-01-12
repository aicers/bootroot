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

## bootroot-agent

### Binary

Build from source:

```bash
cargo build --release
./target/release/bootroot-agent --config agent.toml --oneshot
```

`--oneshot` issues once and exits. For daemon mode, omit it. See
**Configuration** for details.

### Docker

Use the provided compose service:

```bash
docker compose up --build -d bootroot-agent
```

The agent reads `agent.toml.compose` by default in the container.

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
