# Configuration

bootroot-agent reads a TOML configuration file (default `agent.toml`).
The full template lives in `agent.toml.example`.
`agent.toml` is for daemon profiles only. Docker sidecars do not use
`agent.toml`; configure them via runtime arguments or environment variables.

## bootroot CLI

CLI usage is documented in `docs/en/cli.md`. This document focuses on the
**manual configuration** flow.

## bootroot-agent (agent.toml)

### Global Settings

```toml
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "trusted.domain"
```

- `email`: ACME account contact email. The account is created automatically
  on first contact with step-ca, and step-ca stores this address. step-ca
  does not send mail by default, but operators can wire alerts to this
  address, so use a real inbox in production. In this context, “step-ca
  account” and “ACME account” mean the same registration.
- `server`: ACME directory URL used as the entry point for step-ca.
  - `localhost` only works when step-ca runs on the same host as
    bootroot-agent. Otherwise use the step-ca host/IP.
  - The path is `/acme/<provisioner-name>/directory`. In our dev config the
    provisioner name is `acme`, so the path becomes `/acme/acme/directory`.
    If you rename the provisioner in `secrets/config/ca.json`, this path
    changes accordingly.
  Examples:
    - Docker Compose: `https://bootroot-ca:9000/acme/acme/directory`
    - Host install (same host): `https://localhost:9000/acme/acme/directory`
    - Remote step-ca: `https://<step-ca-host>:9000/acme/<provisioner>/directory`
- `domain`: root domain used to auto-generate the DNS SAN as
  `instance_id.service_name.hostname.domain`.

### Scheduler

```toml
[scheduler]
max_concurrent_issuances = 3
```

Limits concurrent issuance operations across profiles.
This caps how many issuance/renewal workflows run at the same time; extra
requests wait in a queue. Use it to avoid overloading step-ca or the host.

### ACME

```toml
[acme]
directory_fetch_attempts = 10
directory_fetch_base_delay_secs = 1
directory_fetch_max_delay_secs = 10
poll_attempts = 15
poll_interval_secs = 2
http_responder_url = "http://localhost:8080"
http_responder_hmac = "change-me"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300
```

Controls HTTP-01 responder settings and retry behavior for ACME operations.

- `http_responder_url`: base URL of the HTTP-01 responder **admin API**.
  bootroot-agent calls this endpoint to register tokens.
  Examples:
  - Docker Compose: `http://bootroot-http01:8080`
  - Remote responder: `http://<responder-host>:8080`
- `http_responder_hmac`: shared HMAC secret for registering tokens. This must
  match the responder's `hmac_secret`.
- `http_responder_timeout_secs`: request timeout to the responder
- `http_responder_token_ttl_secs`: token TTL in seconds

### Retry Settings

```toml
[retry]
backoff_secs = [5, 10, 30]
```

Used when issuance or renewal fails. Profiles can override this.

### EAB (Optional)

```toml
[eab]
kid = "your-key-id"
hmac = "your-hmac-key"
```

EAB can also be passed via CLI (`--eab-kid`, `--eab-hmac`, or `--eab-file`).
For production, prefer injecting EAB values via OpenBao.

### Profiles

Each profile represents one daemon instance (one certificate identity).

```toml
[[profiles]]
service_name = "edge-proxy"
instance_id = "001"
hostname = "edge-node-01"

[profiles.paths]
cert = "certs/edge-proxy-a.pem"
key = "certs/edge-proxy-a.key"

[profiles.daemon]
check_interval = "1h"
renew_before = "720h"
check_jitter = "0s"
```

The DNS SAN is auto-generated as
`<instance-id>.<service-name>.<hostname>.<domain>`. This name is also the
target for HTTP-01 validation, so it must resolve from step-ca to the
HTTP-01 responder IP (for Compose, update the network alias; for host installs,
update `/etc/hosts` or DNS).

#### Profile Retry Override

```toml
[profiles.retry]
backoff_secs = [5, 10, 30]
```

#### Hooks

```toml
[profiles.hooks.post_renew]
# success = [
#   {
#     command = "nginx"
#     args = ["-s", "reload"]
#     working_dir = "/etc/nginx"
#     timeout_secs = 30
#     retry_backoff_secs = [5, 10, 30]
#     max_output_bytes = 4096
#     on_failure = "continue"
#   }
# ]
```

- `working_dir`: per-hook working directory
- `max_output_bytes`: truncate stdout/stderr (logs show truncation)
- `on_failure`: `continue` or `stop`

Hooks run **after** issuance/renewal completes. Use `success` for actions that
should run only when a certificate is issued/renewed, and `failure` for alerting
or cleanup when issuance fails.

What hooks are used for:

- Reload or restart a daemon so it reads the new certificate
- Send notifications (Slack, email, monitoring)
- Trigger deploy or sync scripts

How reloads work (important for daemon owners):

- `systemctl reload <service>` runs the unit’s `ExecReload` or sends a reload
  signal if configured.
- You can also send a signal directly, for example:
  `command = "kill"` and `args = ["-HUP", "<pid>"]`.
- The daemon must **support reload** (signal handling or config reload logic).
  If it does not, use a restart (`systemctl restart ...`) instead.

### CLI Overrides

```bash
bootroot-agent --config agent.toml --oneshot
bootroot-agent --config agent.toml --email admin@example.com
bootroot-agent --config agent.toml --eab-kid X --eab-hmac Y
```

CLI values override file settings when provided.
The precedence order is `agent.toml` → environment variables → CLI options,
so CLI has the highest priority. For example, if `agent.toml` sets
`email = "admin@example.com"`, running `bootroot-agent --email ops@example.com`
uses `ops@example.com`.

## HTTP-01 responder (responder.toml)

The responder reads `responder.toml` (or `BOOTROOT_RESPONDER__*` env vars).

```toml
listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "change-me"
token_ttl_secs = 300
cleanup_interval_secs = 30
max_skew_secs = 60
```

- `listen_addr`: address where step-ca sends **HTTP-01 validation requests**.
  The responder replies to `/.well-known/acme-challenge/<token>` with the key
  authorization.
- `admin_addr`: **admin API** where bootroot-agent registers tokens so the
  responder can answer on `listen_addr`.
- `hmac_secret`: shared secret (must match `acme.http_responder_hmac`)
- `token_ttl_secs`: how long tokens stay valid
- `cleanup_interval_secs`: how often expired tokens are removed
- `max_skew_secs`: allowed clock skew for admin requests
