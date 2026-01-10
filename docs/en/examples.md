# Examples

This section verifies happy paths close to real operations step by step. Each
example explains **what the scenario is**, **how to configure it**, and **what
to verify**.

## Example 1: Compose oneshot issuance

**Scenario**: run step-ca + PostgreSQL + the HTTP-01 responder + bootroot-agent
on a single machine and issue the first certificate. step-ca and the responder
share the Compose network, and step-ca must resolve the DNS SAN to the
HTTP-01 responder.

### Step 1. Inputs

- Agent config: `agent.toml.compose`
- Responder config: `responder.toml.compose`
- DNS SAN alias: `docker-compose.yml` must include
  `001.bootroot-agent.bootroot-agent.trusted.domain` on `bootroot-http01`.

Below are the full config files used by the Compose example.

`agent.toml.compose`:

```toml
   email = "admin@example.com"
   server = "https://bootroot-ca:9000/acme/acme/directory"
   domain = "trusted.domain"

   [scheduler]
   max_concurrent_issuances = 1

   [acme]
   directory_fetch_attempts = 10
   directory_fetch_base_delay_secs = 1
   directory_fetch_max_delay_secs = 10
   poll_attempts = 15
   poll_interval_secs = 2
   http_responder_url = "http://bootroot-http01:8080"
   http_responder_hmac = "dev-hmac"
   http_responder_timeout_secs = 5
   http_responder_token_ttl_secs = 300

   [retry]
   backoff_secs = [5, 10, 30]

   [[profiles]]
   daemon_name = "bootroot-agent"
   instance_id = "001"
   hostname = "bootroot-agent"

   [profiles.paths]
   cert = "/app/certs/bootroot-agent.crt"
   key = "/app/certs/bootroot-agent.key"

   [profiles.daemon]
   check_interval = "1h"
   renew_before = "720h"
   check_jitter = "0s"

   [profiles.retry]
   backoff_secs = [5, 10, 30]
```

`responder.toml.compose`:

```toml
   listen_addr = "0.0.0.0:80"
   admin_addr = "0.0.0.0:8080"
   hmac_secret = "dev-hmac"
   token_ttl_secs = 300
   cleanup_interval_secs = 30
   max_skew_secs = 60
```

### Step 2. Run

```bash
docker compose up --build -d
```

### Step 3. Verify success

```bash
docker logs -f bootroot-agent
```

Expected log: `Successfully issued certificate!`

### Step 4. Check output files

```bash
ls -l certs/
```

Expected files: `bootroot-agent.crt`, `bootroot-agent.key`

## Example 2: Daemon renewal + success hook

**Scenario**: keep step-ca and the HTTP-01 responder on the same machine, run
bootroot-agent in daemon mode, renew periodically, and execute a post-renew
hook on success.

### Step 1. Create a config file

Save the following content to `agent.toml.renewal-example`.

```toml
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
daemon_name = "bootroot-agent"
instance_id = "001"
hostname = "bootroot-agent"

[profiles.paths]
cert = "certs/renewal-example.crt"
key = "certs/renewal-example.key"

[profiles.daemon]
check_interval = "30s"
renew_before = "2m"
check_jitter = "0s"

[profiles.hooks.post_renew]
success = [
  { command = "sh", args = ["-c", "date > certs/renewed.txt"] }
]
```

### Step 2. Run the daemon

```bash
docker compose run -d --name bootroot-agent-renewal --no-deps \
  -v ./agent.toml.renewal-example:/app/agent.toml:ro \
  bootroot-agent --config=/app/agent.toml
```

### Step 3. Verify renewal and hook

```bash
ls -l certs/
cat certs/renewed.txt
```

Expected result: certificate files are created and `renewed.txt` is updated.

### Step 4. Stop the daemon container

```bash
docker rm -f bootroot-agent-renewal
```

## Example 3: Multi-profile + concurrency limit

**Scenario**: keep step-ca and the HTTP-01 responder on the same machine and
issue multiple profiles in one run. Set `max_concurrent_issuances = 1` to
verify queueing behavior.

### Step 1. Add DNS SAN aliases (Compose override)

Save the following content to `docker-compose.scenarios.yml`.

```yaml
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - 201.multi.node-201.trusted.domain
          - 202.multi.node-202.trusted.domain
          - 203.multi.node-203.trusted.domain
```

Then reload the responder service.

```bash
docker compose -f docker-compose.yml -f docker-compose.scenarios.yml up -d bootroot-http01
```

### Step 2. Create a multi-profile config

Save the following content to `agent.toml.multi-example`.

```toml
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
daemon_name = "multi"
instance_id = "201"
hostname = "node-201"

[profiles.paths]
cert = "certs/multi-201.crt"
key = "certs/multi-201.key"

[[profiles]]
daemon_name = "multi"
instance_id = "202"
hostname = "node-202"

[profiles.paths]
cert = "certs/multi-202.crt"
key = "certs/multi-202.key"

[[profiles]]
daemon_name = "multi"
instance_id = "203"
hostname = "node-203"

[profiles.paths]
cert = "certs/multi-203.crt"
key = "certs/multi-203.key"
```

### Step 3. Issue all profiles

```bash
docker compose run --rm --no-deps \
  -v ./agent.toml.multi-example:/app/agent.toml:ro \
  bootroot-agent --oneshot --config=/app/agent.toml
```

### Step 4. Verify outputs

```bash
ls -l certs/multi-*.crt
```

Expected result: three certificates are issued sequentially.

## Example 4: Topology A (single CA/responder + multiple agents)

**Scenario**: step-ca + PostgreSQL + HTTP-01 responder are on one machine.
One bootroot-agent runs on the same machine and two more run on remote hosts.
In this example we simulate the three agents locally by issuing three configs
against the same Compose stack.

### Step 1. Create three agent configs

Save the following content to `agent.toml.topo-a-101`.

```toml
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
daemon_name = "edge-proxy"
instance_id = "101"
hostname = "edge-node-01"

[profiles.paths]
cert = "certs/topo-a-101.crt"
key = "certs/topo-a-101.key"
```

Save the following content to `agent.toml.topo-a-102`.

```toml
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
daemon_name = "edge-proxy"
instance_id = "102"
hostname = "edge-node-02"

[profiles.paths]
cert = "certs/topo-a-102.crt"
key = "certs/topo-a-102.key"
```

Save the following content to `agent.toml.topo-a-103`.

```toml
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
daemon_name = "edge-proxy"
instance_id = "103"
hostname = "edge-node-03"

[profiles.paths]
cert = "certs/topo-a-103.crt"
key = "certs/topo-a-103.key"
```

### Step 2. Start the stack

```bash
docker compose up --build -d
```

### Step 3. Issue certificates for three agents

```bash
docker compose run --rm --no-deps \
  -v ./agent.toml.topo-a-101:/app/agent.toml:ro \
  bootroot-agent --oneshot --config=/app/agent.toml

docker compose run --rm --no-deps \
  -v ./agent.toml.topo-a-102:/app/agent.toml:ro \
  bootroot-agent --oneshot --config=/app/agent.toml

docker compose run --rm --no-deps \
  -v ./agent.toml.topo-a-103:/app/agent.toml:ro \
  bootroot-agent --oneshot --config=/app/agent.toml
```

### Step 4. Verify outputs

```bash
ls -l certs/topo-a-*.crt
```

Expected result: three certificates exist for `topo-a-101`, `topo-a-102`,
and `topo-a-103`.

## Example 5: Topology B (split CA and responder)

**Scenario**: step-ca + PostgreSQL are on one machine, the HTTP-01 responder is
on a separate machine, and bootroot-agent runs on one or more remote machines.
In this example we simulate the split by placing the agent containers on a
dedicated Docker network that can reach both step-ca and the responder.

### Step 1. Create a dedicated network and attach services

```bash
docker network create bootroot-responder-net
docker network connect --alias bootroot-ca bootroot-responder-net bootroot-ca
docker network connect --alias 401.split.edge-node-01.trusted.domain \
  --alias 402.split.edge-node-02.trusted.domain \
  bootroot-responder-net bootroot-http01
```

### Step 2. Create two agent configs

Save the following content to `agent.toml.topo-b-401`.

```toml
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
daemon_name = "split"
instance_id = "401"
hostname = "edge-node-01"

[profiles.paths]
cert = "certs/topo-b-401.crt"
key = "certs/topo-b-401.key"
```

Save the following content to `agent.toml.topo-b-402`.

```toml
email = "admin@example.com"
server = "https://bootroot-ca:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
poll_attempts = 5
poll_interval_secs = 1
http_responder_url = "http://bootroot-http01:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[retry]
backoff_secs = [1, 2, 3]

[[profiles]]
daemon_name = "split"
instance_id = "402"
hostname = "edge-node-02"

[profiles.paths]
cert = "certs/topo-b-402.crt"
key = "certs/topo-b-402.key"
```

### Step 3. Run two agents on the split network

```bash
docker run --rm \
  --network bootroot-responder-net \
  -v ./certs:/app/certs \
  -v ./secrets/certs/root_ca.crt:/app/root_ca.crt \
  -v ./secrets:/app/secrets:ro \
  -v ./agent.toml.topo-b-401:/app/agent.toml:ro \
  bootroot-bootroot-agent --oneshot --config=/app/agent.toml

docker run --rm \
  --network bootroot-responder-net \
  -v ./certs:/app/certs \
  -v ./secrets/certs/root_ca.crt:/app/root_ca.crt \
  -v ./secrets:/app/secrets:ro \
  -v ./agent.toml.topo-b-402:/app/agent.toml:ro \
  bootroot-bootroot-agent --oneshot --config=/app/agent.toml
```

### Step 4. Verify outputs

```bash
ls -l certs/topo-b-*.crt
```

Expected result: two certificates exist for `topo-b-401` and `topo-b-402`.
