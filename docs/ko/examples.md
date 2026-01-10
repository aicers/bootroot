
# 예제

이 섹션은 실제 운영에 가까운 성공 흐름(happy path)을 단계별로 확인하는 데 목적이
있습니다. 각 예제는 **어떤 상황인지**, **어떻게 설정하는지**,
**무엇을 확인해야 하는지**를 포함합니다.

## 예제 1: Compose에서 oneshot 발급

**상황**: 단일 머신에서 step-ca + PostgreSQL + HTTP-01 리스폰더 +
bootroot-agent를 모두 함께 실행합니다. step-ca와 리스폰더는 같은
Compose 네트워크에 있고, step-ca는 HTTP-01 리스폰더로 DNS SAN을
해석할 수 있어야 합니다.

### 단계 1. 준비 파일

- 설정: `agent.toml.compose`
- 리스폰더 설정: `responder.toml.compose`
- DNS SAN alias: `docker-compose.yml`의 `bootroot-http01`에
  `001.bootroot-agent.bootroot-agent.trusted.domain`가 등록되어 있어야 합니다.

아래는 Compose 예제에서 사용하는 설정 파일 전문입니다.

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

### 단계 2. 실행

```bash
docker compose up --build -d
```

### 단계 3. 성공 확인

```bash
docker logs -f bootroot-agent
```

기대 로그: `Successfully issued certificate!`

### 단계 4. 결과 파일 확인

```bash
ls -l certs/
```

기대 파일: `bootroot-agent.crt`, `bootroot-agent.key`

## 예제 2: 데몬 모드 갱신 + 성공 훅

**상황**: 단일 머신에서 step-ca + HTTP-01 리스폰더는 그대로 두고,
bootroot-agent를 데몬 모드로 실행해 주기적으로 갱신합니다. 이 예제는
갱신 성공 시 훅이 실행되는지 확인합니다.

### 단계 1. 설정 파일 작성

`agent.toml.renewal-example`에 아래 내용을 저장하세요.

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

### 단계 2. 데몬 실행

```bash
docker compose run -d --name bootroot-agent-renewal --no-deps \
  -v ./agent.toml.renewal-example:/app/agent.toml:ro \
  bootroot-agent --config=/app/agent.toml
```

### 단계 3. 갱신 및 훅 확인

```bash
ls -l certs/
cat certs/renewed.txt
```

기대 결과: 인증서 파일이 생성되고, `renewed.txt`에 갱신 시각이 기록됩니다.

### 단계 4. 데몬 컨테이너 종료

```bash
docker rm -f bootroot-agent-renewal
```

## 예제 3: 다중 프로필 + 동시 발급 제한

**상황**: 단일 머신에서 step-ca + HTTP-01 리스폰더는 그대로 두고,
bootroot-agent가 여러 프로필을 한 번에 발급합니다. `max_concurrent_issuances = 1`
로 큐잉 동작을 확인합니다.

### 단계 1. DNS SAN alias 추가(Compose override)

`docker-compose.scenarios.yml`에 아래 내용을 저장하세요.

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

그리고 리스폰더를 갱신합니다.

```bash
docker compose -f docker-compose.yml -f docker-compose.scenarios.yml up -d bootroot-http01
```

### 단계 2. 다중 프로필 설정 파일

`agent.toml.multi-example`에 아래 내용을 저장하세요.

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

### 단계 3. 발급 실행

```bash
docker compose run --rm --no-deps \
  -v ./agent.toml.multi-example:/app/agent.toml:ro \
  bootroot-agent --oneshot --config=/app/agent.toml
```

### 단계 4. 결과 확인

```bash
ls -l certs/multi-*.crt
```

기대 결과: 세 개의 인증서가 순차적으로 발급됩니다.

## 예제 4: 토폴로지 A(단일 CA/리스폰더 + 다중 에이전트)

**상황**: step-ca + PostgreSQL + HTTP-01 리스폰더가 한 머신에 있고,
bootroot-agent는 같은 머신 1대 + 원격 2대에서 동작합니다. 이 예제에서는
세 개의 설정 파일을 만들어 같은 Compose 스택에 순차 발급을 요청합니다.

### 단계 1. 에이전트 설정 파일 3개 준비

`agent.toml.topo-a-101`에 아래 내용을 저장하세요.

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

`agent.toml.topo-a-102`에 아래 내용을 저장하세요.

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

`agent.toml.topo-a-103`에 아래 내용을 저장하세요.

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

### 단계 2. 스택 실행

```bash
docker compose up --build -d
```

### 단계 3. 세 개의 에이전트 발급 실행

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

### 단계 4. 결과 확인

```bash
ls -l certs/topo-a-*.crt
```

기대 결과: `topo-a-101`, `topo-a-102`, `topo-a-103` 인증서가 생성됩니다.

## 예제 5: 토폴로지 B(CA/리스폰더 분리)

**상황**: step-ca + PostgreSQL은 한 머신, HTTP-01 리스폰더는 다른 머신,
bootroot-agent는 또 다른 머신(들)에서 동작합니다. 이 예제에서는
별도 네트워크를 만들어 step-ca와 리스폰더에 모두 접근 가능한 에이전트를
시뮬레이션합니다.

### 단계 1. 전용 네트워크 생성 및 연결

```bash
docker network create bootroot-responder-net
docker network connect --alias bootroot-ca bootroot-responder-net bootroot-ca
docker network connect --alias 401.split.edge-node-01.trusted.domain \
  --alias 402.split.edge-node-02.trusted.domain \
  bootroot-responder-net bootroot-http01
```

### 단계 2. 에이전트 설정 파일 2개 준비

`agent.toml.topo-b-401`에 아래 내용을 저장하세요.

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

`agent.toml.topo-b-402`에 아래 내용을 저장하세요.

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

### 단계 3. 분리 네트워크에서 발급 실행

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

### 단계 4. 결과 확인

```bash
ls -l certs/topo-b-*.crt
```

기대 결과: `topo-b-401`, `topo-b-402` 인증서가 생성됩니다.
