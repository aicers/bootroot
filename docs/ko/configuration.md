# 설정

bootroot-agent는 TOML 설정 파일을 읽습니다(기본값: `agent.toml`).
전체 템플릿은 `agent.toml.example`에 있습니다.
`agent.toml`은 데몬 프로필 전용입니다. 도커 사이드카는 `agent.toml`을
사용하지 않고 런타임 인자나 환경변수로 설정합니다.

## bootroot CLI

CLI 사용법은 [CLI 문서](cli.md)에 정리되어 있습니다. 이 문서는 **수동 설정**
절차를 기준으로 설명합니다.

## OpenBao Agent

OpenBao Agent는 OpenBao에서 시크릿을 읽어 파일로 렌더링합니다.
`agent.hcl`은 **OpenBao Agent 설정 파일**이며, 템플릿/출력 경로와
AppRole 로그인 정보를 정의합니다. `agent.hcl` 자체가 시크릿 파일은 아니며,
OpenBao Agent가 이 설정을 사용해 실제 시크릿 파일을 생성합니다.
`bootroot init`은 step-ca/리스폰더용 `agent.hcl`을
`secrets/openbao/stepca/agent.hcl`,
`secrets/openbao/responder/agent.hcl`에 생성합니다.
`bootroot app add`는 앱별 OpenBao Agent 설정 경로를 출력하며,
기본 경로는 `secrets/openbao/apps/<service>/agent.hcl`입니다.

OpenBao Agent는 `role_id`/`secret_id` 파일을 사용해 AppRole로 로그인하며,
해당 파일은 `secrets/apps/<service>/` 아래에 저장됩니다.
디렉터리는 `0700`, 파일은 `0600` 권한을 유지해야 합니다.

구성 책임은 다음과 같습니다.

- **step-ca/리스폰더**: `bootroot init`이 `agent.hcl`을 자동 생성합니다.
- **앱별 에이전트**: `bootroot app add`가 경로와 실행 안내를 출력하며,
  사용자가 해당 경로에 `agent.hcl`을 배치해 실행합니다.

예시 `agent.hcl` 스니펫:

```hcl
exit_after_auth = false
pid_file = "/openbao/secrets/openbao/apps/edge-proxy/agent.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "/openbao/secrets/apps/edge-proxy/role_id"
      secret_id_file_path = "/openbao/secrets/apps/edge-proxy/secret_id"
    }
  }
  sink "file" {
    config = {
      path = "/openbao/secrets/openbao/apps/edge-proxy/token"
    }
  }
}

template {
  source = "/openbao/secrets/openbao/apps/edge-proxy/agent.toml.ctmpl"
  destination = "/openbao/secrets/apps/edge-proxy/agent.toml"
}
```

이 스니펫은 **수동 구성 시 참고용**입니다. bootroot CLI 생태계에서는
`bootroot init`/`bootroot app add`가 생성한 `agent.hcl`을 사용하는 것이
가장 간편합니다.

구성 설명:

- `exit_after_auth`: `true`면 토큰 발급 후 종료, `false`면 상시 실행합니다.
- `pid_file`: 에이전트 PID 파일 경로입니다.
- `auto_auth.method`: AppRole 로그인 설정이며 `role_id`/`secret_id` 파일을 읽습니다.
- `auto_auth.sink`: 발급된 토큰을 파일로 저장하는 위치입니다.
- `template`: OpenBao KV 값을 읽어 실제 설정/시크릿 파일을 렌더링합니다.

## bootroot-agent (agent.toml)

### 전역 설정

```toml
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "trusted.domain"
```

- `email`: ACME 계정 연락처 이메일입니다. bootroot-agent가 step-ca에
  최초 접속할 때 계정을 자동 등록하며, 이 주소가 함께 저장됩니다.
  이 문맥에서 “step-ca 계정”은 ACME 계정과 같은 의미입니다. 기본
  step-ca는 이 주소로 메일을 자동 발송하지 않지만, 운영자가 별도 알림
  시스템을 붙일 때 사용할 수 있으므로 실제 수신 가능한 주소를 권장합니다.
- `server`: ACME 디렉터리 URL입니다. bootroot-agent가 step-ca와 통신할 때
  시작점으로 사용하는 주소입니다.
  - `localhost`는 **step-ca가 같은 머신에서 동작할 때만** 유효합니다.
    다른 머신이면 해당 호스트/IP로 바꿔야 합니다.
  - 경로 형식은 `/acme/<provisioner-name>/directory`입니다. 개발 설정에서는
    provisioner 이름이 `acme`라서 `/acme/acme/directory`가 됩니다.
    `secrets/config/ca.json`에서 provisioner 이름을 바꾸면 경로도 바뀝니다.
  예:
    - Docker Compose: `https://bootroot-ca:9000/acme/acme/directory`
    - 호스트 실행(동일 호스트): `https://localhost:9000/acme/acme/directory`
    - 원격 step-ca: `https://<step-ca-host>:9000/acme/<provisioner>/directory`
- `domain`: `instance_id.service_name.hostname.domain` 형식의 DNS SAN을
  자동 생성할 때 사용하는 루트 도메인입니다(daemon/docker 공통).

### 스케줄러

```toml
[scheduler]
max_concurrent_issuances = 3
```

동시에 처리할 발급 작업 수를 제한합니다.
인증서 발급/갱신을 동시에 실행할 최대 개수이며, 초과하는 작업은
대기합니다. step-ca나 호스트 부하를 줄이기 위한 전역 제한입니다.

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

HTTP-01 리스폰더와 ACME 재시도 동작을 제어합니다.

- `http_responder_url`: HTTP-01 리스폰더 **관리자 API 기본 URL**입니다.
  bootroot-agent가 토큰을 등록할 때 이 주소로 요청합니다.
  예:
  - Docker Compose: `http://bootroot-http01:8080`
  - 원격 리스폰더: `http://<responder-host>:8080`
- `http_responder_hmac`: 토큰 등록용 HMAC 공유 비밀키입니다. HTTP-01 리스폰더의
  `hmac_secret`과 동일해야 합니다.
- `http_responder_timeout_secs`: 리스폰더 요청 타임아웃(초)
- `http_responder_token_ttl_secs`: 토큰 TTL(초)

### 신뢰

```toml
[trust]
ca_bundle_path = "/etc/bootroot/ca-bundle.pem"
trusted_ca_sha256 = ["<sha256-hex>"]
```

mTLS 신뢰를 위해 CA 번들을 저장하고 검증하는 설정입니다.

- `ca_bundle_path`: bootroot-agent가 CA 번들(중간/루트)을 **저장할 경로**입니다.
- `trusted_ca_sha256`: 신뢰할 CA 인증서 지문 목록(SHA-256 hex)입니다.

`trusted_ca_sha256`는 **임의 값이 아니라 실제 CA 인증서 지문**입니다.
`bootroot init`이 CA 지문을 OpenBao에 저장하며,
`bootroot app add` 출력의 agent.toml 스니펫에 **신뢰 지문 목록이 포함**됩니다.
따라서 일반적인 운영 흐름에서는 app add가 제시한 값을 그대로 사용하면 됩니다.

만약 스니펫에 `trusted_ca_sha256`가 나오지 않는다면 다음을 확인하세요.

- step-ca 초기화로 `secrets/certs/root_ca.crt`,
  `secrets/certs/intermediate_ca.crt`가 생성되어 있는지
- `bootroot init`이 같은 `secrets_dir`을 사용해 실행되었는지

권한 참고: CA 번들을 사용하는 서비스가 `ca_bundle_path`를 읽을 수 있어야
합니다. 가장 간단한 방법은 bootroot-agent와 서비스를 동일 사용자/그룹으로
실행하는 것이며, 그렇지 않다면 파일과 상위 디렉터리에 읽기 권한을 부여해야
합니다.

### 재시도 설정

```toml
[retry]
backoff_secs = [5, 10, 30]
```

발급/갱신 실패 시 재시도 간격입니다. 프로필별로 재정의할 수 있습니다.

### EAB (선택)

```toml
[eab]
kid = "your-key-id"
hmac = "your-hmac-key"
```

CLI에서도 지정 가능합니다(`--eab-kid`, `--eab-hmac`, `--eab-file`).
운영 환경에서는 OpenBao에서 EAB 값을 주입하는 구성을 권장합니다.

### 프로필

프로필 하나가 인증서 하나를 의미합니다.

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

DNS SAN은 `<instance-id>.<service-name>.<hostname>.<domain>` 형식으로
자동 생성됩니다(daemon/docker 공통). 이 이름은 HTTP-01 검증 대상이므로, step-ca에서
HTTP-01 리스폰더 IP로 해석되어야 합니다(Compose는 네트워크 alias,
베어메탈은 `/etc/hosts` 또는 DNS 설정).
권장 형식: `<instance-id>.<service-name>.<hostname>.<domain>`.

#### 프로필 재시도 재정의

```toml
[profiles.retry]
backoff_secs = [5, 10, 30]
```

#### 훅

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

훅은 인증서 발급/갱신이 끝난 뒤에 실행하는 후처리 작업입니다. `success`는
해당 단계가 성공했을 때, `failure`는 실패했을 때 실행할 작업을 의미합니다.
인증서를 읽는 데몬에 신호를 보내거나 재시작하는 등의 운영 작업을 넣습니다.
`systemctl reload`는 서비스가 `ExecReload`를 제공하거나 신호 기반 리로드를
지원할 때만 동작합니다. 지원하지 않는 데몬은 `systemctl restart`로 다시
시작해야 하고, 직접 `kill -HUP <pid>`처럼 신호를 보내는 방식도 사용할 수
있습니다. 따라서 데몬 측에서 리로드/재시작 동작을 처리하도록 준비되어 있어야
합니다.

- `working_dir`: 훅 작업 디렉터리
- `max_output_bytes`: stdout/stderr 제한
- `on_failure`: `continue` 또는 `stop`

### CLI 재정의

```bash
bootroot-agent --config agent.toml --oneshot
bootroot-agent --config agent.toml --email admin@example.com
bootroot-agent --config agent.toml --eab-kid X --eab-hmac Y
```

CLI 값이 제공되면 파일 설정을 덮어씁니다.
우선순위는 `agent.toml` → 환경변수 → CLI 옵션이며, CLI가 가장 우선입니다.
예를 들어 `agent.toml`에 `email = "admin@example.com"`이 있어도
`bootroot-agent --email ops@example.com`으로 실행하면 실제로는
`ops@example.com`이 사용됩니다.

## HTTP-01 리스폰더 (responder.toml)

리스폰더는 `responder.toml`(또는 `BOOTROOT_RESPONDER__*` 환경변수)을 읽습니다.

```toml
listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "change-me"
token_ttl_secs = 300
cleanup_interval_secs = 30
max_skew_secs = 60
```

- `listen_addr`: step-ca가 HTTP-01 검증을 위해 **HTTP 요청을 보내는 주소**입니다.
  리스폰더는 `/.well-known/acme-challenge/<token>` 요청에 key authorization을
  응답합니다.
- `admin_addr`: bootroot-agent가 **토큰을 등록하기 위해 호출하는 관리자 API**
  주소입니다. 이 요청을 통해 리스폰더가 `listen_addr`에서 응답할 토큰을
  저장합니다.
- `hmac_secret`: 공유 비밀키(`acme.http_responder_hmac`와 동일해야 함)
- `token_ttl_secs`: 토큰 유효 시간(초)
- `cleanup_interval_secs`: 만료 토큰 정리 주기(초)
- `max_skew_secs`: 관리자 요청 허용 시계 오차(초)
