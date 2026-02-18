# 설정

bootroot-agent는 TOML 설정 파일을 읽습니다(기본값: `agent.toml`).
전체 템플릿은 `agent.toml.example`에 있습니다.

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
`bootroot service add`는 서비스별 OpenBao Agent 설정 경로를 출력하며,
기본 경로는 `secrets/openbao/services/<service>/agent.hcl`입니다.

OpenBao Agent는 `role_id`/`secret_id` 파일을 사용해 AppRole로 로그인하며,
해당 파일은 `secrets/services/<service>/` 아래에 저장됩니다.
디렉터리는 `0700`, 파일은 `0600` 권한을 유지해야 합니다.

구성 책임은 다음과 같습니다.

- **step-ca/리스폰더**: `bootroot init`이 `agent.hcl`을 자동 생성합니다.
- **`--delivery-mode local-file`로 추가한 서비스**:
  `bootroot service add`가 서비스별 OpenBao Agent
  설정/템플릿과 managed `agent.toml` 프로필을 자동 반영합니다.
- **`--delivery-mode remote-bootstrap`로 추가한 서비스**: `bootroot service add`가 부트스트랩
  아티팩트를 만들고, `bootroot-remote sync`가 원격 호스트에서
  `agent.hcl`/템플릿/토큰과 managed `agent.toml` 프로필을 반영합니다.

예시 `agent.hcl` 스니펫:

```hcl
exit_after_auth = false
pid_file = "/openbao/secrets/openbao/services/edge-proxy/agent.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "/openbao/secrets/services/edge-proxy/role_id"
      secret_id_file_path = "/openbao/secrets/services/edge-proxy/secret_id"
    }
  }
  sink "file" {
    config = {
      path = "/openbao/secrets/openbao/services/edge-proxy/token"
    }
  }
}

template {
  source = "/openbao/secrets/openbao/services/edge-proxy/agent.toml.ctmpl"
  destination = "/openbao/secrets/services/edge-proxy/agent.toml"
}
```

이 스니펫은 **수동 구성 시 참고용**입니다. bootroot CLI 생태계에서는
`bootroot init`/`bootroot service add`가 생성한 `agent.hcl`을 사용하는 것이
가장 간편합니다.

`--delivery-mode remote-bootstrap` 경로에서는 원격에 `agent.toml`이 아직 없을 때
`bootroot-remote sync`가 baseline을 생성할 수 있습니다. baseline 생성에는
다음 입력이 사용됩니다.

- `--agent-email`
- `--agent-server`
- `--agent-domain`
- `--agent-responder-url`
- `--profile-hostname`
- `--profile-instance-id`
- `--profile-cert-path`
- `--profile-key-path`

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
  - `https://`만 지원하며 `http://`는 런타임에서 거부됩니다.
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
verify_certificates = true
ca_bundle_path = "/etc/bootroot/ca-bundle.pem"
trusted_ca_sha256 = ["<sha256-hex>"]
```

mTLS 신뢰와 **ACME 서버 TLS 검증**을 제어하는 설정입니다.

개념 정리:

- **mTLS 신뢰**: 서비스가 서로의 인증서를 검증할 때 사용할 **신뢰 번들**입니다.
  bootroot-agent가 발급 응답의 체인(중간/루트)을 `ca_bundle_path`에 저장하면,
  이 파일을 서비스의 trust store로 사용합니다.
- **ACME 서버 TLS 검증**: bootroot-agent가 step-ca(ACME 서버)와 통신할 때
  **서버 인증서를 검증하는 동작**입니다. 이는 mTLS와 별개의 개념입니다.

설정 항목:

- `verify_certificates`: **ACME 서버 TLS 검증** 여부입니다.
  mTLS 신뢰 설정이 아니라, step-ca와 통신할 때 bootroot-agent가
  서버 인증서를 검증할지 결정합니다.
- `ca_bundle_path`: bootroot-agent가 **CA 번들(중간/루트)을 저장할 경로**입니다.
  `verify_certificates = true`일 때 이 값을 설정하면 **이 번들을 ACME 서버
  신뢰 번들로도 사용**합니다.
- `trusted_ca_sha256`: 신뢰할 CA 인증서 지문 목록(SHA-256 hex)입니다.

`trusted_ca_sha256`는 **임의 값이 아니라 실제 CA 인증서 지문**입니다.
`bootroot init`이 CA 지문을 OpenBao에 저장하고, 이후 `bootroot service add`는
`--delivery-mode`에 따라 이를 다르게 반영합니다.

- `--delivery-mode remote-bootstrap`: 지문이 서비스별 원격 sync trust 경로에 자동 기록되고,
  `bootroot-remote sync` 단계에서 서비스 머신의 `agent.toml`에 반영됩니다.
- `--delivery-mode local-file`: trust 설정(`trusted_ca_sha256`,
  `ca_bundle_path`)이 `agent.toml`에 자동 병합됩니다. OpenBao trust 데이터에
  `ca_bundle_pem`도 있으면 bootroot가 해당 PEM을 `ca_bundle_path` 파일에
  제한 권한으로 자동 반영합니다.

`verify_certificates = true`인데 `ca_bundle_path`가 없으면,
bootroot-agent는 **시스템 CA 저장소**로 ACME 서버를 검증합니다.

기본값: `verify_certificates = false` (호환성 유지 목적). 운영 환경에서는
검증을 활성화하고 신뢰할 CA 소스를 제공하는 것을 권장합니다.

운영 팁:

- bootroot-agent가 **처음** step-ca와 통신할 때는 `ca_bundle_path`에
  신뢰할 CA 번들이 **미리 존재해야** 합니다(수동 설치 필요).
  이 과정이 번거롭다면, **일시적으로** `bootroot-agent --insecure`로
  발급을 진행할 수 있습니다.
- 한 번 발급이 성공하면 bootroot-agent가 체인을 `ca_bundle_path`에
  저장합니다. 이후 **정기 갱신(cron/daemon)** 단계에서는
  `--insecure`를 사용하지 말고 **검증을 유지**하는 것이 안전합니다.
- 위 흐름을 사용하면 `agent.toml`의 `verify_certificates = true`는
  그대로 두고, 필요 시에만 CLI로 임시 우회할 수 있습니다.

참고: 단일 step-ca를 사용하는 환경에서는 mTLS 신뢰 번들과
ACME 서버 검증에 **같은 `ca_bundle_path`를 재사용하는 운영**이 가능합니다.
다만 두 개념은 목적이 다르므로 필요 시 분리할 수 있다는 점은 기억하세요.

`--delivery-mode remote-bootstrap` 경로에서 trust 반영이 되지 않거나 값이 비어 있으면 다음을
확인하세요.

- step-ca 초기화로 `secrets/certs/root_ca.crt`,
  `secrets/certs/intermediate_ca.crt`가 생성되어 있는지
- `bootroot init`이 같은 `secrets_dir`을 사용해 실행되었는지
- OpenBao의 `secret/bootroot/ca` 경로에 `trusted_ca_sha256`가 있는지

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

### 명령행 옵션

`bootroot-agent`는 아래 옵션만 설정을 덮어쓸 수 있습니다.
적용 순서는 `agent.toml` → 환경변수 → CLI 옵션이며, 마지막에 적용되는 CLI가
가장 우선입니다.

예: `agent.toml`에 `email = "admin@example.com"`이 있어도
`bootroot-agent --email ops@example.com`으로 실행하면 실제로는
`ops@example.com`이 사용됩니다.

옵션 목록:

- `--config <PATH>`: 설정 파일 경로(기본 `agent.toml`)
- `--email <EMAIL>`: 지원 이메일
- `--ca-url <URL>`: ACME 디렉터리 URL
- `--http-responder-url <URL>`: HTTP-01 리스폰더 URL
  (env `BOOTROOT_HTTP_RESPONDER_URL`)
- `--http-responder-hmac <HMAC>`: HTTP-01 리스폰더 HMAC
  (env `BOOTROOT_HTTP_RESPONDER_HMAC`)
- `--eab-kid <KID>`: EAB Key ID
- `--eab-hmac <HMAC>`: EAB HMAC Key
- `--eab-file <PATH>`: EAB JSON 파일 경로
- `--oneshot`: 1회 발급 후 종료(데몬 루프 비활성화)
- `--verify-certificates`: ACME 서버 TLS 검증 강제
- `--insecure`: ACME 서버 TLS 검증 비활성화

그 외 설정(프로필, 재시도, 스케줄러, 훅, CA 번들 경로 등)은
`agent.toml`에 정의해야 합니다.

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
