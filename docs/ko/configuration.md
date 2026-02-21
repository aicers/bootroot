# 설정

이 섹션은 bootroot-agent, OpenBao Agent, 훅/재시도/신뢰 설정의 구성 원리를
설명합니다.
실제 운영에서는 보통 `bootroot` CLI 자동화를 사용하지만, 이 문서는
**사용자 이해도를 높이기 위해 CLI 자동화를 배제한 수동 관점**으로
구성되어 있습니다.
즉, "CLI가 내부에서 어떤 설정을 만들고 갱신하는지"를 사람이 직접 따라가며
이해할 수 있게 설명합니다.

실제 명령/자동화 흐름은 [CLI](cli.md), [CLI 예제](cli-examples.md)를
함께 참고하세요.

bootroot-agent는 TOML 설정 파일을 읽습니다(기본값: `agent.toml`).
전체 템플릿은 `agent.toml.example`에 있습니다.

CLI(`bootroot`, `bootroot-remote`) 옵션 표기 원칙:

- 옵션 설명에 `(환경 변수: ...)`가 있으면 해당 옵션이 환경 변수 입력을 지원합니다.
- 옵션 설명에 `(기본값 ...)`이 있으면 코드에 기본값이 정의되어 있습니다.
- 위 표기가 없으면 해당 항목은 기본값이 없거나(필수/선택 입력) 환경 변수
  입력을 지원하지 않습니다.

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

OpenBao Agent는 `role_id`/`secret_id` 파일을 사용해 AppRole로 로그인합니다.
서비스별(`bootroot service add`) 기본 경로는
`secrets/services/<service>/`이며, step-ca/리스폰더(`bootroot init`)는
`secrets/openbao/stepca/`, `secrets/openbao/responder/`를 사용합니다.
디렉터리는 `0700`, 파일은 `0600` 권한을 유지해야 합니다.

구성 책임은 다음과 같습니다.

- **step-ca/리스폰더**: `bootroot init`이 `agent.hcl`을 자동 생성합니다.
- **`--delivery-mode local-file`로 추가한 서비스**:
  `bootroot service add`가 서비스별 OpenBao Agent
  설정/템플릿과 managed `agent.toml` 프로필을 자동 반영합니다.
- **`--delivery-mode remote-bootstrap`로 추가한 서비스**: `bootroot service add`가 부트스트랩
  아티팩트를 만들고, `bootroot-remote bootstrap`이 원격 호스트에서
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

`--delivery-mode remote-bootstrap` 방식에서는 원격에 `agent.toml`이 아직 없을 때
`bootroot-remote bootstrap`이 baseline을 생성할 수 있습니다. baseline 생성에는
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
  비어 있으면 검증 단계에서 실행이 실패합니다.
- `http_responder_timeout_secs`: 리스폰더 요청 타임아웃(초)
- `http_responder_token_ttl_secs`: 토큰 TTL(초)

### 신뢰

```toml
[trust]
verify_certificates = true
ca_bundle_path = "/etc/bootroot/ca-bundle.pem"
trusted_ca_sha256 = ["<sha256-hex>"]
```

mTLS 신뢰와 **ACME 서버 TLS 검증**을 함께 다루는 섹션입니다.

#### 1) 개념 구분

1. **mTLS 신뢰**: 서비스가 상대 인증서를 검증할 때 사용할 신뢰 번들입니다.
   bootroot-agent는 발급 응답의 체인(중간/루트)을 `ca_bundle_path`에 저장합니다.
2. **ACME 서버 TLS 검증**: bootroot-agent가 step-ca(ACME 서버)와 통신할 때
   서버 인증서를 검증하는 동작입니다. mTLS 신뢰와는 별도입니다.

#### 2) 핵심 설정

- `verify_certificates`: ACME 서버 TLS 검증 사용 여부
- `ca_bundle_path`: CA 번들(중간/루트) 저장 경로
- `trusted_ca_sha256`: 신뢰할 CA 인증서 지문 목록(SHA-256 hex)
- `verify_certificates = true`인데 `ca_bundle_path`가 없으면 시스템 CA 저장소를 사용
- 기본값은 `verify_certificates = false` (호환성 목적)

`trusted_ca_sha256`는 임의 값이 아니라 실제 CA 인증서 지문이어야 합니다.

#### 3) `--delivery-mode` 연동

- `remote-bootstrap`: 서비스별 원격 bootstrap trust 경로에 지문이 기록되고,
  `bootroot-remote bootstrap`이 서비스 머신 `agent.toml`에 반영
- `local-file`: trust 설정(`trusted_ca_sha256`, `ca_bundle_path`)을
  `agent.toml`에 자동 병합, OpenBao trust 데이터에 `ca_bundle_pem`이 있으면
  `ca_bundle_path` 파일도 자동 반영

#### 4) 실행 플래그 동작

- `--insecure`: 해당 실행에서 `verify_certificates=false` 강제
- `--verify-certificates`: 해당 실행에서 `verify_certificates=true` 강제
- 둘 다 없으면 기존 설정값 그대로 사용

#### 5) 권장 운영 절차

목표: "첫 발급은 미검증, 이후는 검증" 흐름

1. 초기 `agent.toml`을 `trust.verify_certificates = false`로 둡니다.
2. 첫 발급을 `--insecure` 없이 실행합니다.
3. 첫 발급 성공 시 bootroot-agent가 `trust.verify_certificates = true`를 자동 기록합니다.
4. 이후 정기 갱신(cron/daemon)을 `--insecure` 없이 실행해 검증 모드를 유지합니다.

#### 6) 실패/주의 사항

- 자동 전환의 파일 쓰기/재로드 검증이 실패하면 bootroot-agent는 non-zero로 종료
- `--insecure` 실행은 해당 실행에서만 우회하며 자동 강화를 건너뜀
- 다음 일반 실행에서 자동 강화 조건을 다시 검사
- 단일 step-ca 환경에서는 mTLS 번들과 ACME 검증에 같은 `ca_bundle_path` 재사용 가능

#### 7) 점검 체크리스트

- `--delivery-mode remote-bootstrap`에서 trust가 비면 아래를 확인
- `secrets/certs/root_ca.crt`, `secrets/certs/intermediate_ca.crt` 존재 여부
- `bootroot init` 실행 시 동일 `secrets_dir` 사용 여부
- OpenBao `secret/bootroot/ca` 경로의 `trusted_ca_sha256` 존재 여부

권한 참고: `ca_bundle_path`는 이를 읽는 서비스가 접근 가능해야 합니다.
가장 단순한 방법은 bootroot-agent와 서비스를 같은 사용자/그룹으로 실행하는
것입니다.

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
최소 1개 이상의 `[[profiles]]`가 필요하며, `instance_id`는 숫자 문자열이어야
합니다.

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
- `--oneshot`: 1회 발급 후 종료(데몬 루프 비활성화, 기본값 `false`)
- `--verify-certificates`: ACME 서버 TLS 검증 강제(기본값 `false`)
- `--insecure`: ACME 서버 TLS 검증 비활성화(기본값 `false`)

그 외 설정(프로필, 재시도, 스케줄러, 훅, CA 번들 경로 등)은
`agent.toml`에 정의해야 합니다.

## HTTP-01 리스폰더 (responder.toml)

리스폰더는 `responder.toml`(또는 `BOOTROOT_RESPONDER__*` 환경변수)을 읽습니다.
설정 파일 경로는 `bootroot-http01-responder --config <PATH>`로 바꿀 수 있으며,
미지정 시 기본값은 `responder.toml`입니다.

환경 변수 매핑 규칙:

- `BOOTROOT_RESPONDER__<KEY>` 형식으로 주입합니다.
- 예: `listen_addr` -> `BOOTROOT_RESPONDER__LISTEN_ADDR`
- 예: `token_ttl_secs` -> `BOOTROOT_RESPONDER__TOKEN_TTL_SECS`

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
  응답합니다. (기본값 `0.0.0.0:80`, 환경 변수:
  `BOOTROOT_RESPONDER__LISTEN_ADDR`)
- `admin_addr`: bootroot-agent가 **토큰을 등록하기 위해 호출하는 관리자 API**
  주소입니다. 이 요청을 통해 리스폰더가 `listen_addr`에서 응답할 토큰을
  저장합니다. (기본값 `0.0.0.0:8080`, 환경 변수:
  `BOOTROOT_RESPONDER__ADMIN_ADDR`)
- `hmac_secret`: 공유 비밀키(`acme.http_responder_hmac`와 동일해야 함).
  **기본값 없음(필수)**, 빈 값은 거부됩니다. (환경 변수:
  `BOOTROOT_RESPONDER__HMAC_SECRET`)
- `token_ttl_secs`: 토큰 유효 시간(초, 기본값 `300`, 환경 변수:
  `BOOTROOT_RESPONDER__TOKEN_TTL_SECS`, 0은 허용되지 않음)
- `cleanup_interval_secs`: 만료 토큰 정리 주기(초, 기본값 `30`, 환경 변수:
  `BOOTROOT_RESPONDER__CLEANUP_INTERVAL_SECS`, 0은 허용되지 않음)
- `max_skew_secs`: 관리자 요청 허용 시계 오차(초, 기본값 `60`, 환경 변수:
  `BOOTROOT_RESPONDER__MAX_SKEW_SECS`, 0은 허용되지 않음)
