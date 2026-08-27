# 설정

이 섹션은 bootroot-agent, OpenBao Agent, 훅/재시도/신뢰 설정의 구성 원리를
설명합니다.
실제 운영에서는 보통 `bootroot` CLI 자동화를 사용하지만, 이 문서는
**운영자 이해도를 높이기 위해 CLI 자동화를 배제한 수동 관점**으로
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

OpenBao Agent는 OpenBao에서 시크릿을 읽어 파일로 렌더링합니다. bootroot에서
OpenBao Agent는 **인프라 구성 요소**(step-ca와 HTTP-01 리스폰더)에만
사용됩니다. 서비스는 서비스별 OpenBao Agent를 실행하지 **않습니다** — 각
서비스의 `bootroot-agent`가 스스로 OpenBao에 인증하고 fast-poll 루프로
시크릿을 최신 상태로 유지합니다
([개념 > 시크릿 전달 흐름](concepts.md#시크릿-전달-흐름) 참고).

`agent.hcl`은 **OpenBao Agent 설정 파일**이며, 템플릿/출력 경로와
AppRole 로그인 정보를 정의합니다. `agent.hcl` 자체가 시크릿 파일은 아니며,
OpenBao Agent가 이 설정을 사용해 실제 시크릿 파일을 생성합니다.
`bootroot init`은 step-ca/리스폰더용 `agent.hcl`을
`secrets/openbao/stepca/agent.hcl`,
`secrets/openbao/responder/agent.hcl`에 생성합니다.

OpenBao Agent는 `bootroot init`이 `secrets/openbao/stepca/`,
`secrets/openbao/responder/`에 기록한 `role_id`/`secret_id` 파일을 사용해
AppRole로 로그인합니다. 서비스의 AppRole 파일은
`secrets/services/<registration_id>/` 아래에 있으며, 이는 OpenBao Agent가 아니라
`bootroot-agent`가 직접 읽습니다. 디렉터리는 `0700`, 파일은 `0600` 권한을
유지해야 합니다.

구성 책임은 다음과 같습니다.

- **step-ca/리스폰더**: `bootroot init`이 `agent.hcl`을 자동 생성합니다.
- **`--delivery-mode local-file`로 추가한 서비스**:
  `bootroot service add`가 managed `agent.toml` 프로필(최상위 `domain`,
  `[acme].http_responder_hmac`, 그리고 에이전트의 fast-poll 자체 인증
  루프를 활성화하는 `[openbao]` 섹션 포함)을 자동 반영하고, 서비스의
  `secret_id` 옆에 `eab.json`을 프로비저닝합니다. 서비스별 OpenBao Agent
  설정/템플릿/토큰 아티팩트는 생성하지 않습니다.
- **`--delivery-mode remote-bootstrap`로 추가한 서비스**: `bootroot service add`가 부트스트랩
  아티팩트를 만들고, `bootroot-remote bootstrap`이 원격 호스트에서
  managed `agent.toml` 프로필(`[openbao]` 연결 필드 포함)을 반영합니다.
  OpenBao Agent 사이드카는 설치하지 않으며, `agent.hcl`/템플릿/토큰
  아티팩트를 생성하지 않습니다. 대신 원격 `bootroot-agent`가 AppRole로
  스스로 인증하고, 자체 fast-poll 루프를 통해 신뢰(trust)를 렌더링하고
  `secret_id`를 제자리에서 갱신하므로, CA/신뢰 및 `secret_id` 회전이
  호스트별 운영자 조치 없이 전파됩니다.
  [remote-bootstrap](remote-bootstrap.md)을 참고하세요.

예시 `agent.hcl` 스니펫(step-ca 인프라 에이전트):

```hcl
vault {
  address = "http://bootroot-openbao:8200"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path = "/openbao/secrets/openbao/stepca/role_id"
      secret_id_file_path = "/openbao/secrets/openbao/stepca/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink "file" {
    config = {
      path = "/openbao/secrets/openbao/token"
    }
  }
}

template {
  source = "/openbao/secrets/templates/password.txt.ctmpl"
  destination = "/openbao/secrets/password.txt"
}
```

이 스니펫은 **수동 구성 시 참고용**입니다. bootroot CLI 생태계에서는
`bootroot init`이 생성한 `agent.hcl`을 사용하는 것이 가장 간편합니다.

`--delivery-mode remote-bootstrap` 방식에서는 원격에 `agent.toml`이 아직 없을 때
`bootroot-remote bootstrap`이 baseline을 생성할 수 있습니다. baseline 값은
`bootroot service add`가 생성한 `bootstrap.json` 아티팩트에서 읽습니다.
아티팩트가 있으면(`--artifact <경로>`) 아티팩트 값이 CLI 플래그보다 우선합니다.

아티팩트의 `agent-server`, `agent-responder-url` 필드는 기본적으로 localhost
placeholder를 사용합니다. 별도 서비스 머신의 경우, 서비스 호스트로 전송하기
전에 `bootstrap.json`을 편집하여 원격 접근 가능한 엔드포인트로 교체하십시오.

아티팩트에 포함되는 baseline 필드:

- `agent-email`
- `agent-server`
- `agent-domain`
- `agent-responder-url`
- `profile-hostname`
- `profile-instance-id`
- `profile-cert-path`
- `profile-key-path`

구성 설명:

- `vault.address`: 에이전트가 접속하는 OpenBao 서버 주소입니다.
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
  자동 생성할 때 사용하는 루트 도메인입니다.

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
- `account_key_path`(선택): ACME **계정** 서명 키를 저장할 경로입니다. 설정하지
  않으면(기본값이자 기존 설정의 상태) 발급마다 새 계정 키를 만들어 계정을 다시
  등록하는 기존 동작을 유지합니다. 설정하면 해당 경로에서 키를 읽거나 없을 때
  `0600`으로 한 번 생성하므로, 갱신을 거듭해도 하나의 ACME 계정을 유지합니다.
  `bootroot init`이 bootroot 내부 registrar 자격 증명의 생성 설정에 이 값을
  넣어 주며, 그 밖의 경로에서는 자동으로 설정되지 않습니다.

### 신뢰

```toml
[trust]
ca_bundle_path = "/etc/bootroot/ca-bundle.pem"
trusted_ca_sha256 = ["<sha256-hex>"]
```

mTLS 신뢰와 **ACME 서버 TLS 검증**을 함께 다루는 섹션입니다.

#### 1) 개념 구분

1. **mTLS 신뢰**: 서비스가 상대 인증서를 검증할 때 사용할 신뢰 번들입니다.
   매 발급마다 bootroot-agent는 ACME 응답 체인을 `ca_bundle_path`에 이미
   있던 신뢰 인증서들과 지문 기준으로 중복 제거 후 병합하므로,
   `service add`가 시드한 루트가 그대로 보존됩니다.
2. **ACME 서버 TLS 검증**: bootroot-agent가 step-ca(ACME 서버)와 통신할 때
   서버 인증서를 검증하는 동작입니다. mTLS 신뢰와는 별도입니다.

#### 2) 핵심 설정

- `ca_bundle_path`: CA 번들(중간/루트) 저장 경로
- `trusted_ca_sha256`: 신뢰할 CA 인증서 지문 목록(SHA-256 hex)
- trust 두 값이 모두 있으면 bootroot-agent가 해당 번들과 지문으로
  ACME 서버를 검증합니다
- trust가 비어 있으면 `--insecure`를 쓰지 않는 한 시스템 CA 저장소로
  일반 검증을 수행합니다

`trusted_ca_sha256`는 임의 값이 아니라 실제 CA 인증서 지문이어야 합니다.

#### 3) `--delivery-mode` 연동

- `remote-bootstrap`: `bootroot service add`가 서비스별 trust 상태를
  OpenBao에 기록하고, `bootroot-remote bootstrap`이 첫
  `bootroot-agent` 실행 전에 서비스 머신에 `trusted_ca_sha256`와
  `ca_bundle_path`를 반영
- `local-file`: `bootroot service add`가 trust 설정을 `agent.toml`에
  자동 병합하고 `ca_bundle_path`를 기록하며, 실행 중인 에이전트의
  fast-poll 루프가 설정 파일과 번들 파일을 로컬에서 계속 동기화

#### 4) 실행 플래그 동작

- `--insecure`: 해당 실행에서만 ACME 서버 TLS 검증 비활성화
- 오버라이드가 없으면: 구성된 trust 또는 시스템 CA 저장소로 일반 검증

#### 5) 권장 운영 절차

목표: "먼저 trust를 준비하고, 검증이 켜진 상태로 `bootroot-agent`를 시작"

1. `bootroot init`을 실행해 OpenBao `secret/bootroot/ca`에
   `trusted_ca_sha256`와 `ca_bundle_pem`이 들어가게 합니다.
2. `bootroot service add`로 서비스를 추가합니다.
3. 첫 `bootroot-agent` 실행 전에 서비스 호스트에 trust를 반영합니다.
   - `local-file`: `bootroot service add`가 trust 설정과
     `ca-bundle.pem`을 로컬에 기록합니다.
   - `remote-bootstrap`: `bootroot-remote bootstrap`을 1회 실행해 같은
     trust payload를 원격 호스트에 반영합니다.
4. `--insecure` 없이 `bootroot-agent`를 시작합니다. managed onboarding
   흐름에서는 이미 정상 검증에 필요한 trust가 준비돼 있어야 합니다.
5. `--insecure`는 임시 진단이나 break-glass 상황에서만 사용합니다.

기본 Bootroot 배포에서는 step-ca가 HTTPS 엔드포인트에서 CA 인증서를 직접
제시할 수 있습니다. `trusted_ca_sha256`가 설정되면 bootroot-agent는
신뢰 번들로 이어지는 일반 HTTPS leaf뿐 아니라, 지문이 직접 pin된
인증서도 허용합니다.

#### 6) 실패/주의 사항

- `--insecure` 실행은 해당 실행에서만 검증을 우회
- 단일 step-ca 환경에서는 mTLS 번들과 ACME 검증에 같은 `ca_bundle_path` 재사용 가능

#### 7) 점검 체크리스트

- 어느 delivery mode에서든 trust가 비면 아래를 확인
- `secrets/certs/root_ca.crt`, `secrets/certs/intermediate_ca.crt` 존재 여부
- `bootroot init` 실행 시 동일 `secrets_dir` 사용 여부
- OpenBao `secret/bootroot/ca` 경로의 `trusted_ca_sha256`,
  `ca_bundle_pem` 존재 여부
- managed onboarding은 두 값이 모두 필요하며, 하나라도 없으면 trust를 복구할 때까지
  `bootroot service add` 또는 `bootroot-remote bootstrap`이 실패
- 두 전달 방식 모두, trust 갱신 후 실행 중인 `bootroot-agent`가 fast-poll
  루프로 OpenBao에서 `ca-bundle.pem`과 `[trust]` 핀을 다시 렌더하므로,
  서비스 호스트에서 수동 재부트스트랩이 필요하지 않습니다

권한 참고: `ca_bundle_path`는 이를 읽는 서비스가 접근 가능해야 합니다.
가장 단순한 방법은 bootroot-agent와 서비스를 같은 계정/그룹으로 실행하는
것입니다.

### 재시도 설정

```toml
[retry]
backoff_secs = [5, 10, 30]
```

발급/갱신 실패 시 재시도 간격입니다. 프로필별로 재정의할 수 있습니다.

### 레지스트라 엔드포인트 (Linux 전용)

```toml
[registrar_endpoint]
enabled = false
# server_cert_path = "/etc/bootroot/certs/registrar-endpoint.crt"
# server_key_path = "/etc/bootroot/certs/registrar-endpoint.key"
# client_cert_path = "/etc/bootroot/certs/registrar-client.crt"
# client_key_path = "/etc/bootroot/certs/registrar-client.key"
```

레지스트라의 `mint`/`deregister` 동사를 호스트 로컬 `AF_UNIX` 스트림
소켓으로 제공합니다. 기본값은 `false`이며, `[registrar_endpoint]` 테이블이
아예 없을 때도 마찬가지입니다. 이 설정은 bootroot-host 배포만을 위한
것입니다. 키는 정확히 다섯 개이며, 알 수 없는 키는 설정 오류입니다.

활성화가 지원됩니다. 데몬은 버전이 지정된 레지스트라 페이로드를
디코딩하고 동사를 호출한 뒤 그 결과를 인코딩하는 프로덕션 요청 핸들러를
등록하므로, 활성화된 엔드포인트는 정상적으로 기동하고 요청을 처리합니다.
다만 아래 `[registrar]` 키들이 갖춰져 있어야 합니다. `enabled = true`일 때
`state_file`은 **필수**이며, 프로비저닝 설정 파일·배포 상태 파일·내부
자격 증명·감사 저장소는 모두 기동 시점에 열립니다. 그중 하나라도 없거나
사용할 수 없으면, 소켓만 상속한 채 아무도 accept하지 않는 상태로 두는
대신 원인을 지목하는 진단과 함께 기동이 실패합니다.

!!! warning "`mint`는 아직 제공할 수 없습니다"
    `deregister`는 끝에서 끝까지 처리됩니다. `mint`는 그렇지 않습니다.
    mint 요청은 `reload`와 `cert_group`이 불투명한 문자열인 `spec`을
    싣는데, 이 두 문자열의 와이어 표기법은 이 저장소 밖에서 소유하며
    아직 확정되지도, `docs/reference/registrar-wire-contract.md`에
    전사되지도 않았습니다. 확정되기 전까지 모든 mint는 동사가 실행되기
    전에 거부되고 — 응답 바이트 0, 정상 종료 — 데몬은 어떤 변환이
    실패했는지를 로그로 남깁니다. 아무것도 발급되지 않으며, 어떤 표기도
    추측하지 않습니다.

소켓 경로 설정도, TCP 옵션도 의도적으로 없습니다. systemd가 저장소에
포함된 `systemd/bootroot-registrar.socket` 유닛으로
`/run/bootroot/registrar.sock`을 만들고 소유하며, 데몬은 이미 listen
상태인 디스크립터를 fd 3으로 상속받습니다. 데몬이 직접 소켓을 bind하거나
unlink하거나 권한을 바꾸는 일은 없습니다. 유닛과 소유권 요구 사항은
운영 문서의
[레지스트라 엔드포인트 (Linux 전용)](operations.md#registrar-endpoint-linux-only)를
참고하십시오.

#### 엔드포인트의 TLS 자재 {#the-endpoints-tls-material}

엔드포인트는 수락한 모든 연결에서 mTLS를 종단합니다. 따라서 활성화된
엔드포인트에는 자신의 서버 인증서가 필요하고, 호출자를 검증할 배포의 CA
자재도 필요합니다. 여기에 더해 **클라이언트** 인증서 — 같은 호스트의
레지스트라가 되돌려 인증할 때 쓰는 인증서 — 도 필요하며, 네 파일의 경로가
모두 이 테이블 하나에 들어 있습니다.

- **`server_cert_path`** 는 엔드포인트의 리프 인증서 **뒤에 발급자 체인이
  이어지는** PEM 파일입니다. 체인은 DER SHA-256이
  `trust.trusted_ca_sha256`에 들어 있는 인증서까지 올라가야 합니다. 리프의
  유일한 DNS SAN은
  `<instance>.bootroot-registrar-endpoint.<host>.<network.domain>`이어야
  합니다.
- **`server_key_path`** 는 그 리프의 개인 키 PEM입니다. 데몬은 기동 시
  그 키로 서명하고 리프의 공개 키로 검증해 둘이 한 쌍임을 증명합니다.
- **`client_cert_path`** 는 레지스트라의 클라이언트 리프
  `<instance>.bootroot-registrar.<host>.<network.domain>` 뒤에 발급자
  체인이 이어지는 PEM 파일입니다. **이것은 내부 구현 세부가 아니라 공개된
  계약입니다.** 같은 호스트의 레지스트라 프로세스가 이 파일을 읽고,
  호스트를 설치할 때 프로비저닝 도구가 *최초* 인증서를 이 경로에
  배치합니다. 디렉터리도 의미가 있습니다. 엔드포인트 앵커 핀 파일
  `registrar-endpoint-anchors.sha256`을 바로 이 파일 옆에서 찾으므로,
  클라이언트 인증서를 옮기면 호출자의 핀을 읽는 위치도 함께 옮겨집니다.
- **`client_key_path`** 는 그 리프의 개인 키 PEM입니다.
- 엔드포인트가 활성화되어 있으면 **`trust.ca_bundle_path`와
  `trust.trusted_ca_sha256`이 둘 다 설정되어 있어야 합니다.** 호출자는
  번들 전체가 아니라 *핀으로 지정된 부분집합* — 번들 안에서 SHA-256이
  목록에 있는 인증서 — 으로 검증됩니다. 그래서 번들에 인증서가 하나 늘어도
  접속 가능한 대상이 조용히 넓어지지 않으며, 번들에 핀에 맞는 인증서가
  하나도 없으면 모든 것을 신뢰하는 엔드포인트가 아니라 기동 거부가
  됩니다.

체인 요구 사항은 형식적인 것이 아닙니다. 호출자는 신뢰 앵커를 핀으로
지정하고 **서버가 실제로 제시한 인증서들 중에서** 앵커를 고르는 방식으로
이 엔드포인트를 검증합니다. 그래서 리프만 담긴 파일은 문제없이 로드되고,
키와도 맞고, 이름도 맞지만 — 올바르게 설정된 모든 호출자에게 거부당하며
데몬 쪽에는 아무 증상도 남지 않습니다. 그래서 데몬은 기동 시 호출자의
규칙을 자신의 자재에 그대로 적용하고, 리프만 있는 파일, 설정된 앵커까지
올라가지 못하는 체인, 만료됐거나 아직 유효하지 않거나 CA가 아닌 앵커에
대해 기동을 거부합니다.

#### 데몬이 기동 시 두 리프를 직접 발급합니다 {#the-daemon-issues-both-leaves-at-start}

두 이름 모두 `bootroot service add`로는 발급할 수 없습니다. 둘 다 예약된
`bootroot-` 네임스페이스에 속하고, 그 명령은 이를 거부하기 때문입니다.
그래서 데몬이 프로세스 기동마다 한 번, 엔드포인트의 TLS 자재를 로드하기
**전에**, 그리고 활성화된 소켓을 상속받기 전에 두 리프를 직접 발급합니다.
발급은 다른 모든 인증서와 같은, 로컬 step-ca로 나가는 ACME 경로를
사용합니다. 레지스트라 엔드포인트를 통하지 않으므로 아직 아무것도
listen하지 않는 최초 기동에서도 동작하며, 각 리프와 그 키는 각자의 설정된
경로 쌍에 기록됩니다.

발급은 **bootroot 내부 특권 자격 증명** — 데몬이 이미 OpenBao 인증에 쓰는
root 소유 클라이언트 인증서 — 으로 수행됩니다. 이 경로 어디에서도
`role_id`나 `secret_id`를 읽지 않습니다. 인증서 형태를 택한 이유 자체가
레지스트라 표면이 만료되는 비밀을 계속 살려 두지 않게 하려는 것입니다.

`registrar_endpoint.enabled`가 `false`인 호스트에서는 아무것도 발급하지
않습니다. 자재 경로를 만들지도 않고, CA나 OpenBao에 아무것도 요청하지
않습니다.

##### 사용 가능한 자재는 그대로 둡니다 {#usable-material-is-left-exactly-as-it-is}

설정된 경로의 인증서/키 쌍은 다음이 이 순서대로 모두 성립할 때 **사용
가능**합니다.

1. 두 파일이 모두 존재한다.
2. 두 파일을 모두 읽을 수 있다.
3. 두 파일이 모두 파싱된다 — 인증서 파일에서 인증서가, 키 파일에서 개인
   키가 나온다.
4. 키가 리프와 맞는다.
5. 리프의 DNS SAN이 정확히 하나이고, 그 쌍에 해당하는 예약된 이름이다.
6. 리프의 `not_before`가 이미 지났다.
7. 리프의 `not_after`가 아직 지나지 않았다.
8. `trust.ca_bundle_path`가 설정되어 있다면, 리프가 그 번들까지 체인이
   이어진다.

사용 가능한 쌍은 **다시 발급하지 않습니다.** 다시 발급하면 같은 호스트의
레지스트라가 읽고 있는 파일을 아무 이득 없이 흔들고, 데몬을 재시작할
때마다 그 프로세스에 새 키를 떠안기게 됩니다. 그래서 유효 기간 안에 있는
자재는 인증서와 키 모두 재시작을 바이트 단위로 동일하게 넘깁니다. 두 쌍은
독립적으로 판정합니다. 한쪽이 멀쩡하다는 사실은 다른 쪽을 사용 불가인 채로
두는 근거가 되지 않습니다.

위 목록을 한 조건씩 부정하면 여덟 가지 **사용 불가** 상태가 나오며, 데몬은
그 여덟 가지 모두를 기동 거부가 아니라 재발급으로 답합니다.

| 상태 | 이런 상황이 남깁니다 |
| --- | --- |
| 없음 | 최초 설치, 또는 손으로 지운 파일 |
| 읽을 수 없음 | 모드·ACL·소유권 드리프트 |
| 파싱 불가 | 쓰는 도중 전원이 나간 갱신 |
| 키 불일치 | 두 rename 사이에서 죽은 갱신 |
| SAN 불일치 | 그 경로에 놓인 다른 신원의 자재 |
| 아직 유효하지 않음 | CA보다 느린 호스트 시계 |
| 만료됨 | 리프의 `not_after`를 지나도록 내려가 있던 데몬 |
| 체인 드리프트 | 파괴적인 신뢰 앵커 교체 |

이 중 어느 하나라도 거부로 답한다면, 복구하려면 데몬이 떠 있어야 하는
바로 그 상태에서 데몬을 벽돌로 만드는 셈이 됩니다.

특히 만료는 데몬의 첫 갱신 틱에 맡기지 않고 엔드포인트의 TLS 자재가
로드되기 전, **기동 시점에** 복구합니다. 이는 현재 프로젝트 RFC 본문이
서술하는 복구 시점에서 의도적으로 벗어난 것입니다. 그 본문이 결정한
내용은 그대로 지켜집니다 — 복구는 데몬의 몫이고, 호스트를 다시
프로비저닝하는 일은 결코 아닙니다 — 바뀌는 것은 *데몬 자신의 생애주기
안에서 언제*인가뿐입니다. 첫 틱까지 미루면, 복구하려고 수행한 바로 그
재시작에서 활성화된 엔드포인트가 갱신 리드 타임 내내 서비스를 하지 못한
채로 남습니다.

##### ACME 입력은 어디에서 오는가 {#where-the-acme-inputs-come-from}

프로필 외에 두 값이 발급에 필요합니다. ACME 계정을 등록할 때 쓰는 **외부
계정 바인딩(EAB)** 과, 챌린지 게시를 인증하는 **HTTP-01 리스폰더
HMAC** 입니다. 둘 다 OpenBao에서 — 배포 상태 파일이 기록한 KV 마운트 아래
`bootroot/agent/eab`와 `bootroot/responder/hmac`에서 — bootroot 내부 자격
증명으로 읽으며, 메모리 안에서만 사용합니다. 어느 쪽도 디스크에 다시
기록하지 않습니다.

**대체 경로는 없습니다.** 이 `agent.toml`의 `[eab]`와
`[acme] http_responder_hmac`도, 내부 프로필의 렌더된 설정도, 서비스별
AppRole도, EAB 없이 발급하는 것도 아닙니다. 조용한 대체는 낡은 두 번째
출처를 눈에 띄지 않게 경로에 되돌려 놓지만, 거부는 그 사실을 말합니다.

이 읽기는 **실제로 발급이 필요한 리프가 있을 때만** 일어납니다. 자재가
멀쩡한 데몬은 두 쌍을 판정해 사용 가능함을 확인하고, OpenBao 요청도 CA
요청도 전혀 하지 않은 채 기동합니다. 그래서 OpenBao에 닿지 않아도 기동이
막히지 않습니다.

##### 인증서 준비 단계의 두 가지 거부 {#the-two-certificate-preparation-refusals}

인증서 준비는 활성화된 엔드포인트의 기동을 거부하는 방법을 정확히 **두
가지** 추가하며, 둘 사이에는 순서가 있습니다.

1. **필요한 `[registrar_endpoint]` 경로가 설정되지 않음.** `enabled = true`
   인데 `server_cert_path`, `server_key_path`, `client_cert_path`,
   `client_key_path` 중 하나라도 없으면 설정 검증 시점에 거부하며, 진단은
   빠진 키를 지목합니다. 상태 파일을 읽기 전, OpenBao에 요청하기 전,
   인증서를 요청하기 전, 활성화를 시도하기 전입니다. 기본값은 없으며,
   설정되지 않은 경로는 복구 가능한 상태가 아닙니다. 발급이 기록할 곳
   자체가 없기 때문입니다.
2. **발급 자체가 실패함.** 닿지 않는 CA, 실패한 OpenBao 읽기, 거부된
   인증서 로그인, 읽을 수 없는 상태 파일이나 내부 설정, 신뢰 교체로
   무효가 된 자격 증명, 또는 기록되지 못한 쓰기. 진단은 자재 경로와
   실패를 함께 밝힙니다. 어느 경로를 밝히는지는 기동이 어디까지
   갔는지에 달려 있습니다. 개별 발급 안에서 난 실패는 그 쌍을 밝히고,
   OpenBao 읽기와 자격 증명 적재는 두 쌍이 공유하므로 아직 발급이
   필요했던 모든 쌍을 밝히며, 읽을 수 없는 상태 파일이나 내부 설정은 두
   이름을 조합하는 호스트 레이블이 밝혀지기 전에 거부되므로 대신 설정된
   네 경로를 밝힙니다. 자체 서명 리프로도, 빌려 온 리프로도 대체하지
   않습니다.

두 번째 안에서 복구처럼 보이지만 복구가 아닌 세 경우는 따로 짚어 둘
가치가 있습니다.

- **기록되지 못하는 쓰기** — 디렉터리인 경로, 끊어졌거나 순환하는 심볼릭
  링크, 불변 파일, 만들 수 없는 상위 디렉터리, 데몬이 갖지 못한 권한 —
  는 기동을 실패시키며, 경로와 쓰기 오류를 지목합니다.
- **읽을 수 없는 `trust.ca_bundle_path`** 는 발급이 필요하다고 올바르게
  감지된 뒤, *게시 이전에* 실패합니다. 병합은 들여다볼 수 없는 번들을
  덮어쓰기를 거부하므로 리프는 기록되지 않고 번들도 바이트 단위로 그대로
  남습니다.
- **없거나 파싱되지 않는 `trust.ca_bundle_path`** 도 같은 방식으로
  감지되고 게시 이전에 실패하지만, 이유는 다릅니다. 그 이유는 이번
  발급보다 앞서 존재했고 에이전트가 갱신하는 모든 인증서에 똑같이
  적용됩니다. 이 번들이 ACME 디렉터리로 가는 TLS의 신뢰 앵커이므로,
  번들이 없으면 에이전트는 step-ca를 인증할 수 없고 아예 통신하지
  않습니다. 진단은 그 번들을 지목합니다. `trust.ca_bundle_path`에 배포의
  앵커가 다시 놓이면 — `bootroot init`과 fast-poll 신뢰 갱신이 넣어 주는
  것이 그것입니다 — 다음 기동에서 정상적으로 발급되고 병합이 파일을 다시
  채웁니다.

!!! warning "이 둘은 이 변경이 추가한 두 가지일 뿐, 데몬의 유일한 두 가지가 아닙니다"
    활성화된 엔드포인트의 기동은 아래의 모든 조건으로 여전히 거부되며,
    인증서 준비는 그중 어느 것도 건드리지 않습니다. 엔드포인트 기동이
    실패한 운영자는 원인이 위 두 가지 중 하나라고 단정해서는 안 됩니다.

최소한 다음은 그대로 남습니다.

- **Linux가 아닌 플랫폼 거부.** 위 두 가지보다 앞섭니다.
- **나머지 설정 검증.** `[registrar] state_file` 요구 사항과
  `[registrar]`·`[trust]` 테이블 자체의 검사를 포함합니다.
- **소켓 활성화** — 디스크립터, 그 주소, 소켓 경로의 소유권과 권한.
- **엔드포인트의 TLS 로더.** 그 수용 규칙은 위의 사용 가능 규칙보다
  엄격하게 강합니다. 데몬이 사용 가능하다고 판정한 쌍도, 체인이 비었거나
  앵커가 핀에 없거나 리프가 *이 호스트의* 시계 기준으로 유효 구간 밖이면
  곧이어 거부될 수 있습니다.
- **레지스트라 표면의 나머지** — 상태 파일, 시크릿 디렉터리, 프로비저닝
  설정과 그 다이제스트 게이트, 감사 저장소, 동사 리미터 — 는 나중에
  핸들러를 만들 때 열립니다.

특히 호스트와 CA 사이의 지속적인 시계 오차는 양방향으로 로더에
도달합니다. 호스트 시계가 충분히 *느리면* 갓 발급된 대체 리프가 아직
유효하지 않고, 충분히 *빠르면* 이미 만료된 상태가 됩니다. 데몬은 한 번
발급할 뿐 시계를 고치지도, 재시도하지도, 두 번째 검증기를 추가하지도
않습니다. 엔드포인트를 띄울 수 없으면 데몬 자체가 뜨지 않으므로,
호출자에게는 엔드포인트가 계속 닿지 않는 것으로 보이고, 해결책은 기동
진단이 지목하는 것 — CA 장애일 수도 있고, 똑같이 이 호스트의 시계일
수도 있습니다 — 입니다.

엔드포인트가 활성화된 상태에서 다음은 각각 **기동 거부**이며, 진단
메시지는 문제가 된 설정 키를 항상 밝히고 그 설정에 값이 있으면 설정된
경로도 함께 밝힙니다. `server_cert_path`·`server_key_path`·
`client_cert_path`·`client_key_path` 중 하나라도 설정되지 않음, 위 자가
점검이 거부하는 자재, 그리고 `trust.ca_bundle_path`가 없음·읽을 수
없음·파싱 불가·핀에 맞는 인증서 없음. 설정된 경로의 자재가
없음·읽을 수 없음·파싱 불가·키 불일치·SAN 불일치·유효 구간 밖·체인
드리프트인 경우는 이 목록에 **들어 있지 않습니다.** 그 각각은 로더가
보기 전에 위의 발급으로 복구됩니다.

`enabled`는 프로세스 수명 동안 고정됩니다. listen 디스크립터는 리로드
루프보다 앞에서 한 번만 상속되므로, 실행 중인 값과 다른 값으로 `SIGHUP`이
들어오면 그 리로드는 **거부**됩니다. 실행 중인 데몬은 현재 설정 그대로
계속 동작하고, 거부 사실이 로그에 남습니다. 값을 바꾸려면 서비스를
재시작해야 합니다.

**네 인증서 경로도 같은 이유로 고정됩니다.** 그중 하나라도 바꾸는
리로드는 바뀐 키를 밝히는 진단과 함께 거부됩니다. 자재는 리로드 루프보다
앞에서 한 번만 읽으므로, 리로드가 바꾼 경로는 아무도 읽지 않습니다. 그
경로의 *내용*은 고정이 아닙니다. 인증서 갱신은 재시작 없이 제시되는
자재를 교체합니다. 고정되는 것은 경로뿐입니다.

Linux가 아닌 대상에서는 테이블 자체는 파싱되지만, 활성화된 엔드포인트는
활성화 변수를 확인하기 전에 명시적인 미지원 플랫폼 오류로 설정 검증에
실패합니다.

### 레지스트라 감사 레코드 {#registrar-audit-records}

```toml
[registrar]
audit_store_dir = "/var/lib/bootroot/audit-store"
audit_store_reserve_bytes = 2147483648
audit_store_low_water_bytes = 536870912
audit_store_enforcement = "filesystem"
audit_record_dir = "/var/lib/bootroot/audit-store/records"
audit_max_file_bytes = 8388608
audit_max_retained_files = 16
audit_min_retain_days = 90
openbao_audit_max_file_bytes = 67108864
openbao_audit_max_retained_files = 7
openbao_audit_min_retain_days = 90

# 동사 속도 제한. 아래 "레지스트라 동사 속도 제한"을 참고하세요.
rate_limit_admission_burst = 512
rate_limit_admission_refill_interval_ms = 500
rate_limit_predecision_refusal_burst = 32
rate_limit_predecision_refusal_refill_interval_ms = 1000
```

`[registrar]` 테이블은 두 묶음의 키를 담습니다. 하나는 데몬이 레지스트라의
자체 감사 기록을 쓰는 감사 저장소이고, 다른 하나는 레지스트라 엔드포인트가
동사 계층을 구성할 때 쓰는 설정입니다. 데몬 실행 단위 전체가 다시
구성되므로 둘 다 `SIGHUP`마다 다시 읽히며, 프로세스 수명 동안 고정되는
값은 `[registrar_endpoint] enabled` 하나뿐입니다.

`state.json`이 `registrar_endpoint.enabled = true`를 기록한 호스트에서는
root로 실행한 `bootroot init`이 `audit_store_dir`과 그 아래의 `records/`,
`openbao/`를 생성합니다. 저장소는 uid 0 소유에 모드 `0700`이므로 이 실행은
반드시 root여야 합니다. 레지스트라 엔드포인트가 활성화되지 않은 호스트에는
여전히 저장소가 없습니다.

감사 저장소는 레지스트라 엔드포인트가 활성화된 경우에만 열립니다. 동사를
제공하지 않는 호스트는 아무것도 만들지 않습니다.

bootroot는 레지스트라의 `mint`/`deregister` 동사에 대해 자체 추가 전용
감사 기록을 남깁니다. 이는 OpenBao의 필수 파일 감사 장치를 대체하지
않고 **함께** 동작합니다. OpenBao 장치는 OpenBao가 무엇을 하라는 요청을
받았는지 기록하고, 이 기록은 누가 어떤 `(service_name, host, instance)`
조합을 요청했으며 결과가 무엇이었는지를 남깁니다. OpenBao 쓰기가
일어나기 전에 거부된 요청도 여기에 남습니다. `bootroot init`이 수행하는
OpenBao 감사 장치 확인은 그대로입니다.

이 산출물의 소유자는 데몬입니다. 레지스트라는 이 파일을 읽거나, 추가하거나,
삭제하거나, 다른 경로로 돌리거나, 선택할 수 없으며, 요청의 어떤 필드도
경로·권한·회전 정책·보존 정책에 닿지 않습니다. `[registrar]` 테이블이 아예
없으면 기본값이 없는 `state_file`을 뺀 모든 키가 위 기본값을 사용하고,
알 수 없는 키는 설정 오류입니다.

- `audit_store_dir` (기본값 `/var/lib/bootroot/audit-store`) — 데몬 레코드용
  `records/`와 OpenBao 파일 감사 출력용 `openbao/`를 담는 절대 경로입니다.
  상대 경로는 거부됩니다. 이 키가 저장소 위치에 대한 **유일한 정의**이며,
  어디에도 두 번째 사본이 기록되지 않습니다. 설치 측은
  `bootroot init --agent-config <path>`를 통해 이 값을 읽습니다. 이
  플래그는 레지스트라 엔드포인트가 활성인 호스트에서 필수이므로, 그
  실행보다 이 파일이 먼저 존재해야 합니다.
  [공용 감사 저장소](operations.md#공용-감사-저장소)를 참고하세요.
- `audit_store_reserve_bytes` (`u64`, 기본값 `2147483648`, 2 GiB) — 공유
  저장소의 구성된 예산입니다. `i64::MAX`를 넘을 수 없으며, 이 빌드에서는
  예산을 기록할 뿐 강제하지 않습니다.
- `audit_store_low_water_bytes` (`u64`, 기본값 `536870912`, 512 MiB) —
  향후 용량 경보 임계값입니다. reserve보다 작아야 합니다.
- `audit_store_enforcement` (기본값 `filesystem`) — 향후 파일시스템 기반
  상한 또는 강제되지 않는 `directory` 예산을 선택합니다. 이 빌드에서는 두
  모드 모두 구현되지 않았습니다.
- `audit_record_dir` (기본값 `<audit_store_dir>/records`) — 레코드 파일이
  놓이는 절대 경로 디렉터리입니다. 상대 경로는 거부되며, 해석된 경로는
  `audit_store_dir` 안에 있어야 합니다.
- `audit_max_file_bytes` (기본값 `8388608`, 8 MiB) — 활성 파일을
  회전시키는 크기입니다. 최소 `65536`이어야 합니다.
- `audit_max_retained_files` (기본값 `16`) — 활성 파일 옆에 보관하는
  회전 세대 수입니다. 0보다 커야 합니다.
- `audit_min_retain_days` (기본값 `90`) — 보존 **목표** 일수입니다.
  0보다 커야 합니다.

다음 세 개는 OpenBao **자신의** 파일 감사 장치를 제한하며, 엔드포인트가
활성화된 호스트에서 데몬이 이를 로테이션합니다. 위의 세 키를
재사용하지 않고 별도 키로 둔 이유는 두 writer의 분량이 서로 무관하기
때문입니다. 한쪽은 레지스트라 호출당 한정된 한 줄이고, 다른 쪽은 배포
전체의 OpenBao 요청당 한 항목입니다.
[감사 장치 로테이션](operations.md#rotating-the-audit-device)을
참고하세요.

- `openbao_audit_max_file_bytes` (`u64`, 기본값 `67108864`, 64 MiB) —
  장치의 활성 로그를 로테이션하는 크기입니다. 최소 `1048576`(1 MiB)이어야
  합니다. 이 하한은 `audit_max_file_bytes`의 64 KiB와 달리 최대 레코드
  크기에서 **유도된 값이 아닙니다.** bootroot는 OpenBao 감사 항목의 크기를
  통제하지 않으므로 곱할 최대 항목 크기가 없습니다. 이 하한은 로테이션이
  60초 검사마다 일어나는 일이 아니라 드문 사건으로 남게 하기 위해
  존재합니다.
- `openbao_audit_max_retained_files` (`u32`, 기본값 `7`) — 활성 로그 옆에
  보관하는 로테이션 세대 수이며, 활성 로그 자체는 포함하지 않습니다.
  0보다 커야 합니다.
- `openbao_audit_min_retain_days` (`u32`, 기본값 `90`) — 보존 **목표**
  일수입니다. 0보다 커야 합니다. 크기 상한이 항상 우선하므로 바쁜
  배포에서는 이 목표가 흔히 충족되지 않습니다. 이는 의도된 동작이며 경보를
  발생시키지 않습니다.

**기본값은 예약 용량에서 유도되었습니다.** 보존 집합의 하드 상한은
`openbao_audit_max_file_bytes × openbao_audit_max_retained_files` =
448 MiB입니다. 정상 모델에서 장치는 패스 사이에 약 512 MiB, 패스 내부
최고점에 약 576 MiB입니다. 동사 레코드 저장소의 파일군은
`audit_max_file_bytes × (audit_max_retained_files + 1)` = 136 MiB이며,
스테이징 사본이 없으므로 두 배 항도 없습니다. 합하면 2 GiB
`audit_store_reserve_bytes` 안의 712 MiB로, 약 1.3 GiB의 여유가 남습니다.
정상 상태에서 이 두 writer가 512 MiB 저수위 경보에 닿으려면 쓰기 항이
824 MiB — 60초 주기 동안 초당 약 6.9 MiB의 지속 감사 출력 — 에
이르러야 합니다. 주기나 두 한계, 메커니즘을 바꾼다면 이 계산을 다시
유도하세요. 이는 경보가 곧 제3의 writer를 뜻한다는 증거가 **아닙니다.**
로테이션이 멈추면 이 두 writer만으로도 경보 지점을 넘어섭니다.

`openbao_audit_max_file_bytes × (openbao_audit_max_retained_files + 1)`이
64비트 정수에 들어가지 않는 설정은 두 키를 모두 명시하며 로드 시점에
거부됩니다. 그래야 로테이션의 예산 산술이 런타임에서 결코 오버플로하지
않습니다. 16 EiB를 넘는 파일군은 배포가 아니라 오타이며, 대신 포화시키면
예산이 `u64::MAX`가 되어 아무런 한계도 아니게 됩니다.

#### 동사 계층 설정

아래 여덟 개 키는 엔드포인트가 제공하는 레지스트라 동사를 구성합니다. 이
키들은 **조건 없이** 모든 호스트에서 검증됩니다. 엔드포인트 활성화 여부와
무관하게 잘못된 값은 설정 오류입니다. 두 테이블을 잇는 규칙은
`state_file` 하나뿐이며, 방향도 한쪽입니다. `[registrar_endpoint]
enabled = true`일 때 필수라는 것입니다.

```toml
[registrar]
state_file = "/opt/bootroot/state.json"
provisioning_config_path = "/etc/clumit-security/provisioning.toml"
max_wrap_ttl = "30m"
role_token_ttl = "1h"
role_secret_id_ttl = "24h"
secret_id_num_uses = 0
# secret_id_ttl = "10m"
# secret_id_token_bound_cidrs = ["10.0.0.0/8"]
```

- `state_file` (**기본값 없음**) — `bootroot init`이 기록한 `state.json`의
  절대 경로입니다. 동사가 필요로 하는 세 값, 즉 기록된 `openbao_url`과
  `kv_mount`, 그리고 선택적인 `secrets_dir`의 유일한 출처입니다. 이 셋을
  위한 개별 키는 의도적으로 없습니다. `init`과 `rotate`가 최신 상태로
  유지하는 파일 하나만 두는 것이, URL이나 마운트가 두 곳에 적혀 서로
  어긋나는 일을 막습니다. 상대 경로는 거부됩니다. `secrets_dir` 멤버가
  없으면 `secrets`로 해석되며, 상대 경로인 경우 — 그 기본값을 포함해 —
  데몬의 작업 디렉터리가 아니라 **상태 파일 자신의 디렉터리**를 기준으로
  해석됩니다. 소켓으로 활성화된 유닛에는 기준으로 삼을 만한 작업
  디렉터리가 없기 때문입니다. 이 키가 없어도 엔드포인트가 비활성화되어
  있으면 정상적으로 로드되며, 활성화된 상태에서는 두 키를 모두 지목하는
  설정 오류가 됩니다. 파일은 활성화된
  경로에서만 실행 단위마다 한 번 읽히므로 다시 쓰인 `state.json`은 다음
  `SIGHUP`부터 적용되고, 읽는 멤버는 위 셋뿐입니다. 나머지 멤버는 모두
  무시되며 어떤 멤버도 되쓰지 않습니다.
- `provisioning_config_path` (기본값
  `/etc/clumit-security/provisioning.toml`) — 프로비저닝 도구가 렌더링한
  레지스트라 설정 파일의 절대 경로입니다. bootroot는 이 파일을 읽기만
  하며, 그 형식은 저장소 간 계약입니다. 상대 경로는 거부되고, 파일이
  없거나 다이제스트가 어긋나면 기동이 실패합니다.
- `max_wrap_ttl` (기본값 `"30m"`) — 요청된 `wrap_ttl`이 허용되는
  상한입니다. 이보다 긴 요청은 거부되지 않고 이 값으로 잘립니다.
  `OpenBao` 기간 범위 안의 양의 정수 초여야 하며, 요청에 적용되는 바로 그
  정책에 넘겨서 검증하므로 둘이 어긋날 수 없습니다.
- `role_token_ttl` (기본값 `"1h"`) — mint가 만드는 `AppRole`의 역할 수준
  `token_ttl`입니다. 양의 정수 초여야 합니다.
- `role_secret_id_ttl` (기본값 `"24h"`) — 역할 수준 `secret_id_ttl`입니다.
  양의 정수 초여야 합니다.
- `secret_id_num_uses` (기본값 `0`) — 발급된 `secret_id` 하나를 몇 번 쓸 수
  있는지입니다. `0`은 TTL 안에서 무제한을 뜻하며, 등록된 호스트에 필요한
  값이 바로 이것입니다. 그 호스트의 에이전트는 갱신마다, 그리고 fast-poll
  주기마다 `AppRole` 로그인으로 재인증하므로, 한 번만 쓸 수 있는 자격
  증명은 한 번 동작한 뒤 서비스가 로그인할 수 없게 만듭니다.
- `secret_id_ttl` (**선택**, 기본값 없음) — 발급 단위 TTL입니다. 없으면
  역할 수준 `role_secret_id_ttl`이 적용되며, 이는 `--secret-id-ttl` 없이
  실행한 `bootroot service add`의 동작과 같습니다. 지정하는 경우 양의
  정수 초여야 합니다.
- `secret_id_token_bound_cidrs` (**선택**, 기본값 없음) — 발급된 자격
  증명의 토큰을 묶을 CIDR 목록입니다. 지정하는 경우 모든 항목이 비어
  있지 않아야 합니다.

여기의 모든 기간 값은 `openbao.fast_poll_interval`과 똑같이 humantime
문자열 — `"30m"`, `"1h"`, `"24h"` — 입니다. 초 단위 정수만 적는 형식은
계약이 아니므로 거부되며, `OpenBao` 자체 표기법도 마찬가지입니다. 값은
넘겨줄 때 `OpenBao`의 `<n>s` 형식으로 변환됩니다.

`secret_id` 메타데이터를 위한 키는 의도적으로 **없습니다**. `OpenBao`는
조회 시 메타데이터를 그대로 돌려주는데, 누가 무엇을 요청했는지에 대한
bootroot 자신의 기록은 위의 감사 기록입니다. 발급되는 모든 자격 증명에
운영자가 직접 입력한, 검증되지 않는 두 번째 기록을 붙이는 것은 이
엔드포인트가 늘릴 손잡이가 아닙니다. 배포의 활성 루트 지문을 위한 키도
없습니다. 이 값은 `<secrets_dir>/certs/root_ca.crt`에서 유도됩니다.

`audit_max_file_bytes`에 64 KiB 하한이 있는 이유는 레코드 하나의 최악
크기가 정해져 있고, 갓 회전된 파일이 그 하나를 반드시 담을 수 있어야 하기
때문입니다. 레코드에서 공격자가 영향을 줄 수 있는 문자열 — 호출자 신원,
요청된 `service_name`과 `host`, 거부 상세 — 은 각각 512바이트로 제한되며,
제어 문자 한 바이트가 여섯 바이트짜리 `\u0000` 이스케이프가 될 수
있으므로 하한은 512바이트 원본 길이가 아니라 이스케이프된 길이로
계산합니다. 그럼에도 설정된 한도의 빈 파일에 들어가지 못하는 레코드는
직렬화된 길이만으로 거부되며, 저장소가 무엇도 열거나 만들기 전에
거부되므로 기록과 그 디렉터리는 있던 그대로 남습니다.

`audit_min_retain_days`는 `bootroot status`가 보고하는 보존 *목표*입니다.
둘이 어긋나면 `audit_max_retained_files`가 이깁니다. 파일 개수는 하드
용량 제약이고 일수는 그렇지 않기 때문입니다.

#### 소유권과 권한

저장소는 레지스트라 표면이 요청을 받기 전에 열리며, 성능을 낮춰 계속
동작하는 대신 닫힌 상태로 실패합니다.

- 없는 경로 구성 요소는 root 소유 `0755`로 만들고, 저장소 디렉터리 자체는
  root 소유 `0700`으로, 활성 파일은 `0600`으로 만듭니다. 이미 존재하는
  항목의 소유자와 권한은 절대 바꾸지 않습니다.
- 운영 환경에서는 검사 대상 경로가 모두 uid 0 소유여야 합니다.
- 저장소 디렉터리, 그 직속 상위 디렉터리, 활성 파일, 모든 회전 세대는
  심볼릭 링크이거나 다른 uid 소유이면 거부됩니다. 저장소 디렉터리와 직속
  상위 디렉터리는 그룹 또는 다른 사용자에게 쓰기 가능해도 거부됩니다.
- 직속 상위 디렉터리보다 위쪽은 검사하지도, 변경하지도 않습니다.

`audit_record_dir`는 공유되거나 사용자가 쓸 수 있는 경로가 아니라 bootroot
호스트 자체 저장소의 `audit_store_dir` 안을 가리켜야 합니다.

#### 레코드 형식

기록은 버전이 붙은 JSON Lines 계열 하나를 사용합니다. 활성 파일은
`registrar-audit.jsonl`이고, 각 줄은 완전한 JSON 객체 하나 뒤에
개행이 붙은 형태입니다. 따옴표·역슬래시·제어 문자·개행은 JSON
이스케이프되므로 레코드 하나는 언제나 정확히 한 줄입니다.

```json
{"record_version":1,"phase":"intent","ts":"2026-08-23T12:34:56.789Z","request_id":"9RmA…0","verb":"mint","caller_identity":"spiffe://review/manager#7f3a","requested":{"service_name":"review","host":"h1","instance":7}}
{"record_version":1,"phase":"outcome","ts":"2026-08-23T12:34:56.930Z","request_id":"9RmA…0","verb":"mint","caller_identity":"spiffe://review/manager#7f3a","requested":{"service_name":"review","host":"h1","instance":7},"registration_id":"review-h1-007","outcome":{"class":"first_mint"}}
```

- `record_version`은 이 형식의 모든 레코드에서 `1`입니다. 데몬은
  다른 버전의 레코드를 아예 기록하지 않으므로, 이 파일 계열 안에서
  형식 버전이 섞이는 일은 없습니다.
- `phase`는 정확히 `intent` 또는 `outcome`입니다. 두 단계 모두 신원
  필드를 온전히 담으므로, 짝이 되는 줄이 회전으로 사라진 뒤에도 각 줄을
  그대로 읽을 수 있습니다.
- `ts`는 밀리초 정밀도의 RFC 3339 UTC 타임스탬프이며, 소수점 이하는 항상
  세 자리이고 시간대 표기는 항상 `Z`입니다. 이 형식이 인정하는 표기는
  이것 하나뿐입니다. 데몬은 밀리초보다 정밀하거나 UTC가 아닌 오프셋을
  가진 타임스탬프를, 나머지 자리를 자르거나 오프셋을 바꿔 기록하지 않고
  아예 거부합니다. 그래서 저장된 줄은 언제나 기록 대상이던 값 그대로
  다시 읽히며, 이 형식을 읽는 쪽도 데몬이 쓴 표기만 받아들입니다.
- `verb`는 정확히 `mint` 또는 `deregister`입니다.
- `caller_identity`는 호출자의 신원을 그대로 담습니다.
- `requested`는 `service_name`, `host`, `instance`를 담습니다. `instance`는
  JSON 숫자이며, 요청에 없으면 키 자체가 생략됩니다.
- `registration_id`는 파생이 끝나기 전에는 생략됩니다. `null`이나 빈
  문자열로 기록되는 일은 없습니다.
- `outcome`은 `outcome` 줄에만 있고 `intent` 줄에는 없습니다. 데몬은 이
  짝이 어긋난 레코드를 아예 기록하지 않으므로, 파일 안에서 둘이 어긋나는
  일은 없습니다. `class`로 태깅된 객체이며 `first_mint`,
  `idempotent_remint`, `identity_removed`, `idempotent_already_absent`,
  `refused` 중 하나이고, 거부일 때는 `reason`이, 있을 때는 `detail`이
  덧붙습니다.
- `truncated`는 무언가 잘렸을 때만 존재합니다. 키는 필드 경로
  `caller_identity`, `requested.service_name`, `requested.host`,
  `outcome.detail`이며, 각 값은 원본 전체 바이트에 대한
  `{"full_sha256":"<소문자 16진수 64자>","full_bytes":<정수>}`입니다.
  길이를 초과한 값도 이것으로 대조하고 실제 길이를 보고할 수 있습니다.

#### 회전과 보존

활성 파일은 `audit_max_file_bytes`를 넘기게 될 추가 쓰기 **직전에**
회전하며, 저장소를 열 때 이미 한계에 도달했거나 넘긴
파일은 저장소를 쓸 수 있게 되기 전에 회전합니다. 회전 세대의 이름은
다음과 같습니다.

```text
registrar-audit-<YYYYMMDDTHHMMSSZ>-<NNNNNN>.jsonl
```

타임스탬프는 초 정밀도 UTC이고, 0으로 채운 여섯 자리 일련번호는 매
타임스탬프마다 `000000`에서 시작해 같은 초에 충돌이 생기면 증가합니다.
예를 들어 `registrar-audit-20260823T123456Z-000000.jsonl` 다음에
`registrar-audit-20260823T123456Z-000001.jsonl`이 옵니다. 두 부분 모두
너비가 고정이므로 이름이 사전순으로 오래된 것부터 최신 순으로 정렬됩니다.

저장소를 열 때와 회전할 때마다, 남은 세대가
`audit_max_retained_files` 이하가 될 때까지 사전순으로 가장 오래된 것부터
삭제합니다. 파일을 새로 만들거나 회전할 때는 파일 데이터와 상위
디렉터리를 모두 flush하므로 새 이름이 전원 장애로 사라지지 않습니다.
일반적인 추가 쓰기는 데이터만 flush합니다.

기록하려는 레코드에 필요한 회전이 실패하면 오류이며 레코드는 기록되지
않습니다. 회전 마지막 단계인 디렉터리 flush가 실패한 경우도 마찬가지로,
디스크에 닿은 쓰기가 아니라 회전 실패로 보고합니다. 보존 정리(trim) 실패는 `tracing`으로 로그에 남고, 공간이
충분한 추가 쓰기를 실패시키지 **않습니다**.

실패한 디렉터리 flush는 빚으로 남습니다. 다음 추가 쓰기는 파일이 이미
있다는 사실만으로 그 이름이 안전하다고 결론짓지 않고 디렉터리를 다시
flush합니다. flush된 디렉터리 항목과 그렇지 않은 항목은 디스크상에서
구분되지 않으므로, 빚을 남긴 채 종료한 데몬은 그 빚을 다음 기동으로
넘깁니다. 저장소를 열 때 레코드를 하나라도 추가하기 전에 디렉터리를 한 번
flush하며, 디렉터리를 flush할 수 없는 저장소는 열리지 않습니다.

#### 기본값 용량 산정

기본값의 하드 상한은 8 MiB × 17개 파일(활성 파일 1개와 회전 세대 16개),
즉 약 **136 MiB**입니다.

기준 배포 용량 산정은 한 줄당 **400바이트**라는 일반
레코드 가정을 사용합니다. 호출 한 번마다 `intent`와 `outcome` 두 줄이
기록됩니다.

```text
2 × (초기 호출 2,000회 + 90일 × 일 200회) = 40,000개 레코드
40,000 × 400바이트 = 16,000,000바이트 ≈ 16 MB (≈ 15.3 MiB)
```

즉 초기 등록 2,000건에 하루 200회를 처리하는 플릿이라면 90일 목표 전체가
기본 상한의 약 8분의 1 안에 들어갑니다. 이는 **일반적인 설치·재설치
활동**을 기준으로 한 값이며 거부 폭주를 기준으로 한 값이 아닙니다.
거부된 요청을 반복 재시도하는 호출자는 재시도 속도만큼
레코드를 만들며, 그때 디스크 사용량을 제한하는 것은
`audit_min_retain_days`가 아니라 파일 개수 상한입니다.

### 레지스트라 동사 속도 제한

이 네 개의 키는 위의 `[registrar]` 테이블에 들어 있으며, 한 클라이언트
신원이 `mint`/`deregister` 동사를 얼마나 빠르게 호출할 수 있는지를
제한합니다. 거부되는 호출을 대량으로 밀어 넣는 호출자가 레코드 저장소를
한없이 키우지 못하게 하기 위한 것입니다. 이 빌드의 bootroot는 레지스트라
동사 요청을 처리하지 않으므로 아직 이 버킷에 부과되는 호출은 없으며, 키는
지금도 로드되고 검증됩니다.

동사마다 클라이언트 신원별로 토큰 버킷이 둘 있습니다. 하나는 bootroot의
순수 로컬 검사만으로 거부되는 호출용이고, 다른 하나는 그 검사를 통과해
OpenBao에 닿을 수 있는 호출용입니다. 각 버킷은 가득 찬 상태로 시작해
메모리에만 존재하며, 버스트를 상한으로 리필 간격마다 토큰 하나씩
쌓입니다. 이 분리가 보장하는 것과 보장하지 않는 것, 제한된 호출자에게
보이는 것, 기준 배포보다 큰 플릿에서 버스트를 산정하는 방법은
[레지스트라 동사 속도 제한](operations.md#registrar-verb-rate-limiting)에
있습니다.

- `rate_limit_admission_burst` (`u32`, 기본값 `512`) — 로컬 검사를 통과한
  호출을 한 클라이언트 신원이 한 번에 얼마나 밀어 넣을 수 있는지입니다.
  `wave_hosts × modules_per_host`로 잡으며, 기본값은 기준 배포의 호스트
  64대 × 모듈 8개입니다.
- `rate_limit_admission_refill_interval_ms` (`u32`, 기본값 `500`) —
  admission 토큰 하나가 쌓이는 밀리초 간격입니다. 기본값은 초당 두 건을
  지속합니다.
- `rate_limit_predecision_refusal_burst` (`u32`, 기본값 `32`) — 로컬에서
  거부되는 호출의 같은 예산입니다. 이 경로의 정상적인 거부는 운영자의
  오타가 하나씩 도착하는 것이므로 훨씬 작습니다.
- `rate_limit_predecision_refusal_refill_interval_ms` (`u32`, 기본값
  `1000`) — 초당 거부 토큰 하나를 지속합니다.

모두 부호 없는 정수이며, 속도는 분수 비율이 아니라 토큰당 밀리초 간격으로
표현해 설정 표면에 부동소수점 값이 하나도 없도록 했습니다. 네 키 모두 0은
로드 시점에 거부됩니다. 버스트가 0이면 첫 정상 호출부터 제한되고, 간격이
0이면 토큰이 무한히 공급되어 속도 제한기가 조용히 무력화되기 때문입니다.
음수나 소수 값도 마찬가지로 문제의 키 이름과 함께 거부됩니다.

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

`registration_id`는 필수이며, 이 프로필이 폴링하는 모든 네임스페이스의
이름이 여기에서 파생됩니다 — `bootroot/services/<registration_id>/…` KV
서브트리와 프로필별 fast-poll 상태 파일 이름입니다. 영소문자/숫자/하이픈만
허용하며, 영숫자로 시작하고 끝나야 하고, 최대 131자입니다. 이 키를 생략한
`[[profiles]]` 블록은 로드에 실패합니다. 인증서 필드가 아니라는 점이
의도적입니다: SAN의 두 번째 label은 계속 `service_name`이므로, 한 호스트에
있는 같은 컴포넌트의 여러 등록은 `service_name`을 공유하고
`registration_id`로만 구분됩니다.

```toml
[[profiles]]
registration_id = "edge-proxy"
service_name = "edge-proxy"
instance_id = "001"
hostname = "edge-node-01"

[profiles.paths]
cert = "certs/edge-proxy-a.pem"
key = "certs/edge-proxy-a.key"

[profiles.daemon]
check_interval = "1h"
renew_before = "16h"
check_jitter = "0s"
```

DNS SAN은 `<instance-id>.<service-name>.<hostname>.<domain>` 형식으로
자동 생성됩니다. 이 이름은 HTTP-01 검증 대상이므로, step-ca에서
HTTP-01 리스폰더 IP로 해석되어야 합니다. Compose 환경에서는 `bootroot service add`가
`bootroot-http01` 컨테이너에 별칭을 자동 등록합니다. 베어메탈 환경에서는
`/etc/hosts` 또는 DNS를 수동으로 설정하세요.

`service_name`과 `hostname`은 각각 단일 DNS label입니다. 영문자, 숫자,
하이픈만 쓸 수 있고 최대 63 옥텟입니다. 둘 중 하나라도 규칙을 어기면
설정 로드 단계에서 거부되므로, 잘못된 SAN 구성 요소가 나중에 ACME 주문
거부로 드러나지 않습니다.

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

훅은 `agent.toml`을 직접 편집하는 대신
`bootroot service add` 시점에 CLI 플래그로도
설정할 수 있습니다. 일반적인 리로드 패턴에는
프리셋 플래그 `--reload-style`과
`--reload-target`을 사용하고(예:
`--reload-style systemd --reload-target nginx`),
세부 제어가 필요하면 저수준 플래그
`--post-renew-command`, `--post-renew-arg`,
`--post-renew-timeout-secs`,
`--post-renew-on-failure`를 사용합니다.
이 플래그들은 관리 대상 프로필에 대응하는
`[profiles.hooks.post_renew]` 항목을 생성합니다.
`remote-bootstrap` 전달 모드에서는 동일한
플래그가 `bootroot-remote bootstrap`으로
전달됩니다.
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
- `--insecure`: ACME 서버 TLS 검증 비활성화(기본값 `false`)

그 외 설정(프로필, 재시도, 스케줄러, 훅, CA 번들 경로 등)은
`agent.toml`에 정의해야 합니다.

데몬 모드에서는 발급 재시도 시 설정 파일을 디스크에서 다시 읽습니다.
CLI로 전달한 값은 매 재시도마다 다시 적용되므로, 예를 들어
`--http-responder-hmac`으로 전달한 값은 첫 시도뿐 아니라 이후
모든 재시도에서도 유지됩니다.

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
max_token_ttl_secs = 900
cleanup_interval_secs = 30
max_skew_secs = 60
admin_rate_limit_requests = 300
admin_rate_limit_window_secs = 60
admin_body_limit_bytes = 8192
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
- `max_token_ttl_secs`: 요청에 포함된 `ttl_secs`의 상한입니다. 이 값을 넘는
  요청은 HMAC 검증 후 거부하지 않고 이 상한으로 잘라서(clamp) 저장합니다.
  (기본값 `900`, 환경 변수: `BOOTROOT_RESPONDER__MAX_TOKEN_TTL_SECS`, 0은
  허용되지 않으며 `token_ttl_secs` 이상이어야 함)
- `cleanup_interval_secs`: 만료 토큰 정리 주기(초, 기본값 `30`, 환경 변수:
  `BOOTROOT_RESPONDER__CLEANUP_INTERVAL_SECS`, 0은 허용되지 않음)
- `max_skew_secs`: 관리자 요청 허용 시계 오차(초, 기본값 `60`, 환경 변수:
  `BOOTROOT_RESPONDER__MAX_SKEW_SECS`, 0은 허용되지 않음)
- `admin_rate_limit_requests`: 한 rate-limit window 안에서 허용되는 성공한
  관리자 토큰 등록 수입니다. 이를 넘는 요청은 HTTP `429 Too Many Requests`로
  거부됩니다. (기본값 `300`, 환경 변수:
  `BOOTROOT_RESPONDER__ADMIN_RATE_LIMIT_REQUESTS`, 0은 허용되지 않음)
- `admin_rate_limit_window_secs`: 관리자 rate-limit window 길이(초, 기본값
  `60`, 환경 변수: `BOOTROOT_RESPONDER__ADMIN_RATE_LIMIT_WINDOW_SECS`, 0은
  허용되지 않음)
- `admin_body_limit_bytes`: 관리자 등록 요청 본문 최대 크기입니다. 이 값을
  넘는 요청은 HTTP `413 Payload Too Large`로 거부됩니다. (기본값 `8192`,
  환경 변수: `BOOTROOT_RESPONDER__ADMIN_BODY_LIMIT_BYTES`, 0은 허용되지 않음)
