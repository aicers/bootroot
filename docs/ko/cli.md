# CLI

이 문서는 Bootroot 자동화를 위한 CLI(`bootroot`, `bootroot-remote`) 사용 방법을 정리합니다.

## 개요

CLI는 infra 기동/초기화/상태 점검과 서비스 온보딩, 발급 검증,
시크릿 회전을 제공합니다.
또한 Prometheus/Grafana 기반 로컬 모니터링을 관리합니다.
역할:

- `bootroot`: step-ca가 동작하는 머신에서 infra/init/service/rotate/monitoring 자동화
- `bootroot-remote`: 원격 서비스가 동작하는 머신에서 일회성 bootstrap 및
  명시적 secret_id 전달 수행

주요 명령:

- `bootroot infra install`
- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot service add`
- `bootroot service update`
- `bootroot service info`
- `bootroot verify`
- `bootroot rotate`
- `bootroot clean`
- `bootroot openbao save-unseal-keys`
- `bootroot openbao delete-unseal-keys`
- `bootroot monitoring`
- `bootroot-remote bootstrap`
- `bootroot-remote apply-secret-id`

## 공통 옵션

- `--lang`: 출력 언어 (`en` 또는 `ko`, 기본값 `en`)
  - 환경 변수: `BOOTROOT_LANG`

표기 규칙: 옵션 설명에 `(환경 변수: ...)`가 있으면 해당 옵션이 환경 변수 입력을
지원한다는 뜻입니다. 옵션 설명에 `(기본값 ...)`가 있으면 코드에 기본값이
정의되어 있다는 뜻입니다. 위 표기가 없으면 해당 항목은 기본값이 없거나
(필수/선택 입력) 환경 변수 입력을 지원하지 않습니다.

## bootroot CLI 자동 준비 범위와 운영자 책임

bootroot CLI가 자동으로 설치/기동해 주는 항목(Docker 방식):

- `bootroot infra up` 기준 OpenBao/PostgreSQL/step-ca/HTTP-01 responder
  컨테이너의 이미지 pull, 생성, 기동 및 `state.json`에 등록된 HTTP-01
  DNS 별칭 재적용
  (서비스 이미지 build가 필요한 경우 별도 `docker compose build` 수행 필요)
- `bootroot service add` 기준 서비스의 HTTP-01 검증 FQDN을
  `bootroot-http01` 컨테이너에 Docker 네트워크 별칭으로 자동 등록
- 기본 토폴로지(OpenBao/PostgreSQL/step-ca/HTTP-01 responder를 한 머신에 배치)에서는
  `bootroot init`이 step-ca/responder용 OpenBao Agent 설정을 생성하고,
  compose override로 전용 OpenBao Agent 컨테이너(`openbao-agent-stepca`,
  `openbao-agent-responder`)를 활성화

bootroot CLI가 자동으로 준비하는 항목:

- 서비스/시크릿 관련 설정 및 상태 파일(`state.json`, 서비스별 AppRole/secret 파일 등)
- `service add`/`init`/`rotate` 흐름에서 생성되는 로컬 구성 파일 갱신

운영자가 직접 설치/관리해야 하는 항목:

- `bootroot` CLI
- `bootroot-agent`
- `bootroot-remote`(추가 서비스가 step-ca 운영 머신이 아닌 다른 머신에서 동작할 때,
  해당 서비스 머신에서 실행하는 CLI)
- OpenBao Agent(추가 서비스용; step-ca/responder용은 `bootroot init`에서 자동 준비)

프로세스 상시 운영도 운영자 책임입니다.

- systemd 모드: `Restart=always` 또는 `on-failure` 설정
- 컨테이너 모드: 컨테이너 restart 정책 + Docker 데몬 부팅 자동 시작

추가 서비스가 step-ca 운영 머신이 아닌 다른 머신에서 동작하는 경우, 해당
서비스 머신에서 `bootroot-remote bootstrap`을 1회 실행해 초기 설정 번들을
반영한 뒤, secret_id 회전 이후에는 `bootroot-remote apply-secret-id`로
명시적 secret_id 전달을 수행합니다.

## 이름 해석(DNS/hosts) 운영 책임

핵심 원칙:

- HTTP-01 검증이 동작하려면 step-ca가 서비스 검증 FQDN을 responder IP로
  찾을 수 있어야 합니다. Docker Compose 환경에서는 `bootroot service add`가
  `bootroot-http01` 컨테이너에 별칭을 자동 등록합니다.
- step-ca/responder를 IP가 아닌 이름으로 접근하면, 관련 호스트들에서
  DNS/hosts 매핑을 일관되게 맞춰야 합니다.

상세 기준과 조건별 설명은 개요의 [/etc/hosts 매핑 설정](index.md#etchosts)을
참고하세요.

## bootroot infra up

Docker Compose로 OpenBao/PostgreSQL/step-ca/HTTP-01 리스폰더를 기동하고
상태를 점검합니다.
이 명령은 **step-ca가 실행되는 동일 머신에서** OpenBao/PostgreSQL/
HTTP-01 리스폰더가 함께 구동된다는 전제를 둡니다. 서로 다른 머신에
분산해 운영하려면 CLI 대신 수동으로 구성/기동해야 합니다.

### 입력

- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--services`: 기동 대상 서비스 목록 (기본값 `openbao,postgres,step-ca,bootroot-http01`)
- `--image-archive-dir`: 로컬 이미지 아카이브 디렉터리(선택)
- `--restart-policy`: 컨테이너 재시작 정책 (기본값 `always`)
- `--openbao-url`: OpenBao API URL (기본값 `http://localhost:8200`)
- `--openbao-unseal-from-file`: 파일에서 OpenBao 언실 키 읽기
  (dev/test 전용, 환경 변수: `OPENBAO_UNSEAL_FILE`)

### 출력

- 컨테이너 상태/헬스 요약
- 완료 메시지

`state.json`에 비루프백 OpenBao 바인딩 의도가 저장되어 있으면
(`infra install --openbao-bind`으로 설정), `infra up`은 TLS 사전 조건을
검증한 뒤 compose 오버라이드를 자동으로 적용하여 OpenBao가 저장된
주소에서 리슨하도록 합니다.

### 실패 조건

다음 조건이면 실패로 판정합니다.

- docker compose/pull 실패
- 컨테이너 미기동 또는 헬스 체크 실패
- 비루프백 OpenBao 바인딩 의도가 저장되어 있으나 TLS 인증서/키 또는
  `openbao.hcl` TLS 설정이 누락된 경우
- 비루프백 OpenBao 바인딩 의도가 저장되어 있으나 compose 오버라이드
  파일이 누락된 경우

### 예시

```bash
bootroot infra up
```

## bootroot infra install

제로 설정(zero-config) 최초 설치를 수행합니다. 임의의 PostgreSQL
비밀번호가 포함된 `.env`를 생성하고, `secrets/` 및 `certs/` 디렉터리를
만들고, Docker Compose 서비스를 기동합니다(로컬 이미지 빌드 포함).
새로 클론한 환경의 권장 진입점입니다. 이미 구성된 환경을 재시작하려면
`bootroot infra up`을 사용하세요.

### 입력

- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--services`: 기동 대상 서비스 목록 (기본값 `openbao,postgres,step-ca,bootroot-http01`)
- `--image-archive-dir`: 로컬 이미지 아카이브 디렉터리(선택)
- `--restart-policy`: 컨테이너 재시작 정책 (기본값 `always`)
- `--openbao-url`: OpenBao API URL (기본값 `http://localhost:8200`)
- `--openbao-bind <IP>:<port>`: 멀티호스트 배포를 위해
  OpenBao를 비루프백 주소에 바인딩합니다(선택).
  바인딩 의도를 state에 기록하고 compose 오버라이드
  파일을 생성합니다. 오버라이드는 `infra install` 중에는
  적용되지 **않으며**, TLS 검증 후 `bootroot init` 또는
  `infra up`에서 처음 적용됩니다.
  기본값은 `127.0.0.1:8200`입니다.
- `--openbao-tls-required`: `--openbao-bind`에
  비루프백 주소를 지정할 때 필요한 확인 플래그입니다.
  비루프백 포트가 게시되기 전에 TLS가 적용됨을
  확인합니다.
- `--openbao-bind-wildcard`: `--openbao-bind`에
  와일드카드 주소(`0.0.0.0` 또는 `[::]`)를 사용할 때
  필요한 확인 플래그입니다. 이 플래그 없이 와일드카드
  바인딩은 거부됩니다.
- `--openbao-advertise-addr <IP>:<port>`:
  `--openbao-bind`에 와일드카드 주소를 사용할 때
  필수입니다. 원격 부트스트랩 아티팩트가 OpenBao에
  도달하는 데 사용할 라우팅 가능한 주소를 지정합니다.
  특정 IP여야 하며 와일드카드나 루프백은 허용되지
  않습니다. 설치 시 `state.json`에 `openbao_advertise_addr`로
  저장됩니다. CN 측 `openbao_url`은 TLS 검증 후
  `bootroot init`이 바인드 주소 기반 HTTPS URL로 다시
  작성할 때까지 설치 시 루프백 URL로 유지됩니다.

### 출력

- 생성된 `.env` 파일(임의 PostgreSQL 자격증명 포함)
- 생성된 `secrets/` 및 `certs/` 디렉터리
- 컨테이너 상태/헬스 요약
- 완료 메시지
- `--openbao-bind` 사용 시:
  `secrets/openbao/docker-compose.openbao-exposed.yml`
  compose 오버라이드 파일 및 `state.json`에 바인딩 의도
  기록

### 실패 조건

다음 조건이면 실패로 판정합니다.

- docker compose build/pull 실패
- 컨테이너 미기동 또는 헬스 체크 실패
- `--openbao-bind` 형식이 잘못됨 (유효한 IP 주소의
  `<IP>:<port>` 형식이어야 함)
- 비루프백 주소의 `--openbao-bind` 사용 시
  `--openbao-tls-required` 누락
- `--openbao-bind-wildcard` 없이 와일드카드 주소(`0.0.0.0` 또는
  `[::]`)의 `--openbao-bind` 사용
- 와일드카드 주소의 `--openbao-bind` 사용 시
  `--openbao-advertise-addr` 누락

### 예시

```bash
bootroot infra install
```

특정 바인딩 주소를 사용한 멀티호스트 배포:

```bash
bootroot infra install --openbao-bind 192.168.1.10:8200 --openbao-tls-required
```

와일드카드 바인딩(명시적 확인 및 advertise 주소 필요):

```bash
bootroot infra install \
  --openbao-bind 0.0.0.0:8200 \
  --openbao-tls-required \
  --openbao-bind-wildcard \
  --openbao-advertise-addr 192.168.1.10:8200
```

## bootroot init

OpenBao 초기화/언실/정책/AppRole 구성, step-ca 초기화, 시크릿 등록을 수행합니다.

### 입력

입력 우선순위는 **CLI 옵션 > 환경 변수 > 프롬프트/기본값**입니다.

- `--openbao-url`: OpenBao API URL (기본값 `http://localhost:8200`)
- `--kv-mount`: OpenBao KV v2 마운트 경로 (기본값 `secret`)
- `--secrets-dir`: 시크릿 디렉터리 (기본값 `secrets`)
- `--compose-file`: infra 상태 점검용 compose 파일 (기본값 `docker-compose.yml`)
- `--enable <feature,...>`: 선택 기능 활성화(쉼표 구분).
  값: `auto-generate`, `show-secrets`, `db-provision`, `db-check`,
  `eab-auto`
- `--skip <phase,...>`: 선택 단계 건너뛰기(쉼표 구분).
  값: `responder-check`
- `--summary-json`: init 요약을 머신 파싱용 JSON 파일로 저장
  (민감 필드 포함 가능: 예 `root_token`)
- `--root-token`: OpenBao root token (환경 변수: `OPENBAO_ROOT_TOKEN`).
  기본 실행에서는 필수입니다. preview 모드(`--print-only`/`--dry-run`)에서는
  선택이며, trust 프리뷰를 보려면 지정해야 합니다.
  현재 실행에서 OpenBao를 신규 초기화하는 경우에는 별도 수동 입력 없이
  생성된 토큰을 내부 흐름에서 사용합니다. 반대로 이미 초기화된 OpenBao에
  대해 재실행할 때는 `--root-token`/환경 변수/프롬프트로 토큰을 제공해야
  합니다. `bootroot`는 root token 영구 저장소를 별도로 관리하지 않습니다.
- `--unseal-key`: OpenBao unseal key (반복 가능, 환경 변수: `OPENBAO_UNSEAL_KEYS`)
  같은 옵션을 여러 번 전달할 수 있습니다
  (예: `--unseal-key k1 --unseal-key k2 --unseal-key k3`).
  환경 변수는 쉼표 구분 목록으로 전달합니다
  (예: `OPENBAO_UNSEAL_KEYS="k1,k2,k3"`).
- `--openbao-unseal-from-file`: 파일에서 OpenBao 언실 키 읽기
  (dev/test 전용, 환경 변수: `OPENBAO_UNSEAL_FILE`)
- `--stepca-password`: step-ca 키 암호 값 (저장 위치: `secrets/password.txt`,
  환경 변수: `STEPCA_PASSWORD`)
- `--db-dsn`: step-ca용 PostgreSQL DSN
- `--db-admin-dsn`: PostgreSQL 관리자 DSN (환경 변수: `BOOTROOT_DB_ADMIN_DSN`)
- `--db-user`: step-ca용 PostgreSQL 계정 (환경 변수: `BOOTROOT_DB_USER`)
- `--db-password`: step-ca용 PostgreSQL 비밀번호 (환경 변수: `BOOTROOT_DB_PASSWORD`)
- `--db-name`: step-ca용 PostgreSQL DB 이름 (환경 변수: `BOOTROOT_DB_NAME`)
- `--db-timeout-secs`: DB 연결 타임아웃(초, 기본값 `2`)
- `--http-hmac`: HTTP-01 responder HMAC (환경 변수: `HTTP01_HMAC`)
- `--responder-url`: HTTP-01 responder 관리자 URL (선택, 환경 변수: `HTTP01_RESPONDER_URL`)
- `--responder-timeout-secs`: responder 요청 타임아웃(초, 기본값 `5`)
- `--stepca-url`: step-ca URL (기본값 `https://localhost:9000`)
- `--stepca-provisioner`: step-ca ACME provisioner 이름 (기본값 `acme`)
- `--secret-id-ttl`: 초기화 중 생성되는 AppRole 역할의 역할 수준
  `secret_id` TTL (기본값 `24h`). 계획된 회전 주기의 최소 2배 이상으로
  설정하여 누락된 실행이 자격증명을 만료시키지 않도록 하세요. `24h`는
  보안 보수적 기본값이며, 운영 여유가 노출 최소화보다 중요할 때 `48h`
  이상을 사용하세요. `48h` 초과 시 경고를 출력하고, `168h` 초과 시
  거부합니다. 회전 주기 안내가 항상 stderr에 출력됩니다.
  서비스별 오버라이드는 이후
  `bootroot service add --secret-id-ttl` 또는
  `bootroot service update --secret-id-ttl`로 설정할 수 있습니다.
  [운영 > SecretID TTL과 회전 주기](operations.md#secretid-ttl)를
  참고하세요.
- `--eab-kid`, `--eab-hmac`: 수동 EAB 입력
  (환경 변수: `EAB_KID`, `EAB_HMAC`)

DB DSN host 처리 규칙:

- `localhost`, `127.0.0.1`, `::1` 입력은 init 시 내부적으로
  `postgres`로 정규화됩니다.
- `db.internal` 같은 원격 호스트는 step-ca 컨테이너 런타임에서 접근할 수
  없어 init이 실패합니다.

### 대화형 동작

- 누락된 필수 입력을 프롬프트로 받습니다.
- 입력값은 빈 값 여부, 허용된 enum 값인지, 경로/상위 디렉터리가
  유효한지 확인합니다.
- `password.txt`, `ca.json`, `state.json` 덮어쓰기 전 확인합니다.
- 실행 전 계획 요약, 실행 후 최종 요약을 출력합니다.

### 출력

- OpenBao 초기화/언실 결과, AppRole 생성 결과 요약
- `password.txt`, `secrets/config/ca.json` 갱신 결과
- step-ca 초기화 여부, responder 체크 결과
- DB 연결 점검 결과(옵션 사용 시)
- DB host 해석 결과(`from -> to`)
- EAB 등록 여부
- step-ca/responder용 OpenBao Agent compose override 자동 적용
- 다음 단계 안내
- `--summary-json` 지정 시 자동화용 init 요약 JSON 파일 생성

### step-ca/responder용 OpenBao Agent 초기 인증 준비

현재 기본 토폴로지에서는 step-ca가 설치된 머신에서 OpenBao, step-ca,
responder가 함께 동작하며 로컬 `secrets` 디렉터리를 공유합니다.

이 기본 토폴로지에서는 `bootroot init`이 step-ca/responder용 OpenBao Agent의
초기 인증 준비를 자동으로 처리합니다. 핵심 작업은 다음과 같습니다.

- `bootroot-stepca`, `bootroot-responder`는 OpenBao AppRole 이름이며,
  `role_id`는 각 AppRole에 대해 OpenBao가 부여하는 별도 식별자
- 각 AppRole에 대해 OpenBao가 `role_id`/`secret_id`를 발급
- 발급된 `role_id`/`secret_id`를 OpenBao Agent가 읽을 파일로 저장
- OpenBao Agent 설정(`agent.hcl`)의 `role_id_file_path`/
  `secret_id_file_path`에 해당 파일 경로를 반영
- 기본 `docker-compose.yml` 위에 추가 설정 파일을 compose override로
  덮어 적용해 step-ca/responder용 OpenBao Agent 서비스/설정을 활성화하고
  에이전트 시작

이 구조는 step-ca/responder 프로세스가 OpenBao Agent를 직접 실행하는 방식이
아니라, 전용 OpenBao Agent 인스턴스를 별도로 구동하는 방식이며, 기본 compose
토폴로지에서는 이 전용 인스턴스를 별도 컨테이너
(`openbao-agent-stepca`, `openbao-agent-responder`)로 실행합니다. 즉,
step-ca/responder와 같은 compose 스택에서 옆에 붙어 동작하는 사이드카
성격의 전용 에이전트 컨테이너입니다.

생성되는 인증 파일 경로(`role_id`/`secret_id`):

- step-ca:
  `secrets/openbao/stepca/role_id`,
  `secrets/openbao/stepca/secret_id`
- responder:
  `secrets/openbao/responder/role_id`,
  `secrets/openbao/responder/secret_id`

보안 전제:

- 시크릿 디렉터리 권한: `0700`
- 시크릿 파일(`role_id`/`secret_id` 및 렌더 결과) 권한: `0600`
- step-ca가 설치된 머신 기준 로컬 신뢰 경계 전제

OpenBao와 step-ca/responder가 서로 다른 머신에 배치되면, 이 섹션에서 전제한
로컬 `secrets` 디렉터리 공유(파일 기반 시크릿 전달) 모델이 성립하지 않습니다.
이 경우 AppRole 자격증명 전달과 에이전트 기동을 위한 별도 원격 초기 인증 준비
절차가 필요하며, 해당 토폴로지는 `bootroot` CLI 자동화 범위에 포함되지
않습니다.

### 실패 조건

다음 조건이면 실패로 판정합니다.

- infra 컨테이너가 비정상인 경우
- OpenBao 초기화/언실/인증 실패
- responder 체크 실패(옵션 사용 시)
- step-ca 초기화 실패

### 예시

```bash
bootroot init --enable auto-generate,eab-auto --responder-url http://localhost:8080
```

## bootroot status

infra 상태(컨테이너 포함)와 OpenBao KV/AppRole 상태를 점검합니다.

### 입력

- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--openbao-url`: OpenBao URL (기본값 `http://localhost:8200`)
- `--kv-mount`: OpenBao KV v2 마운트 경로 (기본값 `secret`)
- `--root-token`: KV/AppRole 체크용 토큰
  (선택, 환경 변수: `OPENBAO_ROOT_TOKEN`)
  토큰을 주지 않으면 infra/컨테이너 상태 중심으로 점검하고, KV/AppRole
  상세 체크는 제한됩니다.

### 출력

- 컨테이너 상태 요약
- OpenBao/ KV 상태 요약

### 실패 조건

다음 조건이면 실패로 판정합니다.

- 컨테이너 미기동/비정상
- OpenBao 응답 불가

### 예시

```bash
bootroot status
```

## bootroot service add

새로운 서비스(daemon/docker)이 step-ca에서 인증서를 발급받을 수 있도록
온보딩 정보를 등록하고 OpenBao AppRole을 생성합니다. 이 명령을 실행하면
**`bootroot` CLI**가 아래 순서로 온보딩 자동화를 수행합니다.

### 1) 기본 자동 반영

- 서비스 메타데이터를 `state.json`에 등록
- 서비스 전용 OpenBao 정책/AppRole 생성, `role_id`/`secret_id` 발급
- `secrets/services/<service>/role_id`, `secret_id` 파일 생성
- 결과 요약과 운영자용 스니펫 출력

### 2) 전달 모드(`--delivery-mode`)별 자동 반영

#### 2-1) `local-file`

- 사용 시점: 서비스가 OpenBao/PostgreSQL/step-ca/HTTP-01 responder가 설치된
  동일 머신에 추가될 때
- 자동 반영: `agent.toml`의 관리 대상 프로필 블록 갱신(없으면 추가),
  `--domain`에서 가져온 최상위 `domain`, OpenBao에 저장된 리스폰더 HMAC에서
  가져온 `[acme].http_responder_hmac`, OpenBao Agent 템플릿/설정/토큰 파일
  로컬 생성, `bootroot-http01` 컨테이너에 HTTP-01 DNS 별칭 자동 등록

#### 2-2) `remote-bootstrap`

- 사용 시점: 서비스가 OpenBao/PostgreSQL/step-ca/HTTP-01 responder가 설치된
  머신이 아닌 다른 머신에 추가될 때
- 자동 반영: 원격 반영용 OpenBao KV 번들
  (`secret_id`/`eab`/`responder_hmac`/`trust`) 기록, 원격 bootstrap
  아티팩트 생성
- 동작 의미: step-ca가 동작하는 머신의 `bootroot`가 기록한 설정/시크릿 묶음을
  원격 서비스 머신의 `bootroot-remote`가 pull해서 반영
- 아티팩트 의미: 원격 동기화 시작에 필요한 초기 입력/실행 정보를 담은 산출물

### 3) 명령 범위와 운영자 작업

- 이 명령은 새 서비스의 **인증서 발급/갱신 경로를 준비**하는 필수 단계입니다.
- `bootroot service add` 자체가 인증서를 발급하지는 않습니다.

운영자가 직접 해야 할 작업:

- 서비스 머신에서 OpenBao Agent/bootroot-agent를 실제로 기동/상시 운영
- `local-file`인 경우 `bootroot service add`가 같은 호스트에 trust 파일을
  미리 준비하므로, 첫 managed `bootroot-agent` 실행부터 검증 모드로 시작 가능
- `remote-bootstrap`인 경우 생성된 `원격 실행 명령 템플릿`을 수정한 뒤
  `bootroot-agent`를 시작하기 전에 서비스 머신에서
  `bootroot-remote bootstrap`을 1회 실행하고, secret_id 회전 이후
  `bootroot-remote apply-secret-id` 실행
- `bootroot verify` 또는 실제 서비스 실행으로 발급 경로 검증

### 4) trust 자동 처리와 preview

기본 흐름에서 `bootroot init`를 정상 완료하면 OpenBao의
`secret/bootroot/ca`가 자동으로 준비되며, 기본 실행
(`--print-only`/`--dry-run` 없이 실행)의 `bootroot service add`가 trust
관련 값도 자동으로 처리합니다.

#### 4-1) 전달 모드별 trust 자동 처리

- `remote-bootstrap` 방식: 서비스 trust 상태를 서비스별 원격 bootstrap
  번들(`secret/.../services/<service>/trust`)에 자동 기록하고, 원격 서비스
  머신의 `bootroot-remote bootstrap`이 첫 `bootroot-agent` 실행 전에
  trust 설정과 CA 번들을 반영합니다.
- `local-file` 방식: trust 설정(`trusted_ca_sha256`, `ca_bundle_path`)이
  `agent.toml`에 자동 병합되고, CA 번들 PEM이 로컬
  `ca_bundle_path`에 기록되며, 서비스별 OpenBao Agent가 이를 계속
  동기화합니다.

#### 4-2) managed trust bootstrap(요약)

- 일반적인 managed onboarding 흐름에서는 두 delivery mode 모두 첫
  `bootroot-agent` 실행 전에 trust를 준비합니다.
- `local-file`: `bootroot service add`가 trust 설정과 `ca-bundle.pem`을
  로컬에 기록합니다.
- `remote-bootstrap`: `bootroot service add`가 OpenBao에 서비스 trust
  payload를 준비하고, `bootroot-remote bootstrap`이 원격 호스트에
  반영합니다.
- `--insecure`는 실행 단위 break-glass 오버라이드입니다. 자세한
  규칙/운영 흐름은 [설정 > 신뢰](configuration.md#_4) 섹션을
  참고하세요.

#### 4-3) preview 모드(`--print-only`/`--dry-run`)

- 런타임 인증(root token 또는 AppRole)을 주면 preview에서도 OpenBao trust
  데이터를 조회해 trust 스니펫을 출력합니다.
- 런타임 인증이 없으면 trust 스니펫을 출력하지 못하는 이유를 함께 출력합니다.
- `--print-only`/`--dry-run`은 파일/상태를 쓰지 않는 미리보기 모드입니다.

#### 4-4) 수동 설정이 필요한 대표 상황

- `local-file` 방식에서 `agent.toml`에 trust 항목을 직접 고정해 관리하려는 경우
- preview 출력만 보고 설정을 적용하는 경우

### 런타임 배포 정책

#### OpenBao Agent

- Docker 서비스: 서비스별 사이드카(**필수**)
- daemon 서비스: 서비스별 daemon(**필수**)

#### bootroot-agent

- Docker 서비스: 서비스별 사이드카(권장)
- daemon 서비스: 호스트당 통합 daemon 1개(권장)

참고: Docker 서비스도 통합 daemon 사용은 가능하지만 비권장입니다
(격리/라이프사이클 정합성 측면).

### 입력

입력 우선순위는 **CLI 옵션 > 환경 변수 > 프롬프트/기본값**입니다.

- `--service-name`: 서비스 이름 식별자
  - 단일 DNS label이어야 합니다. 영문자/숫자/하이픈만 허용하며, 최대 63자,
    점(`.`)과 밑줄(`_`)은 허용되지 않습니다.
- `--deploy-type`: 배포 타입 (`daemon` 또는 `docker`)
- `--delivery-mode`: 전달 모드 (`local-file` 또는 `remote-bootstrap`).
  참고: `remote-bootstrap`은 실행 파일이 아니라 모드 값이며, 이 모드에서
  사용하는 실행 파일은 `bootroot-remote`입니다.
- `--hostname`: DNS SAN에 사용할 호스트명
  - `--service-name`과 같은 단일 DNS label 규칙을 따릅니다.
- `--domain`: DNS SAN 루트 도메인
  - 점으로 구분된 DNS label들의 DNS 이름이어야 하며, 각 label은
    영문자/숫자/하이픈만 사용할 수 있습니다.
- `--agent-config`: bootroot-agent 설정 파일 경로
- `--cert-path`: 인증서 출력 경로
- `--key-path`: 개인키 출력 경로
- `--instance-id`: 서비스 instance_id
  - 숫자만 허용됩니다 (`001`, `42` 등)
- `--container-name`: 도커 서비스 컨테이너 이름 (docker 필수)
- `--auth-mode`: 런타임 인증 모드 (`auto`, `root`, `approle`, 기본값 `auto`)
- `--root-token`: OpenBao root token (환경 변수: `OPENBAO_ROOT_TOKEN`,
  전환/비상 경로)
- `--approle-role-id`: OpenBao AppRole role_id
  (환경 변수: `OPENBAO_APPROLE_ROLE_ID`)
- `--approle-secret-id`: OpenBao AppRole secret_id
  (환경 변수: `OPENBAO_APPROLE_SECRET_ID`)
- `--approle-role-id-file`: AppRole role_id 파일 경로
  (환경 변수: `OPENBAO_APPROLE_ROLE_ID_FILE`)
- `--approle-secret-id-file`: AppRole secret_id 파일 경로
  (환경 변수: `OPENBAO_APPROLE_SECRET_ID_FILE`)
- `--notes`: 메모(선택)
- `--print-only`: 파일/state 변경 없이 안내/스니펫만 출력
- `--dry-run`: preview 모드 별칭(`--print-only`와 동일)

갱신 후 훅 플래그(프리셋):

- `--reload-style`: 리로드 스타일 프리셋 (`sighup`, `systemd`, `docker-restart`, `none`)
- `--reload-target`: 프리셋 대상 (프로세스 이름, systemd 유닛, 컨테이너 이름)

프리셋은 생성된 `agent.toml` 프로필에 다음과 같은 `post_renew` 훅 항목으로 확장됩니다:

- `systemd` + 대상 `nginx` — `systemctl reload nginx`
- `sighup` + 대상 `nginx` — `pkill -HUP nginx`
- `docker-restart` + 대상 `my-container` — `docker restart my-container`
- `none` — 훅 없음

갱신 후 훅 플래그(저수준):

- `--post-renew-command`: 갱신 성공 후 실행할 훅 명령
- `--post-renew-arg`: 훅 인자 (반복 가능)
- `--post-renew-timeout-secs`: 훅 타임아웃(초, 기본값 `30`)
- `--post-renew-on-failure`: 실패 정책 (`continue` 또는 `stop`, 기본값 `continue`)

프리셋 플래그(`--reload-style`/`--reload-target`)와
저수준 플래그(`--post-renew-*`)는 상호
배타적입니다. 프리셋 플래그를 사용하면 동등한
저수준 훅 설정으로 확장됩니다.
`remote-bootstrap` 전달 모드에서는 이 플래그가
`bootroot-remote bootstrap`으로 전달됩니다.

발급 시점 `secret_id` 정책 플래그:

- `--secret-id-ttl`: 생성되는 `secret_id`의 TTL (생략 시 역할 수준 기본값
  상속). 회전 주기의 최소 2배 이상이어야 합니다
- `--secret-id-wrap-ttl`: `secret_id`에 대한 응답 래핑 TTL (기본값 `30m`)
- `--no-wrap`: `secret_id` 응답 래핑 비활성화
- `--rn-cidrs`: `secret_id` 토큰에 바인딩할 CIDR 범위 (반복 가능,
  예: `--rn-cidrs 10.0.0.0/24 --rn-cidrs 192.168.1.0/24`).
  설정 시 OpenBao는 지정된 범위 밖의 소스 IP에서의 인증을 거부합니다.
  생략 시 기본 동작(CIDR 바인딩 없음)을 유지합니다

이 값들은 `state.json`에 저장되며 `rotate approle-secret-id` 시 적용됩니다.
`--no-wrap`과 `--secret-id-wrap-ttl`은 동일 필드를 제어합니다.
`--no-wrap`은 저장되는 래핑 TTL을 `0`으로 설정하여 래핑을 완전히 비활성화합니다.

### 대화형 동작

- 누락된 필수 입력을 프롬프트로 받습니다(배포 타입 기본값: `daemon`).
- 식별자 값이 비어 있지 않은지와 DNS/숫자 규칙을 만족하는지, 허용된 enum
  값인지, 경로/상위 디렉터리가 유효한지 확인합니다.
- 실행 전 계획 요약, 실행 후 최종 요약을 출력합니다.

### 출력

- 서비스 메타데이터 요약
- AppRole/정책/secret_id 경로 요약
- 전달 모드 요약(`local-file`은
  `agent.toml`/OpenBao Agent 설정/템플릿 자동 반영 경로, `remote-bootstrap`은
  부트스트랩 아티팩트 + 순서형 원격 handoff 명령 템플릿 출력)
- 출력에 소유/책임 범위를 명시하는 라벨을 함께 표시:
  `Bootroot 자동 반영 항목`, `운영자 실행 항목 (필수)`,
  `운영자 실행 항목 (권장)`, `운영자 실행 항목 (선택)`
- 서비스별 OpenBao Agent 안내(daemon/docker 분리)
- 타입별 온보딩 안내 (daemon 프로필 / docker sidecar)
- daemon/docker 스니펫(복붙용) 출력(기본 모드 + preview 모드)

### 실패 조건

다음 조건이면 실패로 판정합니다.

- `state.json` 누락
- 중복된 `service-name`
- `instance-id` 누락
- docker에 `container-name` 누락
- OpenBao AppRole 생성 실패

## bootroot service update

`service add`를 다시 실행하지 않고 서비스별 `secret_id` 정책 필드를
변경합니다. 정책 플래그 중 하나 이상이 필요합니다.

### 입력

- `--service-name`: 서비스 이름 식별자
- `--secret-id-ttl`: 생성되는 `secret_id`의 TTL (서비스별 오버라이드를
  지우고 역할 수준 기본값으로 되돌리려면 `"inherit"` 사용). 회전 주기의
  최소 2배 이상이어야 합니다
- `--secret-id-wrap-ttl`: `secret_id`의 응답 래핑 TTL (기본 래핑 동작을
  복원하려면 `"inherit"` 사용)
- `--no-wrap`: `secret_id`의 응답 래핑 비활성화
  (`--secret-id-wrap-ttl`과 상호 배타)
- `--rn-cidrs`: `secret_id` 토큰에 바인딩할 CIDR 범위 (반복 가능).
  기존 바인딩을 제거하려면 `--rn-cidrs clear` 사용

### 동작

- `state.json`에서 서비스 항목을 읽고 지정된 정책 필드만 갱신합니다.
- 변경사항이 없으면 기록하지 않고 종료합니다.
- 변경 전/후 값의 요약을 출력합니다.
- 다음 발급에 갱신된 정책을 적용하려면 `rotate approle-secret-id`를
  실행하라는 안내를 출력합니다.

### 출력

- 정책 변경 요약 (변경 전 → 변경 후)
- 다음 단계 안내

### 실패 조건

다음 조건이면 실패로 판정합니다.

- `state.json` 누락
- 서비스 미등록
- 정책 플래그 미지정

### 예시

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl 12h
bootroot service update --service-name edge-proxy --no-wrap
bootroot service update --service-name edge-proxy --secret-id-wrap-ttl inherit
```

## bootroot service info

등록된 서비스 정보를 조회합니다.

### 입력

- `--service-name`: 서비스 이름 식별자

### 출력

- 서비스 타입/경로/AppRole/시크릿 경로 요약
- 서비스별 OpenBao Agent 안내(daemon/docker 분리)

### 실패 조건

다음 조건이면 실패로 판정합니다.

- `state.json` 누락
- 등록되지 않은 서비스

## bootroot verify

bootroot-agent를 one-shot으로 실행해 발급을 검증합니다. 서비스 온보딩 직후
또는 설정 변경 후에 실제 발급이 가능한지 확인할 때 사용합니다.
검증 이후에도 **주기적 갱신을 원하면 bootroot-agent를 상시 모드로
실행**해야 합니다(oneshot 없이 실행). CLI로 전달한 오버라이드
(예: `--http-responder-hmac`, `--ca-url`)는 데몬 재시도 시에도
유지되므로, 해당 플래그는 `--oneshot`과 동일하게 동작합니다.

### 입력

- `--service-name`: 서비스 이름 식별자
- `--agent-config`: bootroot-agent 설정 경로 (선택, 기본은 등록된 값)
- `--db-check`: ca.json DSN으로 DB 연결/인증 점검
- `--db-timeout-secs`: DB 연결 타임아웃(초, 기본값 `2`)

### 대화형 동작

- 누락된 필수 입력을 프롬프트로 받습니다.
- 입력값은 비어 있지 않은지 확인합니다.
- 실행 전 계획 요약, 실행 후 최종 요약을 출력합니다.

### 출력

- cert/key 존재 여부
- 검증 결과 요약
- DB 연결 점검 결과(옵션 사용 시)

### 실패 조건

다음 조건이면 실패로 판정합니다.

- bootroot-agent 실행 실패
- cert/key 파일 누락

## bootroot rotate

시크릿 회전을 수행합니다. `state.json`을 기준으로 경로를 찾고,
OpenBao와 통신해 값을 갱신합니다.

지원 서브커맨드:

- `rotate stepca-password`
- `rotate eab`
- `rotate db`
- `rotate responder-hmac`
- `rotate approle-secret-id`
- `rotate trust-sync`
- `rotate force-reissue`
- `rotate ca-key`
- `rotate openbao-recovery`

### 입력

공통:

- `--state-file`: `state.json` 경로 (선택)
- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--openbao-url`: OpenBao API URL (선택)
- `--kv-mount`: OpenBao KV 마운트 경로 (선택)
- `--secrets-dir`: 시크릿 디렉터리 (선택)
- `--auth-mode`: 런타임 인증 모드 (`auto`, `root`, `approle`, 기본값 `auto`)
- `--root-token`: OpenBao root token (환경 변수 `OPENBAO_ROOT_TOKEN`,
  전환/비상 경로)
- `--approle-role-id`: OpenBao AppRole role_id
  (환경 변수: `OPENBAO_APPROLE_ROLE_ID`)
- `--approle-secret-id`: OpenBao AppRole secret_id
  (환경 변수: `OPENBAO_APPROLE_SECRET_ID`)
- `--approle-role-id-file`: AppRole role_id 파일 경로
  (환경 변수: `OPENBAO_APPROLE_ROLE_ID_FILE`)
- `--approle-secret-id-file`: AppRole secret_id 파일 경로
  (환경 변수: `OPENBAO_APPROLE_SECRET_ID_FILE`)
- `--show-secrets`: stdout의 민감 필드를 마스킹하지 않고 평문으로 표시
- `--yes`: 확인 프롬프트 생략

출력 동작:

- 기본값으로 rotate 서브커맨드의 민감한 stdout 필드는 마스킹됩니다.
- 평문 stdout이 정말 필요한 경우에만 `--show-secrets`를 사용하세요.
- 이 동작은 EAB 자격증명, root token, unseal keys 같은 요약 출력에 적용됩니다.
- `rotate openbao-recovery`의 `--output`은 stdout 마스킹과 별개입니다.
  자격증명 평문은 지정한 파일에 기록하고, stdout에는 요약과 출력 경로만
  표시합니다.

서브커맨드별:

#### `rotate stepca-password`

- `--new-password`: 새 step-ca 키 비밀번호(선택, 미지정 시 자동 생성)
- 구현 참고: bootroot는 비대화형 Docker 환경에서 overwrite 확인 프롬프트로
  인한 실패를 막기 위해 `step crypto change-pass`를 `-f`(`--force`)와 함께
  실행합니다.

#### `rotate eab`

- `--stepca-url`: step-ca URL (기본값 `https://localhost:9000`)
- `--stepca-provisioner`: ACME 프로비저너 이름 (기본값 `acme`)
- stdout 요약의 EAB `kid` / `hmac`는 `--show-secrets`를 주지 않으면
  마스킹됩니다

#### `rotate db`

- `--db-admin-dsn`: DB 관리자 DSN (환경 변수 `BOOTROOT_DB_ADMIN_DSN`).
  `ca.json`이 있으면(즉, `bootroot init --enable db-provision`으로 생성된
  경우) 선택 사항입니다. bootroot가 `ca.json`의 `db.dataSource` 필드에서
  현재 관리자 DSN을 자동으로 읽어옵니다. 값을 재정의하려면 플래그를 명시적
  으로 지정하고, `ca.json`이 없고 대화형 프롬프트를 피하고 싶을 때도 직접
  지정하세요.
- `--db-password`: 새 DB 비밀번호
  (선택, 미지정 시 자동 생성, 환경 변수: `BOOTROOT_DB_PASSWORD`)
- `--db-timeout-secs`: DB 점검 타임아웃(초, 기본값 `2`)

#### `rotate responder-hmac`

- `--hmac`: 새 responder HMAC(선택, 미지정 시 자동 생성)

#### `rotate approle-secret-id`

- `--service-name`: 대상 서비스 이름

#### `rotate trust-sync`

CA 인증서 지문과 번들 PEM을 OpenBao에 동기화하고 각 서비스의 trust
데이터를 갱신합니다. 원격 서비스의 경우 서비스별 KV 경로에 trust 페이로드를
기록합니다. 로컬 서비스의 경우 에이전트 설정의 `[trust]` 섹션을 갱신하고
CA 번들 PEM을 디스크에 기록합니다.

추가 인수 없음.

#### `rotate force-reissue`

서비스의 cert/key 파일을 삭제해 bootroot-agent가 인증서를 재발급하도록
합니다. 로컬(daemon) 서비스의 경우 bootroot-agent 프로세스에 SIGHUP을
보냅니다. Docker 서비스의 경우 컨테이너를 재시작합니다. 원격 서비스의 경우
`bootroot-remote bootstrap` 실행을 안내합니다.

- `--service-name`: 대상 서비스 이름

#### `rotate ca-key`

step-ca가 사용하는 CA 키 쌍을 회전합니다. 기본 동작은 중간 CA 키 쌍만
교체하며, `--full` 옵션을 주면 루트 CA와 중간 CA 키 쌍을 모두 교체합니다.

두 모드 모두 8단계 멱등(idempotent) 워크플로를 사용합니다.
`rotation-state.json` 파일이 진행 상태를 추적하므로, 실패 후 재실행하면
마지막으로 완료된 단계부터 자동으로 이어서 진행합니다. 이 파일은 동시
수정도 방지합니다.

단계:

- Phase 0 — 사전 점검: 필수 파일 존재 확인, 현재 fingerprint 조회
- Phase 1 — 백업: 현재 cert/key 파일 백업
- Phase 2 — 생성: 새 CA 키 쌍 및 인증서 생성
- Phase 3 — 가산적 trust: 전이 trust(기존 + 신규 fingerprint)를 OpenBao에
  기록해 서비스가 기존/신규 인증서를 모두 수락하도록 함
- Phase 4 — step-ca 재시작: step-ca 컨테이너를 재시작해 새 키 쌍 적용
- Phase 5 — 재발급: 서비스 cert/key 삭제 후 bootroot-agent에 시그널
  (daemon은 SIGHUP, Docker는 컨테이너 재시작)을 보내 새 CA로 재발급 유도.
  원격 서비스는 안내 메시지 출력
- Phase 6 — trust 확정: 최종 trust(신규 fingerprint만)를 OpenBao에 기록해
  기존 fingerprint 제거
- Phase 7 — 정리: `rotation-state.json` 삭제, 선택적으로 백업 파일 제거

중간 CA만 교체하는 모드는 3-fingerprint 전이 trust(기존 루트, 기존 중간,
신규 중간)를 사용합니다. 전체 모드는 4-fingerprint 전이 trust(기존 루트,
기존 중간, 신규 루트, 신규 중간)를 사용합니다.

입력:

- `--full`: 루트 + 중간 CA 키 모두 교체(기본: 중간 CA만)
- `--skip <phase,...>`: 선택 단계 건너뛰기(쉼표 구분).
  값: `reissue`(Phase 5 — 서비스 인증서 재발급),
  `finalize`(Phase 6 — trust 확정)
- `--force`: 미이전 서비스가 있어도 Phase 6 강제 실행
- `--cleanup`: 완료 시 백업 파일 삭제(Phase 7)

#### `rotate openbao-recovery`

OpenBao 복구 자격증명을 수동으로 회전합니다. 이 작업은 자동 실행되지
않으며 운영자가 명시적으로 실행해야 합니다.

- `--rotate-unseal-keys`: rekey를 통해 언실 키 회전
- `--rotate-root-token`: 새 루트 토큰 생성
- `--unseal-key`: 기존 언실 키(반복 지정 가능)
- `--unseal-key-file`: 기존 언실 키 파일(줄바꿈 구분)
- `--output`: 새 자격증명을 파일로 저장(`0600`)
- stdout 요약의 새 root token / unseal keys는 `--show-secrets`를 주지 않으면
  마스킹됩니다

최소 하나의 대상 플래그(`--rotate-unseal-keys` / `--rotate-root-token`)를
반드시 지정해야 합니다. `rotate openbao-recovery`는 AppRole role/role_id/
secret_id를 변경하지 않습니다.

중요 동작:

- `--rotate-unseal-keys`는 기존 언실 키가 필요합니다.
  OpenBao에 설정된 언실 해제 최소 필요 개수만큼 키 조각을
  `--unseal-key`, `--unseal-key-file`, 또는 대화형 입력으로 제공해야 합니다.
- 기존 언실 키를 분실하면 언실 키 회전은 수행할 수 없습니다.
  이 경우 현실적인 복구 경로는 OpenBao 재초기화이며, 결과적으로
  `bootroot init` 재실행과 서비스 재bootstrap이 필요합니다.
- `--rotate-root-token`은 언실 키 입력 없이 실행할 수 있습니다.

### 회전 시크릿 쓰기 대상

아래 3개 서브커맨드는 OpenBao만 갱신하지 않고, 로컬 런타임 파일도 함께
갱신합니다.

#### `rotate stepca-password`

OpenBao KV: `bootroot/stepca/password`  
로컬 파일: `secrets/password.txt`

#### `rotate db`

OpenBao KV: `bootroot/stepca/db`  
로컬 파일: `secrets/config/ca.json` (`db.dataSource`)

#### `rotate responder-hmac`

OpenBao KV: `bootroot/responder/hmac`  
로컬 파일: `secrets/responder/responder.toml` (`hmac_secret`)

값을 명시하지 않으면(`--new-password`, `--db-password`, `--hmac`) bootroot가
새 랜덤 값을 생성합니다.

### 로컬 파일 갱신이 필요한 이유

- `step-ca` 키 암호는 비대화형 운영에서 `--password-file`로 소비되므로
  `password.txt` 갱신이 필요합니다.
- `step crypto change-pass`는 기본 동작에서 `/dev/tty`를 통해 overwrite 확인을
  받으려 하므로, 컨테이너 기반 비대화형 실행에서는 bootroot가 `-f`를 사용해
  TTY 할당 오류를 방지합니다.
- `step-ca` DB 연결 정보는 `ca.json`의 `db.dataSource`를 읽으므로, DSN 변경을
  해당 파일에 반영해야 런타임에 적용됩니다.
- responder는 설정 파일의 `hmac_secret` 값을 읽습니다.

즉 회전 값의 소스 오브 트루스는 OpenBao로 유지하되, 현재 런타임 소비 모델상
로컬 파일 반영이 필요합니다.

### 로컬 시크릿 파일 보안 요건

이 모델에서 파일 기반 시크릿 저장은 아래 최소 요건을 만족할 때 허용됩니다.

- 시크릿 파일 권한: `0600`
- 시크릿 디렉터리 권한: `0700`
- 최소 권한 계정 소유권 유지
- 로그/출력/백업으로 시크릿 유출 방지

리스크가 0은 아닙니다. 호스트 침해 시 로컬 시크릿 파일이 노출될 수 있습니다.

### 출력

- 회전 요약(수정된 파일 경로/설정 목록)
- 필요한 재시작/리로드 안내(step-ca 재시작, responder 리로드 등)
- AppRole secret_id 회전 시 OpenBao Agent 리로드 및 로그인 점검 결과

### 실패 조건

다음 조건이면 실패로 판정합니다.

- `state.json` 누락 또는 파싱 실패
- OpenBao 연결/헬스 체크 실패
- 런타임 인증 누락 또는 인증 실패(root token 또는 AppRole)
- step-ca 비밀번호 회전 시 키/비밀번호 파일 누락
- DB 회전 시 관리자 DSN 누락 또는 DB 프로비저닝 실패
- EAB 발급 요청 실패
- responder 설정 파일 쓰기 실패 또는 리로드 실패
- OpenBao 복구 자격증명(rekey/루트 토큰) 회전 실패
- AppRole 대상 서비스 미등록 또는 secret_id 갱신 실패

## bootroot monitoring

로컬 모니터링 스택(Prometheus + Grafana)을 관리합니다.
`docker-compose.yml`의 프로필을 사용해 LAN/공개 모드를 분리합니다.

지원 서브커맨드:

- `monitoring up`
- `monitoring status`
- `monitoring down`

### 프로필

- `lan`: Grafana 바인딩 주소는 `GRAFANA_LAN_BIND_ADDR`(기본 `127.0.0.1`)  
  기본값은 **로컬호스트 전용**이라 같은 머신에서만 접속 가능합니다.  
  여기서 LAN IP는 **같은 머신이 가진 IP 중 사설망 인터페이스의 주소**를 뜻합니다  
  (예: `192.168.x.x`, `10.x.x.x`).  
  `GRAFANA_LAN_BIND_ADDR`를 LAN IP로 지정하면 **해당 사설망 대역에서만 접속**되며  
  외부 인터넷에서는 접근할 수 없습니다(별도 라우팅/포트포워딩이 없는 전제).
- `public`: Grafana 바인딩 주소는 `0.0.0.0`  
  **모든 인터페이스에서 접속 가능**하며, 동일 LAN뿐 아니라 외부에서도 접근됩니다.
  접속 URL: `http://<공인-IP>:3000`

### `monitoring up`

선택한 프로필로 Prometheus와 Grafana를 기동합니다.

입력:

- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--profile`: `lan` 또는 `public` (기본 `lan`)
- `--grafana-admin-password`: Grafana 관리자 비밀번호를 **최초 기동 시** 설정
  (환경 변수: `GRAFANA_ADMIN_PASSWORD`)

동작:

- 이미 실행 중이면 메시지를 출력하고 종료합니다.
- 비밀번호는 Grafana DB에 저장되므로, 최초 기동 이후에는 변경되지 않습니다.

접속 URL:

- `lan`: `http://<LAN-IP>:3000` (기본값이면 `http://127.0.0.1:3000`)
- `public`: `http://<공인-IP>:3000`

### `monitoring status`

모니터링 서비스 상태와 Grafana 접근 정보를 출력합니다.

출력:

- Prometheus/Grafana 상태/헬스
- Grafana 접속 URL(프로필 + `GRAFANA_LAN_BIND_ADDR` 기준)
- 관리자 비밀번호 상태:
  - `기본값(admin)`, `설정됨`, `알 수 없음`

비고:

- 실행 중인 프로필을 자동 감지합니다. `--profile`은 받지 않습니다.
- `--compose-file`로 대상 compose 파일 경로를 지정할 수 있습니다
  (기본값 `docker-compose.yml`).

### `monitoring down`

모니터링 컨테이너를 중지/삭제합니다(infra에는 영향 없음).

입력:

- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--reset-grafana-admin-password`: Grafana 데이터 볼륨을 삭제하여
  다음 `monitoring up`에서 비밀번호를 다시 적용할 수 있게 합니다.

비고:

- 실행 중인 프로필을 자동 감지합니다. `--profile`은 받지 않습니다.

## bootroot clean

로컬 환경을 완전히 정리해 처음부터 다시 시작할 수 있게 합니다.
컨테이너를 중지하고, 볼륨을 삭제하고, 생성된 시크릿/state/`.env`를
제거합니다. 정리 후 `bootroot infra install`과 `bootroot init`을 다시
실행하면 됩니다.

### 입력

- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--yes` / `-y`: 확인 프롬프트 생략

### 동작

- `docker compose down -v --remove-orphans` 실행
- `secrets/`, `state.json`, `.env` 삭제, 선택적으로 `certs/` 삭제
- 파괴적 작업 전 확인 프롬프트 표시(`--yes` 미사용 시)

### 예시

```bash
bootroot clean
```

## bootroot openbao save-unseal-keys

OpenBao 언실 키를 대화형으로 파일에 저장합니다. 저장된 파일은
`bootroot infra up` 재시작 시 자동 언실에 사용할 수 있습니다
(dev/test 편의 기능).

### 입력

- `--secrets-dir`: 시크릿 디렉터리 (기본값 `secrets`)

### 동작

- 언실 키를 프롬프트로 입력받아 시크릿 디렉터리에 파일로 저장
- 저장된 파일은 `bootroot infra up --openbao-unseal-from-file`에서 사용

### 예시

```bash
bootroot openbao save-unseal-keys
```

## bootroot openbao delete-unseal-keys

이전에 저장한 언실 키 파일을 삭제합니다.

### 입력

- `--secrets-dir`: 시크릿 디렉터리 (기본값 `secrets`)

### 예시

```bash
bootroot openbao delete-unseal-keys
```

## bootroot-remote (원격 bootstrap 실행 파일)

`bootroot-remote`는 `bootroot service add --delivery-mode remote-bootstrap`로
등록된 서비스를 위한 별도 실행 파일입니다. step-ca가 동작하는 머신의
OpenBao에 저장된 서비스 목표 상태(`secret_id`/`eab`/`responder_hmac`/`trust`)를
원격 서비스 머신에서 1회 bootstrap으로 반영해 `agent.toml` 같은 로컬
파일을 갱신합니다. 이후 secret_id 회전 시에는 `bootroot-remote apply-secret-id`
로 명시적 secret_id 전달을 수행합니다.
`bootroot-remote`도 공통 옵션 `--lang`(환경 변수 `BOOTROOT_LANG`)을 지원합니다.

전송 옵션(SSH, Ansible, cloud-init, systemd-credentials), `secret_id` 위생,
`RemoteBootstrapArtifact` 스키마 참조를 포함한 전체 워크스루는
[원격 부트스트랩 운영자 가이드](remote-bootstrap.md)를 참고하세요.

### `bootroot-remote bootstrap`

원격 노드에 서비스 시크릿/설정을 1회 pull+apply합니다.

주요 입력:

- `--artifact <path>`: 부트스트랩 아티팩트 JSON 파일 경로. 지정 시
  아티팩트 값이 개별 CLI 플래그보다 우선합니다. CLI 플래그는 아티팩트에
  없는 필드의 대체 값으로 사용됩니다. 민감한 `wrap_token` 값이 셸 명령줄과 `ps`
  출력에 노출되지 않도록 합니다. 래핑이 활성(기본값)이면
  `bootroot service add`는 `--artifact`를 사용하는 명령 템플릿을
  출력합니다.
  아티팩트에 `wrap_token`과 `wrap_expires_at` 필드가 포함된 경우
  `bootroot-remote`는 `sys/wrapping/unwrap`을 통해 토큰을 언래핑하여
  로그인 흐름 전에 `secret_id`를 얻습니다.
- `--openbao-url`: OpenBao API URL (환경 변수: `OPENBAO_URL`).
  `--artifact` 미지정 시 필수.
- `--kv-mount`: OpenBao KV v2 마운트 경로 (환경 변수: `OPENBAO_KV_MOUNT`)
  (기본값 `secret`)
- `--service-name`: `--artifact` 미지정 시 필수.
  - `bootroot service add`와 같은 단일 DNS label 규칙을 따릅니다.
- `--role-id-path`, `--secret-id-path`, `--eab-file-path`:
  `--artifact` 미지정 시 필수.
- `--agent-config-path`: `--artifact` 미지정 시 필수.
- baseline/profile 입력:
  `--agent-email`, `--agent-server`, `--agent-domain`,
  `--agent-responder-url`, `--profile-hostname`,
  `--profile-instance-id`, `--profile-cert-path`, `--profile-key-path`
  - `--agent-domain`은 점으로 구분된 DNS label들의 DNS 이름이어야 합니다.
  - `--profile-hostname`은 `--service-name`과 같은 단일 DNS label이어야
    합니다.
  - `--profile-instance-id`는 숫자만 허용됩니다. `bootroot service add`가
    생성하는 원격 handoff 명령 템플릿은 이 값을 이미 채워 둡니다.
  - `--profile-cert-path`, `--profile-key-path`는 선택입니다.
    미지정 시 `--agent-config-path` 기준 `certs/<service>.crt`,
    `certs/<service>.key`를 기본 경로로 사용합니다.
  - 기본값:
    - `--agent-email`: `admin@example.com`
    - `--agent-server`: `https://localhost:9000/acme/acme/directory`
    - `--agent-domain`: `trusted.domain`
    - `--agent-responder-url`: `http://127.0.0.1:8080`
    - `--profile-hostname`: `localhost`
  - `bootroot service add`가 출력하는 `원격 실행 명령 템플릿`은 `--artifact`
    플래그를 사용합니다. `--agent-server`, `--agent-responder-url` 값은
    명령줄이 아닌 아티팩트에 포함됩니다. localhost 기본값은 동일 호스트
    배치에서만 맞으며, 별도 서비스 머신에서는 아티팩트 전송 전에
    `bootstrap.json`을 편집하여 `stepca.internal`,
    `responder.internal` 같은 원격 접근 가능 엔드포인트로 교체해야 합니다.
- `--ca-bundle-path`: 관리되는 step-ca trust bundle을 쓸 출력 경로.
  `--artifact` 미지정 시 필수.
- 갱신 후 훅 플래그: `--reload-style`,
  `--reload-target`, `--post-renew-command`,
  `--post-renew-arg`, `--post-renew-timeout-secs`,
  `--post-renew-on-failure` (`bootroot service add`와
  동일한 의미; 생성된 원격 handoff 명령 템플릿에서
  전달)
- `--summary-json`(선택), `--output text|json` (기본값 `text`)

`agent.toml`이 아직 없으면 bootstrap 단계에서 baseline을 생성한 뒤, 서비스용
관리 대상 프로필 블록을 갱신(없으면 추가)합니다.

### `bootroot-remote apply-secret-id`

회전된 secret_id를 원격 서비스 머신에 반영합니다. control node에서
`bootroot rotate approle-secret-id` 실행 후, 새 secret_id를 서비스 머신에
전달할 때 사용합니다.

주요 입력:

- `--openbao-url`: OpenBao API URL (환경 변수: `OPENBAO_URL`)
- `--kv-mount`: OpenBao KV v2 마운트 경로 (환경 변수: `OPENBAO_KV_MOUNT`)
  (기본값 `secret`)
- `--service-name`
  - `bootroot service add`와 같은 단일 DNS label 규칙을 따릅니다.
- `--role-id-path`, `--secret-id-path`
- `--output text|json` (기본값 `text`)

출력 보안 규칙:

- text 출력은 항목별 상세 오류 메시지를 redaction 처리
- JSON 출력은 머신 파싱용이며 민감 아티팩트로 취급
