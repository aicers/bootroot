# CLI

이 문서는 Bootroot 자동화를 위한 CLI(`bootroot`, `bootroot-remote`) 사용 방법을 정리합니다.

## 개요

CLI는 infra 기동/초기화/상태 점검과 서비스 온보딩, 발급 검증,
시크릿 회전을 제공합니다.
또한 Prometheus/Grafana 기반 로컬 모니터링을 관리합니다.
역할:

- `bootroot`: step-ca가 동작하는 머신에서 infra/init/service/rotate/monitoring 자동화
- `bootroot-remote`: 원격 서비스가 동작하는 머신에서 pull/sync/ack 동기화 수행

주요 명령:

- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot service add`
- `bootroot service info`
- `bootroot service sync-status`
- `bootroot verify`
- `bootroot rotate`
- `bootroot monitoring`
- `bootroot-remote pull/ack/sync`

## 공통 옵션

- `--lang`: 출력 언어 (`en` 또는 `ko`, 기본값 `en`)
  - 환경 변수: `BOOTROOT_LANG`

## bootroot CLI 자동 준비 범위와 운영자 책임

bootroot CLI가 자동으로 설치/기동해 주는 항목(Docker 경로):

- `bootroot infra up` 기준 OpenBao/PostgreSQL/step-ca/HTTP-01 responder
  컨테이너의 이미지 pull/build, 생성, 기동
- step-ca/OpenBao/responder가 한 머신에서 동작하는 bootroot 기본 토폴로지에서
  `bootroot init` 기준 step-ca/responder용 OpenBao Agent 설정 생성 및
  compose override를 통한 `openbao-agent-stepca`/`openbao-agent-responder`
  컨테이너 활성화

단, 호스트 바이너리/서비스(systemd 유닛 등) 설치는 자동으로 수행하지 않습니다.

bootroot CLI가 자동으로 준비하는 항목:

- 서비스/시크릿 관련 설정 및 상태 파일(`state.json`, 서비스별 AppRole/secret 파일 등)
- `service add`/`init`/`rotate` 흐름에서 생성되는 로컬 구성 파일 갱신

운영자가 직접 설치/관리해야 하는 항목:

- `bootroot` CLI
- `bootroot-agent`
- `bootroot-remote`(추가 서비스가 step-ca 운영 머신이 아닌 다른 머신에서 동작할 때,
  해당 서비스 머신에서 실행하는 CLI)
- OpenBao Agent

프로세스 상시 운영도 운영자 책임입니다.

- systemd 모드: `Restart=always` 또는 `on-failure` 설정
- 컨테이너 모드: 컨테이너 restart 정책 + Docker 데몬 부팅 자동 시작

추가 서비스가 step-ca 운영 머신이 아닌 다른 머신에서 동작하는 경우, 해당
서비스 머신에서 `bootroot-remote sync`를 주기 실행(systemd timer 또는 cron)으로
구성해야 합니다.

## 이름 해석(DNS/hosts) 운영 책임

HTTP-01 검증에서 step-ca는 각 검증 FQDN
(`<instance>.<service>.<hostname>.<domain>`)을 responder 대상으로 해석할 수
있어야 합니다.

step-ca/responder 엔드포인트를 IP가 아닌 이름으로 사용한다면, 참여하는 모든
호스트에서 DNS/hosts를 일관되게 설정해야 합니다.

- control/step-ca 호스트
- 각 remote 서비스 호스트

로컬 Docker E2E에서는 이 매핑을 테스트 스크립트가 자동 주입합니다.

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
- `--openbao-unseal-from-file`: 파일에서 OpenBao 언실 키 읽기 (dev/test 전용)

### 출력

- 컨테이너 상태/헬스 요약
- 완료 메시지

### 실패 조건

다음 조건이면 실패로 판정합니다.

- docker compose/pull 실패
- 컨테이너 미기동 또는 헬스 체크 실패

### 예시

```bash
bootroot infra up
```

## bootroot init

OpenBao 초기화/언실/정책/AppRole 구성, step-ca 초기화, 시크릿 등록을 수행합니다.

### 입력

입력 우선순위는 **CLI 옵션 > 환경 변수 > 프롬프트/기본값**입니다.

- `--openbao-url`: OpenBao API URL (기본값 `http://localhost:8200`)
- `--kv-mount`: OpenBao KV v2 마운트 경로 (기본값 `secret`)
- `--secrets-dir`: 시크릿 디렉터리 (기본값 `secrets`)
- `--compose-file`: infra 상태 점검용 compose 파일 (기본값 `docker-compose.yml`)
- `--auto-generate`: 비밀번호/HMAC 등을 자동 생성
- `--show-secrets`: 요약 출력에 시크릿 표시
- `--summary-json`: init 요약을 머신 파싱용 JSON 파일로 저장
- `--root-token`: OpenBao root token (환경 변수: `OPENBAO_ROOT_TOKEN`)
- `--unseal-key`: OpenBao unseal key (반복 가능, 환경 변수: `OPENBAO_UNSEAL_KEYS`)
- `--openbao-unseal-from-file`: 파일에서 OpenBao 언실 키 읽기 (dev/test 전용)
- `--stepca-password`: step-ca 키 암호 (`password.txt`, 환경 변수: `STEPCA_PASSWORD`)
- `--db-dsn`: step-ca용 PostgreSQL DSN
- `--db-provision`: step-ca용 PostgreSQL 역할/DB 생성
- `--db-admin-dsn`: PostgreSQL 관리자 DSN (환경 변수: `BOOTROOT_DB_ADMIN_DSN`)
- `--db-user`: step-ca용 PostgreSQL 사용자 (환경 변수: `BOOTROOT_DB_USER`)
- `--db-password`: step-ca용 PostgreSQL 비밀번호 (환경 변수: `BOOTROOT_DB_PASSWORD`)
- `--db-name`: step-ca용 PostgreSQL DB 이름 (환경 변수: `BOOTROOT_DB_NAME`)
- `--db-check`: DB 연결/인증 점검
- `--db-timeout-secs`: DB 연결 타임아웃(초)
- `--http-hmac`: HTTP-01 responder HMAC (환경 변수: `HTTP01_HMAC`)
- `--responder-url`: HTTP-01 responder 관리자 URL (선택, 환경 변수: `HTTP01_RESPONDER_URL`)
- `--skip-responder-check`: init 시 responder 체크 생략(테스트/제약 환경용)
- `--responder-timeout-secs`: responder 요청 타임아웃(초, 기본값 `5`)
- `--eab-auto`: step-ca에서 EAB 자동 발급
- `--stepca-url`: step-ca URL (기본값 `https://localhost:9000`)
- `--stepca-provisioner`: step-ca ACME provisioner 이름 (기본값 `acme`)
- `--eab-kid`, `--eab-hmac`: 수동 EAB 입력

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

현재 기본 토폴로지에서는 OpenBao, step-ca, responder가 step-ca가 설치된
머신에서 함께 동작하며 로컬 `secrets` 디렉터리를 공유합니다.

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
bootroot init --auto-generate --eab-auto --responder-url http://localhost:8080
```

## bootroot status

infra 상태(컨테이너 포함)와 OpenBao KV/AppRole 상태를 점검합니다.

### 입력

- `--compose-file`: compose 파일 경로
- `--openbao-url`: OpenBao URL
- `--kv-mount`: OpenBao KV v2 마운트 경로
- `--root-token`: KV/AppRole 체크용 토큰(선택)

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
**`bootroot` CLI**가 아래 자동화를 수행합니다.

- 서비스 메타데이터를 `state.json`에 등록
- 서비스 전용 OpenBao 정책/AppRole 생성, `role_id`/`secret_id` 발급
- `secrets/services/<service>/role_id`, `secret_id` 파일 생성
- 결과 요약 출력(기본 모드에서는 수동 스니펫 숨김)

전달 모드(`--delivery-mode`) 선택값별 자동 반영:

1. `local-file`:
   서비스가 step-ca/OpenBao/responder가 설치된 동일 머신에 추가될 때
   사용합니다. `agent.toml`의 관리 대상 프로필 블록 갱신(없으면 추가)과 OpenBao Agent
   템플릿/설정/토큰 파일 생성을 로컬에서 바로 처리합니다.
2. `remote-bootstrap`:
   서비스가 step-ca/OpenBao/responder가 설치된 머신이 아닌 다른 머신에
   추가될 때 사용합니다. 원격 반영용 OpenBao KV 번들
   (`secret_id`/`eab`/`responder_hmac`/`trust`)을 기록하고 원격 bootstrap
   아티팩트를 생성합니다. 여기서 "원격 반영용"은 step-ca가 동작하는 머신의
   `bootroot`가 기록한 목표 설정/시크릿 묶음을 원격 서비스 머신의
   `bootroot-remote`가 pull해서 반영한다는 의미입니다. "원격 bootstrap
   아티팩트"는 이 원격 동기화를 시작할 때 필요한 초기 입력/실행 정보를 담은
   산출물입니다.

이 명령은 새 서비스 추가 시 **인증서 발급/갱신 경로를 준비**하는 필수 단계입니다.
다만 `bootroot service add` 자체가 인증서를 발급하지는 않습니다.

사용자가 직접 해야 할 작업:

- 서비스 머신에서 OpenBao Agent/bootroot-agent를 실제로 기동/상시 운영
- `remote-bootstrap`인 경우 서비스 머신에서 `bootroot-remote` 주기 실행 구성
- `bootroot verify` 또는 실제 서비스 실행으로 발급 경로 검증

기본 흐름에서 `bootroot init`를 정상 완료하면 OpenBao의
`secret/bootroot/ca`가 자동으로 준비되며, 기본 실행
(`--print-only`/`--dry-run` 없이 실행)의 `bootroot service add`가 trust
관련 값도 자동으로 처리합니다.

- `remote-bootstrap` 경로: `trusted_ca_sha256`를 서비스별 원격 sync
  번들(`secret/.../services/<service>/trust`)에 자동 기록하고, 원격 서비스
  머신의 `bootroot-remote sync`가 이를 `agent.toml` trust 항목에 반영합니다.
- `local-file` 경로: trust 항목(`trusted_ca_sha256`)은 `agent.toml`에 자동
  삽입되지 않습니다. 따라서 trust 검증을 사용할 경우 `agent.toml`에 해당
  항목을 수동으로 설정해야 합니다.

preview 모드(`--print-only`/`--dry-run`) 주의:

- OpenBao를 조회하지 않으므로 trust 값이 스니펫에 자동 포함되지 않습니다.

사용자가 수동으로 설정해야 하는 대표 상황:

- `local-file` 경로에서 `agent.toml`에 trust 항목을 직접 고정해 관리하려는 경우
- preview 출력만 보고 설정을 적용하는 경우

`--print-only`/`--dry-run`은 파일/상태를 쓰지 않고 수동 스니펫만 출력하는
미리보기 모드입니다.

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
- `--deploy-type`: 배포 타입 (`daemon` 또는 `docker`)
- `--delivery-mode`: 전달 모드 (`local-file` 또는 `remote-bootstrap`).
  참고: `remote-bootstrap`은 실행 파일이 아니라 모드 값이며, 이 모드에서
  사용하는 실행 파일은 `bootroot-remote`입니다.
- `--hostname`: DNS SAN에 사용할 호스트명
- `--domain`: DNS SAN 루트 도메인
- `--agent-config`: bootroot-agent 설정 파일 경로
- `--cert-path`: 인증서 출력 경로
- `--key-path`: 개인키 출력 경로
- `--instance-id`: 서비스 instance_id
- `--container-name`: 도커 서비스 컨테이너 이름 (docker 필수)
- `--root-token`: OpenBao root token (환경 변수: `OPENBAO_ROOT_TOKEN`)
- `--notes`: 메모(선택)
- `--print-only`: 파일/state 변경 없이 안내/스니펫만 출력
- `--dry-run`: preview 모드 별칭(`--print-only`와 동일)

### 대화형 동작

- 누락된 필수 입력을 프롬프트로 받습니다(배포 타입 기본값: `daemon`).
- 입력값은 빈 값 여부, 허용된 enum 값인지, 경로/상위 디렉터리가
  유효한지 확인합니다.
- 실행 전 계획 요약, 실행 후 최종 요약을 출력합니다.

### 출력

- 서비스 메타데이터 요약
- AppRole/정책/secret_id 경로 요약
- 전달 모드 및 항목별 sync-status 요약(`local-file`은
  `agent.toml`/OpenBao Agent 설정/템플릿 자동 반영 경로, `remote-bootstrap`은
  부트스트랩 아티팩트 + 원격 실행 명령 출력)
- 서비스별 OpenBao Agent 안내(daemon/docker 분리)
- 타입별 온보딩 안내 (daemon 프로필 / docker sidecar)
- daemon/docker 스니펫(복붙용) 출력(`--print-only`/`--dry-run`에서만)

### 실패 조건

다음 조건이면 실패로 판정합니다.

- `state.json` 누락
- 중복된 `service-name`
- `instance-id` 누락
- docker에 `container-name` 누락
- OpenBao AppRole 생성 실패

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

## bootroot service sync-status

`bootroot-remote`가 생성한 summary JSON을 바탕으로 `state.json`의 sync-status를
갱신합니다. 일반적으로 `bootroot-remote ack`가 이 명령을 호출합니다.

### 입력

- `--service-name`: 서비스 이름
- `--summary-json`: `bootroot-remote pull/sync` summary JSON 경로
- `--state-file`: `state.json` 경로 오버라이드(선택)

### 추적 항목

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

### 상태 값

- `none`: 아직 추적 대상 아님
- `pending`: 원격 반영 대기
- `applied`: 원격 반영 ack 완료
- `failed`: 반영 실패
- `expired`: pending 유지 시간이 기준을 초과해 만료됨

### 출력

- 대상 서비스의 항목별 sync-status 요약
- 갱신된 `state.json`(또는 `--state-file`) 메타데이터/타임스탬프

### 실패 조건

다음 조건이면 실패로 판정합니다.

- `state.json` 누락 또는 파싱 실패
- summary JSON 누락/파싱 실패
- 대상 서비스 미등록

## bootroot verify

bootroot-agent를 one-shot으로 실행해 발급을 검증합니다. 서비스 온보딩 직후
또는 설정 변경 후에 실제 발급이 가능한지 확인할 때 사용합니다.
검증 이후에도 **주기적 갱신을 원하면 bootroot-agent를 상시 모드로
실행**해야 합니다(oneshot 없이 실행).

### 입력

- `--service-name`: 서비스 이름 식별자
- `--agent-config`: bootroot-agent 설정 경로 (선택, 기본은 등록된 값)
- `--db-check`: ca.json DSN으로 DB 연결/인증 점검
- `--db-timeout-secs`: DB 연결 타임아웃(초)

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

### 입력

공통:

- `--state-file`: `state.json` 경로 (선택)
- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--openbao-url`: OpenBao API URL (선택)
- `--kv-mount`: OpenBao KV 마운트 경로 (선택)
- `--secrets-dir`: 시크릿 디렉터리 (선택)
- `--root-token`: OpenBao root token (환경 변수 `OPENBAO_ROOT_TOKEN`)
- `--yes`: 확인 프롬프트 생략

서브커맨드별:

#### `rotate stepca-password`

- `--new-password`: 새 step-ca 키 비밀번호(선택, 미지정 시 자동 생성)
- 구현 참고: bootroot는 비대화형 Docker 환경에서 overwrite 확인 프롬프트로
  인한 실패를 막기 위해 `step crypto change-pass`를 `-f`(`--force`)와 함께
  실행합니다.

#### `rotate eab`

- `--stepca-url`: step-ca URL
- `--stepca-provisioner`: ACME 프로비저너 이름

#### `rotate db`

- `--db-admin-dsn`: DB 관리자 DSN (환경 변수 `BOOTROOT_DB_ADMIN_DSN`)
- `--db-password`: 새 DB 비밀번호(선택, 미지정 시 자동 생성)
- `--db-timeout-secs`: DB 점검 타임아웃(초)

#### `rotate responder-hmac`

- `--hmac`: 새 responder HMAC(선택, 미지정 시 자동 생성)

#### `rotate approle-secret-id`

- `--service-name`: 대상 서비스 이름

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
- root token 누락 또는 인증 실패
- step-ca 비밀번호 회전 시 키/비밀번호 파일 누락
- DB 회전 시 관리자 DSN 누락 또는 DB 프로비저닝 실패
- EAB 발급 요청 실패
- responder 설정 파일 쓰기 실패 또는 리로드 실패
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

- `--profile`: `lan` 또는 `public` (기본 `lan`)
- `--grafana-admin-password`: Grafana 관리자 비밀번호를 **최초 기동 시** 설정
  (환경 변수 `GRAFANA_ADMIN_PASSWORD`로도 지정 가능)

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

### `monitoring down`

모니터링 컨테이너를 중지/삭제합니다(infra에는 영향 없음).

입력:

- `--reset-grafana-admin-password`: Grafana 데이터 볼륨을 삭제하여
  다음 `monitoring up`에서 비밀번호를 다시 적용할 수 있게 합니다.

비고:

- 실행 중인 프로필을 자동 감지합니다. `--profile`은 받지 않습니다.

## bootroot-remote (원격 동기화 실행 파일)

`bootroot-remote`는 `bootroot service add --delivery-mode remote-bootstrap`로
등록된 서비스를 위한 별도 실행 파일입니다. step-ca가 동작하는 머신의
OpenBao에 저장된 서비스 목표 상태(`secret_id`/`eab`/`responder_hmac`/`trust`)를
원격 서비스 머신에서 `pull/sync/ack` 순서로 반영해 `agent.toml` 같은 로컬
파일을 갱신하고, 결과를 `state.json`의 sync-status에 기록합니다.

### `bootroot-remote pull`

원격 노드에 서비스 시크릿/설정을 pull+apply합니다.

주요 입력:

- `--openbao-url`, `--kv-mount`, `--service-name`
- `--role-id-path`, `--secret-id-path`, `--eab-file-path`
- `--agent-config-path`
- baseline/profile 입력:
  `--agent-email`, `--agent-server`, `--agent-domain`,
  `--agent-responder-url`, `--profile-hostname`,
  `--profile-instance-id`, `--profile-cert-path`, `--profile-key-path`
- `--ca-bundle-path`
- `--summary-json`(선택), `--output text|json`

`agent.toml`이 아직 없으면 pull 단계에서 baseline을 생성한 뒤, 서비스용
관리 대상 프로필 블록을 갱신(없으면 추가)합니다.

### `bootroot-remote ack`

summary 파일을 `state.json`의 sync-status로 반영합니다.

주요 입력:

- `--service-name`
- `--summary-json`
- `--bootroot-bin`(기본 `bootroot`)
- `--state-file`(선택)

### `bootroot-remote sync`

스케줄 실행을 위해 `pull + ack`를 retry/backoff/jitter와 함께 수행합니다.
운영에서는 systemd timer 또는 cron으로 이 명령을 주기 실행해야 합니다.

주요 재시도 입력:

- `--retry-attempts`
- `--retry-backoff-secs`
- `--retry-jitter-secs`

summary JSON 계약 항목:

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

각 항목은 pull 결과에서 `applied|unchanged|failed`로 기록되고,
ack 단계에서 `state.json`의 sync-status 값으로 매핑됩니다.

출력 보안 규칙:

- text 출력은 항목별 상세 오류 메시지를 redaction 처리
- JSON 출력은 머신 파싱용이며 민감 아티팩트로 취급
