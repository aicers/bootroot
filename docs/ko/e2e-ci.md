# CI/E2E

이 문서는 bootroot의 CI/E2E 검증 구조, 시나리오별 실행 흐름,
로컬 사전검증 방법, 실패 점검 기준을 정리합니다.

## CI 워크플로 구성

PR 필수 CI(`.github/workflows/ci.yml`)는 다음을 실행합니다.

- `test-core`: 단위/통합 스모크 경로
- `test-docker-e2e-matrix`: 전체 흐름 + 회전/복구 Docker E2E 조합 검증

확장 E2E(`.github/workflows/e2e-extended.yml`)는 별도 실행됩니다.

- `workflow_dispatch` 수동 실행
- `23:30 KST` 스케줄(UTC cron) + 당일 `main` 커밋 활동(KST) 게이팅

확장 워크플로는 복원력/경합 같은 무거운 검증을 위해 PR 필수 경로와
분리되어 있습니다.

## E2E 용어와 구성 축

용어 정의:

- `control node`: `bootroot`를 실행하며 step-ca와 OpenBao가 설치되어
  인프라 초기화와 서비스 상태 기록을 담당하는 머신
- `remote node`: `bootroot-remote`를 실행해 서비스 머신의 로컬 파일/설정을 반영하는 머신

E2E 시나리오는 다음 두 축의 조합으로 구성됩니다.

1. 전달 모드 (`bootroot service add --delivery-mode` 선택지)
2. 호스트 이름 매핑 모드 (E2E 스크립트 실행 모드)

전달 모드(`--delivery-mode`):

- `local-file`: `--delivery-mode`의 선택지입니다. 서비스가 step-ca/OpenBao/
  responder가 동작하는 같은 머신에 추가될 때 사용합니다.
- `remote-bootstrap`: `--delivery-mode`의 선택지입니다. 서비스가 다른
  머신에 추가될 때 사용하며, control node의 `bootroot`와 서비스 머신의
  `bootroot-remote sync`를 함께 사용합니다.

호스트 이름 매핑 모드(E2E 실행 모드):

- `fqdn-only-hosts`: E2E 스크립트가 사용하는 모드 이름입니다. 호스트 머신
  `/etc/hosts`는 수정하지 않고 `localhost`/IP 기반으로 step-ca, responder에
  접속합니다.
- `hosts-all`: E2E 스크립트가 사용하는 모드 이름입니다. 호스트 머신
  `/etc/hosts`에 `stepca.internal`, `responder.internal` entry를 추가해 해당
  이름으로 접속합니다. E2E에서는 실행 중에만 추가하고 cleanup에서 제거하며,
  운영 환경에서는 DNS/hosts를 지속적으로 관리해야 합니다.

공통 동작: 위 두 매핑 모드 모두 서비스 SAN(FQDN) 도달을 위해 step-ca
컨테이너 내부 `/etc/hosts`에 서비스 FQDN -> responder IP 매핑을 설정합니다.

운영 참고: E2E의 hosts 추가/정리는 테스트 편의를 위한 동작입니다. 운영 환경에서는
이름 매핑(DNS/hosts)과 서비스/에이전트 상시 실행을 지속적으로 관리해야 합니다.

## Docker E2E 검증 범위

PR 필수 Docker 조합 검증은 다음을 검증합니다.

- 로컬 전달 E2E 시나리오 (`fqdn-only-hosts`)
- 로컬 전달 E2E 시나리오 (`hosts-all`)
- 원격 전달 E2E 시나리오 (`fqdn-only-hosts`)
- 원격 전달 E2E 시나리오 (`hosts-all`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac,trust_sync`)

주요 스크립트:

- `scripts/e2e/docker/run-main-lifecycle.sh`
- `scripts/e2e/docker/run-main-remote-lifecycle.sh`
- `scripts/e2e/docker/run-rotation-recovery.sh`

확장 워크플로는 다음을 검증합니다.

- baseline 경합/스케일 동작
- 반복 장애/복구 동작
- 주기 실행 모드 동등성(`systemd-timer`, `cron`)

주요 스크립트:

- `scripts/e2e/docker/run-extended-suite.sh`

## 시나리오별 구성과 실행 단계

이 섹션은 다른 메뉴의 핵심 맥락을 의도적으로 다시 설명합니다.
이 페이지 하나만 보고도 CI/E2E 시나리오를 이해하고 재현할 수 있도록 구성했습니다.

### 1) 로컬 전달 E2E 시나리오 (`fqdn-only-hosts`)

구성:

- `scripts/e2e/docker/run-main-lifecycle.sh` 기반 단일 머신 시나리오
- Docker Compose에서 `openbao`, `postgres`, `step-ca`, `bootroot-http01` 실행
- 서비스는 `--delivery-mode local-file`로 추가
- 이 시나리오의 서비스 구성(총 2개): `edge-proxy` (`daemon`), `web-app` (`docker`)
- 해석 모드는 `fqdn-only-hosts` (`/etc/hosts` 수정 없음)

목적:

- 기본 same-machine 온보딩 경로를 end-to-end로 검증
- `bootroot init` -> `service add` -> `verify` 흐름 검증
- same-machine 경로에서 회전 후 재발급 동작 검증

실행 단계:

1. `infra-up`: Compose 서비스 기동 및 readiness 대기
2. `init`: `bootroot init --summary-json` 실행 후 JSON에서 `root_token` 파싱
3. `service-add`: daemon + docker 서비스를 `local-file` 모드로 추가
4. `verify-initial`: 초기 인증서 발급/검증 후 fingerprint 스냅샷 저장
5. `rotate-responder-hmac`: 회전 실행 후 재발급 강제
6. `verify-after-responder-hmac`: 재검증 및 fingerprint 변경 확인
7. `cleanup`: 로그/아티팩트 수집 후 Compose 정리

실제 실행 명령(스크립트 발췌):

```bash
# 1) infra-up
bootroot infra up --compose-file "$COMPOSE_FILE"

# 2) init
BOOTROOT_LANG=en printf "y\ny\nn\n" | bootroot init \
  --compose-file "$COMPOSE_FILE" \
  --secrets-dir "$SECRETS_DIR" \
  --summary-json "$INIT_SUMMARY_JSON" \
  --auto-generate --show-secrets \
  --stepca-url "$STEPCA_EAB_URL" \
  --db-dsn "postgresql://step:step-pass@postgres:5432/step?sslmode=disable" \
  --responder-url "$RESPONDER_URL"

# 3) service-add
bootroot service add --service-name edge-proxy --deploy-type daemon \
  --delivery-mode local-file --agent-config "$AGENT_CONFIG_PATH"
bootroot service add --service-name web-app --deploy-type docker \
  --delivery-mode local-file --agent-config "$AGENT_CONFIG_PATH"

# 4) verify-initial / 6) verify-after-responder-hmac
bootroot verify --service-name edge-proxy --agent-config "$AGENT_CONFIG_PATH"
bootroot verify --service-name web-app --agent-config "$AGENT_CONFIG_PATH"

# 5) rotate-responder-hmac
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" --root-token "$OPENBAO_ROOT_TOKEN" \
  --yes responder-hmac
```

### 2) 로컬 전달 E2E 시나리오 (`hosts-all`)

구성:

- 위와 동일한 스크립트/토폴로지 사용
- `fqdn-only-hosts`와 동일한 서비스 구성: `edge-proxy` (`daemon`), `web-app` (`docker`)
- 해석 모드는 `hosts-all`
- 스크립트가 `stepca.internal`, `responder.internal` 임시 host entry를
  추가/삭제 (`sudo -n` 필요)

목적:

- `hosts-all` 이름 해석 경로 검증
- `/etc/hosts` 기반 이름 해석에서 발생하는 문제 조기 탐지

실행 단계:

1. `stepca.internal`, `responder.internal` host entry 추가
2. `fqdn-only-hosts`와 동일한 전체 흐름 phase 실행
3. cleanup에서 임시 host entry 제거

실제 실행 명령(스크립트 발췌):

```bash
# hosts-all 모드로 실행
RESOLUTION_MODE=hosts-all ./scripts/e2e/docker/run-main-lifecycle.sh

# 내부적으로 /etc/hosts 추가/정리
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 3) 원격 전달 E2E 시나리오 (`fqdn-only-hosts`)

구성:

- 한 번의 실행에서 두 workspace 사용:
  `control-node` (step-ca 머신 역할), `remote-node` (서비스 머신 역할)
- 서비스는 `--delivery-mode remote-bootstrap`으로 추가
- 이 시나리오의 서비스 구성(총 1개): `edge-proxy` (`daemon`)
- 원격 동기화 반영은 `bootroot-remote sync`로 수행
- 해석 모드는 `fqdn-only-hosts`

목적:

- remote-bootstrap 온보딩과 동기화 반영 방식 검증
- `secret_id`, `eab`, `responder_hmac`, `trust_sync` 항목의
  sync/ack 기반 상태 반영 검증
- 원격 회전/복구 시퀀스를 항목별로 검증

실행 단계:

1. control node에서 `infra-up`, `init` 실행 후 summary JSON에서 `root_token` 파싱
2. control node에서 `remote-bootstrap` 모드로 `service-add` 실행
3. bootstrap 재료(`role_id`, `secret_id`)를 remote node로 복사
4. `sync-initial`: remote node에서 `bootroot-remote sync` 실행
5. control node `state.json`에서 sync status가 `applied`인지 확인
6. `verify-initial`: remote node에서 인증서 발급/검증
7. 회전 + sync + verify 반복: `rotate-secret-id` -> `sync-after-secret-id` ->
   `verify-after-secret-id`,
   `rotate-eab` -> `sync-after-eab` -> `verify-after-eab`,
   `rotate-trust-sync` ->
   `sync-after-trust-sync` -> `verify-after-trust-sync`,
   `rotate-responder-hmac` ->
   `sync-after-responder-hmac` -> `verify-after-responder-hmac`
8. 각 검증 단계 사이 인증서 fingerprint 변경 여부 확인

실제 실행 명령(스크립트 발췌):

```bash
# control node: infra-up / init / service-add
bootroot infra up --compose-file "$COMPOSE_FILE"
BOOTROOT_LANG=en printf "y\ny\nn\n" | bootroot init \
  --compose-file "$COMPOSE_FILE" --summary-json "$INIT_SUMMARY_JSON" \
  --auto-generate --show-secrets --eab-kid "$INIT_EAB_KID" \
  --eab-hmac "$INIT_EAB_HMAC"
bootroot service add --service-name "$SERVICE_NAME" --deploy-type daemon \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH"

# remote node: sync
bootroot-remote sync --openbao-url "http://127.0.0.1:8200" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$role_id_path" --secret-id-path "$secret_id_path" \
  --agent-config-path "$REMOTE_AGENT_CONFIG_PATH" \
  --summary-json "$summary_path" --output json

# control node: verify / rotate
bootroot verify --service-name "$SERVICE_NAME" \
  --agent-config "$REMOTE_AGENT_CONFIG_PATH"
bootroot rotate --yes approle-secret-id --service-name "$SERVICE_NAME"
bootroot rotate --yes responder-hmac
```

### 4) 원격 전달 E2E 시나리오 (`hosts-all`)

구성:

- 위 원격 전달 E2E 시나리오와 동일한 control-node/remote-node 모델
- remote `fqdn-only-hosts`와 동일한 서비스 구성: `edge-proxy` (`daemon`)
- 해석 모드는 `hosts-all`
- 스크립트가 임시 `/etc/hosts` entry를 추가/정리

목적:

- hosts 기반 이름 해석에서 remote-bootstrap 전체 흐름 검증
- remote sync/verify 단계의 해석 모드 의존 실패 탐지

실행 단계:

1. `stepca.internal`, `responder.internal` host entry 추가
    - `stepca.internal` entry 추가
    - `responder.internal` entry 추가
2. 원격 전달 E2E 시나리오의 phase 전체 실행
3. cleanup에서 임시 host entry 제거
    - `HOSTS_MARKER`가 붙은 행만 삭제

실제 실행 명령(스크립트 발췌):

```bash
# hosts-all 모드로 원격 전체 흐름 실행
RESOLUTION_MODE=hosts-all ./scripts/e2e/docker/run-main-remote-lifecycle.sh

# 내부적으로 /etc/hosts 추가/정리
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 5) rotation/recovery matrix

구성:

- 스크립트: `scripts/e2e/docker/run-rotation-recovery.sh`
- 기본 시나리오 입력:
  `tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json`

#### 서비스 구성(3개 노드, 총 8개 서비스)

- `node-a`: daemon-c1 (daemon), daemon-c2 (daemon), docker-c1 (docker)
- `node-b`: daemon-c3 (daemon), docker-c2 (docker), docker-c3 (docker)
- `node-c`: daemon-c4 (daemon), docker-c4 (docker)

각 서비스에 대해 모든 회전 항목을 반복 검증합니다.

#### 회전 항목

- `secret_id,eab,responder_hmac,trust_sync`

목적:

- pending/applied/failed/expired 상태 전이 검증
- 단일 타깃 실패 주입 후 복구 검증
- `expired` 전이와 재동기화(`applied`) 검증

실행 단계(항목별 반복):

1. 모든 서비스 상태를 `pending`으로 마킹
2. sync cycle 1: `pending -> applied` 확인
3. sync cycle 2(재회전): `pending -> applied` 재확인
4. 실패 cycle: 특정 서비스 1회 실패를 주입하고, 타깃 서비스가 `failed` 또는 `pending`인지,
   다른 서비스가 `applied`를 유지하는지 확인
5. 복구 cycle: 타깃 서비스를 다시 `pending`으로 설정한 뒤 sync를 재실행해 `applied` 복구 확인
6. `secret_id` 항목은 추가로 summary+ack로 `expired`를 강제하고, sync 재실행 후 `applied` 복귀 확인

실제 실행 명령(스크립트 발췌):

```bash
# 시나리오 실행
./scripts/e2e/docker/run-rotation-recovery.sh

# 항목별 sync/ack 루프에서 사용하는 핵심 명령
./scripts/e2e/docker/run-sync-once.sh
bootroot verify --service-name "$service" --agent-config "$agent_config_path"

# expired 강제 및 ack 반영
bootroot service sync-status --service-name "$service_name" \
  --summary-json "$summary_path"
```

### 6) extended workflow 케이스

구성:

- 스크립트: `scripts/e2e/docker/run-extended-suite.sh`
- 케이스: `scale-contention`, `failure-recovery`, `runner-timer`, `runner-cron`
- 케이스 결과는 `extended-summary.json`에 집계
- 서비스 구성: 각 케이스가 사용하는 하위 시나리오/스크립트 구성을 그대로 상속하며,
  scale/contention, failure/recovery 케이스는 복수 서비스를 포함

목적:

- 무거운 stress/recovery 검증을 PR 필수 경로 밖에서 수행
- 주기 실행 모드 동등성(`systemd-timer`, `cron`) 검증
- 더 긴 cycle/time window에서 반복 안정성 검증

실행 단계:

1. 케이스별로 독립 실행하고 케이스별 `run.log` 저장
2. `phases.log`에 케이스 단위 `start/pass/fail` 기록
3. 전체 결과를 `extended-summary.json`으로 집계
4. 케이스 하나라도 `fail`이면 워크플로 실패 처리

실제 실행 명령(스크립트 발췌):

```bash
# 확장 스위트 실행
./scripts/e2e/docker/run-extended-suite.sh

# 케이스별 내부 호출
./scripts/e2e/docker/run-baseline.sh
./scripts/e2e/docker/run-rotation-recovery.sh
RUNNER_MODE=systemd-timer ./scripts/e2e/docker/run-harness-smoke.sh
RUNNER_MODE=cron ./scripts/e2e/docker/run-harness-smoke.sh
```

## 로컬 사전검증 표준

푸시 전 최소 다음을 모두 실행하세요.

1. `cargo test`
2. `./scripts/ci-local-e2e.sh`
3. `./scripts/e2e/docker/run-extended-suite.sh`

실행 가이드:

```bash
./scripts/ci-local-e2e.sh
./scripts/e2e/docker/run-extended-suite.sh
```

로컬에서 `sudo -n`이 불가능하면:

- `./scripts/ci-local-e2e.sh --skip-hosts-all`을 실행합니다.
- 이유: `hosts-all` 케이스는 실행 중 호스트 머신의 `/etc/hosts`를
  추가/복원해야 하며, 이 작업은 비대화식 관리자 권한(`sudo -n`)이
  필요합니다.

이는 로컬 제약 우회용입니다. CI에서는 `hosts-all` 케이스도 실행됩니다.

## init 자동화 입출력 규칙

라이프사이클 스크립트는 `bootroot init --summary-json` 출력으로 자동화를
수행합니다. 사람용 요약 텍스트를 파싱해 토큰/시크릿을 추출하지 않습니다.
로컬 CLI 시나리오 실행도 같은 방식으로 `--summary-json`의 `.root_token`을 사용합니다.
이 절차는 **테스트/자동화 편의용 규칙**이며, 운영 환경의 토큰 보관 정책을
대체하지 않습니다.

E2E가 사용하는 최소 머신 필드:

- `root_token`

E2E에서 OpenBao 언실/토큰 사용 방식:

- E2E는 보통 `init` 단계에서 한 번 언실한 뒤 같은 실행 동안 재언실하지 않음
- 다시 언실이 필요한 경우는 OpenBao가 다시 `sealed` 상태가 되었을 때뿐임
  (예: 프로세스/컨테이너 재시작, 수동 seal, 복구 절차)
- `root_token`은 `init-summary.json`에서 읽어 셸 변수(`OPENBAO_ROOT_TOKEN`)로
  보관하고, 같은 실행 내 `service add`/`rotate` 등에 `--root-token`으로 전달
- 테스트 스크립트도 root token을 장기 저장하지 않으며, 실행 컨텍스트 변수로만
  전달해 사용
- 요약 JSON 파일 자체에 토큰이 포함되므로 아티팩트 보관 시 민감정보로 취급
  해야 함

운영 가이드:

- init summary JSON은 민감 아티팩트로 취급
- 로그에 원문 시크릿 출력 금지
- 시크릿 파일/디렉터리 권한 `0600`/`0700` 유지

## 원격 동기화 검증 기준

이 섹션의 목적은 "원격 동기화가 실제로 반영되었는지"를 E2E에서 어떤 기준으로
판정하는지 명확히 정의하는 것입니다.

검증 흐름:

1. control node의 `bootroot service add --delivery-mode remote-bootstrap`가
   목표 상태를 기록합니다.
2. remote node의 `bootroot-remote sync`가 해당 상태를 읽어 로컬 파일/설정에
   반영합니다. (`sync` 내부에서 `pull`/`ack` 단계가 함께 수행됨)
3. E2E는 다음 두 출력이 같은 결과를 가리키는지 비교합니다:

    - `bootroot-remote sync --summary-json ...` 결과 JSON
    - control node의 `bootroot service sync-status` 조회 결과

비교 항목(서비스별):

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

판정 규칙:

- 각 항목의 상태가 두 출력에서 일치해야 함
- 회전 테스트에서는 `pending -> applied` 전이가 예상대로 발생해야 함
- 하나라도 `failed`로 남거나 두 출력이 불일치하면 해당 단계를 실패로 처리함

상태값 의미:

- `none`: 아직 대상 항목이 생성/기록되지 않음
- `pending`: 목표 상태는 기록되었지만 아직 반영 전
- `applied`: 원격 반영이 성공적으로 완료됨
- `failed`: 반영 중 오류가 발생함
- `expired`: 사용 가능 기간이 끝나 재동기화가 필요함

## E2E `phases.log` 형식

E2E 스크립트는 단계 진행 상태를 `phases.log` 파일로 남깁니다.
아래는 그 파일에 기록되는 이벤트 JSON 형식입니다.

로컬 전달 E2E 시나리오 스크립트는 다음 형식으로 기록합니다.

```json
{"ts":"2026-02-17T04:49:01Z","phase":"infra-up","mode":"fqdn-only-hosts"}
```

필드:

- `ts`: UTC 타임스탬프
- `phase`: 단계 식별자
- `mode`: 해석 모드(`fqdn-only-hosts` 또는 `hosts-all`)

확장 스위트는 다음 형식으로 기록합니다.

```json
{"ts":"2026-02-17T04:49:01Z","phase":"runner-cron","status":"pass"}
```

필드:

- `ts`: UTC 타임스탬프
- `phase`: 케이스 식별자
- `status`: `start|pass|fail`

## 아티팩트 경로

일반 사용자 관점에서는 필수 정보가 아닙니다.  
CI 실패를 직접 디버깅하는 사용자/기여자 관점에서는 유용한 정보입니다.

PR 필수 아티팩트 예시:

- `tmp/e2e/ci-main-fqdn-<run-id>`
- `tmp/e2e/ci-main-hosts-<run-id>`
- `tmp/e2e/ci-main-remote-fqdn-<run-id>`
- `tmp/e2e/ci-main-remote-hosts-<run-id>`
- `tmp/e2e/ci-rotation-<run-id>`

확장 아티팩트 예시:

- `tmp/e2e/extended-<run-id>`

## 실패 점검 순서

실패 시 다음 순서로 확인하세요.

1. `phases.log` (어느 단계에서 멈췄는지)
2. `run.log` (상위 실행 흐름)
3. `init.raw.log` / `init.log` (init 단계 상세)
4. `compose-logs.log` 또는 케이스별 로그 (컨테이너 상세)
5. `extended-summary.json` (확장 스위트 케이스 상태)
