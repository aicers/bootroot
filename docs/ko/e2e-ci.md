# CI/E2E

이 문서는 bootroot의 CI/E2E 검증 구조, 시나리오별 실행 흐름,
로컬 사전검증 방법, 실패 점검 기준을 정리합니다.

## CI 워크플로 구성

PR 필수 CI(`.github/workflows/ci.yml`)는 다음을 실행합니다.

- `test-core`: 단위/통합 스모크 경로
- `test-docker-e2e-matrix`: 전체 흐름 + 회전/복구 Docker E2E 조합 검증
  (5개 시나리오가 matrix 전략으로 병렬 실행)

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
  `bootroot-remote bootstrap`을 함께 사용합니다.

호스트 이름 매핑 모드(E2E 실행 모드):

- `no-hosts`: E2E 스크립트가 사용하는 모드 이름입니다. 호스트 머신
  `/etc/hosts`는 수정하지 않고 `localhost`/IP 기반으로 step-ca, responder에
  접속합니다.
- `hosts`: E2E 스크립트가 사용하는 모드 이름입니다. 호스트 머신
  `/etc/hosts`에 `stepca.internal`, `responder.internal` entry를 추가해 해당
  이름으로 접속합니다. E2E에서는 실행 중에만 추가하고 cleanup에서 제거하며,
  운영 환경에서는 DNS/hosts를 지속적으로 관리해야 합니다.

공통 동작: 위 두 매핑 모드 모두 서비스 SAN(FQDN) 도달을 위해 step-ca
컨테이너 내부 `/etc/hosts`에 서비스 FQDN -> responder IP 매핑을 설정합니다.

운영 참고: E2E의 hosts 추가/정리는 테스트 편의를 위한 동작입니다. 운영 환경에서는
이름 매핑(DNS/hosts)과 서비스/에이전트 상시 실행을 지속적으로 관리해야 합니다.

## Docker E2E 검증 범위

PR 필수 Docker 조합 검증은 다음을 검증합니다.

- 로컬 전달 E2E 시나리오 (`no-hosts`)
- 로컬 전달 E2E 시나리오 (`hosts`)
- 원격 전달 E2E 시나리오 (`no-hosts`)
- 원격 전달 E2E 시나리오 (`hosts`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac,trust_sync`)

주요 스크립트:

- `scripts/impl/run-local-lifecycle.sh`
- `scripts/impl/run-remote-lifecycle.sh`
- `scripts/impl/run-rotation-recovery.sh`

확장 워크플로는 다음을 검증합니다.

- baseline 경합/스케일 동작
- 반복 장애/복구 동작
- 회전 스케줄 동등성(`systemd-timer`, `cron`)
- CA 키 회전 장애/복구(5개 장애 주입 시나리오)
- 인프라 라이프사이클(전체 로컬 전달 왕복)

주요 스크립트:

- `scripts/impl/run-extended-suite.sh`

## 시나리오별 구성과 실행 단계

이 섹션은 다른 메뉴의 핵심 맥락을 의도적으로 다시 설명합니다.
이 페이지 하나만 보고도 CI/E2E 시나리오를 이해하고 재현할 수 있도록 구성했습니다.

### 1) 로컬 전달 E2E 시나리오 (`no-hosts`)

구성:

- `scripts/impl/run-local-lifecycle.sh` 기반 단일 머신 시나리오
- Docker Compose에서 `openbao`, `postgres`, `step-ca`, `bootroot-http01` 실행
- 서비스는 `--delivery-mode local-file`로 추가
- 이 시나리오의 서비스 구성(총 2개): `edge-proxy` (`daemon`), `web-app` (`docker`)
- 해석 모드는 `no-hosts` (`/etc/hosts` 수정 없음)

목적:

- 기본 same-machine 온보딩 경로를 end-to-end로 검증
- `bootroot init` -> `service add` -> `verify` 흐름 검증
- same-machine 경로에서 회전 후 재발급 동작 검증

실행 단계:

1. `infra-up`: Compose 서비스 기동 및 readiness 대기
2. `init`: `bootroot init --summary-json` 실행 후 JSON에서 런타임 AppRole
   자격증명 파싱
3. `service-add`: daemon + docker 서비스를 `local-file` 모드로 추가
4. `verify-initial`: 초기 인증서 발급/검증 후 fingerprint 스냅샷 저장
5. `rotate-openbao-recovery`: OpenBao 루트 토큰 수동 회전
6. `bootstrap-after-openbao-recovery`: remote bootstrap 재실행으로
   AppRole 기반 접근 연속성 검증
7. `rotate-responder-hmac`: 회전 실행 후 재발급 강제
8. `verify-after-responder-hmac`: 재검증 및 fingerprint 변경 확인
9. `cleanup`: 로그/아티팩트 수집 후 Compose 정리

실제 실행 명령(스크립트 발췌):

```bash
# 1) infra-install (.env 생성, 컨테이너 시작)
bootroot infra install --compose-file "$COMPOSE_FILE"

# 2) init
# DB 자격 증명은 infra install이 생성한 .env에서 자동으로 읽힙니다.
# POSTGRES_HOST와 POSTGRES_PORT는 스크립트에서 설정하여
# host-mapped 포트를 통해 연결합니다.
BOOTROOT_LANG=en printf "y\n" | bootroot init \
  --compose-file "$COMPOSE_FILE" \
  --secrets-dir "$SECRETS_DIR" \
  --summary-json "$INIT_SUMMARY_JSON" \
  --enable auto-generate,show-secrets,db-provision \
  --stepca-url "$STEPCA_EAB_URL" \
  --db-user "step" \
  --db-name "stepca" \
  --responder-url "$RESPONDER_URL"

# 3) service-add
bootroot service add --service-name edge-proxy --deploy-type daemon \
  --delivery-mode local-file --agent-config "$AGENT_CONFIG_PATH"
bootroot service add --service-name web-app --deploy-type docker \
  --delivery-mode local-file --agent-config "$AGENT_CONFIG_PATH"

# 4) verify-initial / 8) verify-after-responder-hmac
bootroot verify --service-name edge-proxy --agent-config "$AGENT_CONFIG_PATH"
bootroot verify --service-name web-app --agent-config "$AGENT_CONFIG_PATH"

# 5) rotate-openbao-recovery (명시적 수동 실행)
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --root-token "$INIT_ROOT_TOKEN" \
  --yes \
  openbao-recovery \
  --rotate-root-token \
  --output "$OPENBAO_RECOVERY_OUTPUT_FILE"

# 7) rotate-responder-hmac
# init summary에서
#   runtime_service_add: role_id/secret_id
#   runtime_rotate: role_id/secret_id
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --auth-mode approle \
  --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
  --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
  --yes responder-hmac
```

### 2) 로컬 전달 E2E 시나리오 (`hosts`)

구성:

- 위와 동일한 스크립트/토폴로지 사용
- `no-hosts`와 동일한 서비스 구성: `edge-proxy` (`daemon`), `web-app` (`docker`)
- 해석 모드는 `hosts`
- 스크립트가 `stepca.internal`, `responder.internal` 임시 host entry를
  추가/삭제 (`sudo -n` 필요)

목적:

- `hosts` 이름 해석 경로 검증
- `/etc/hosts` 기반 이름 해석에서 발생하는 문제 조기 탐지

실행 단계:

1. `stepca.internal`, `responder.internal` host entry 추가
2. `no-hosts`와 동일한 전체 흐름 phase 실행
3. cleanup에서 임시 host entry 제거

실제 실행 명령(스크립트 발췌):

```bash
# hosts 모드로 실행
RESOLUTION_MODE=hosts ./scripts/impl/run-local-lifecycle.sh

# 내부적으로 /etc/hosts 추가/정리
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 3) 원격 전달 E2E 시나리오 (`no-hosts`)

구성:

- 한 번의 실행에서 두 workspace 사용:
  `control-node` (step-ca 머신 역할), `remote-node` (서비스 머신 역할)
- 서비스는 `--delivery-mode remote-bootstrap`으로 추가
- 이 시나리오의 서비스 구성(총 2개): `edge-proxy` (`daemon`),
  `web-app` (`docker`)
- 원격 bootstrap 반영은 `bootroot-remote bootstrap`으로 수행
- 해석 모드는 `no-hosts`

목적:

- remote-bootstrap 온보딩과 일회성 bootstrap 반영 방식 검증
- `secret_id`, `eab`, `trust_sync`, `responder_hmac` 항목의
  bootstrap 기반 반영 검증
- 원격 회전/복구 시퀀스와 전체 `bootstrap` 재반영 검증

실행 단계:

1. control node에서 `infra-up`, `init` 실행 후 summary JSON에서 런타임
   AppRole 자격증명 파싱
2. control node에서 `remote-bootstrap` 모드로 두 서비스 `service-add` 실행
3. bootstrap 재료(`role_id`, `secret_id`)를 remote node로 복사
4. `bootstrap-initial`: remote node에서 서비스별 `bootroot-remote bootstrap`
   실행
5. `verify-initial`: remote node에서 인증서 발급/검증
6. 회전 + bootstrap 재반영 + verify 반복:
   `rotate-secret-id` -> `bootstrap` -> `verify-after-secret-id`,
   `rotate-eab` -> `bootstrap` -> `verify-after-eab`,
   `rotate-trust-sync` -> `bootstrap` -> `verify-after-trust-sync`,
   `rotate-responder-hmac` -> `bootstrap` -> `verify-after-responder-hmac`
7. 각 검증 단계 사이 인증서 fingerprint 변경 여부 확인

실제 실행 명령(스크립트 발췌):

```bash
# control node: infra-install / init / service-add
bootroot infra install --compose-file "$COMPOSE_FILE"
BOOTROOT_LANG=en printf "y\ny\nn\n" | bootroot init \
  --compose-file "$COMPOSE_FILE" --summary-json "$INIT_SUMMARY_JSON" \
  --enable auto-generate,show-secrets --eab-kid "$INIT_EAB_KID" \
  --eab-hmac "$INIT_EAB_HMAC"
bootroot service add --service-name edge-proxy --deploy-type daemon \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH"
bootroot service add --service-name web-app --deploy-type docker \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH_2"

# remote node: bootstrap (서비스별)
bootroot-remote bootstrap --openbao-url "http://127.0.0.1:8200" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$role_id_path" --secret-id-path "$secret_id_path" \
  --agent-config-path "$REMOTE_AGENT_CONFIG_PATH" \
  --output json

# control node: rotate / remote node: bootstrap 재반영
bootroot rotate --yes approle-secret-id --service-name edge-proxy
bootroot rotate --yes approle-secret-id --service-name web-app
bootroot-remote bootstrap ...  # 서비스별 재반영
bootroot rotate --yes responder-hmac
bootroot-remote bootstrap ...  # 서비스별 재반영
```

### 4) 원격 전달 E2E 시나리오 (`hosts`)

구성:

- 위 원격 전달 E2E 시나리오와 동일한 control-node/remote-node 모델
- remote `no-hosts`와 동일한 서비스 구성: `edge-proxy` (`daemon`),
  `web-app` (`docker`)
- 해석 모드는 `hosts`
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
# hosts 모드로 원격 전체 흐름 실행
RESOLUTION_MODE=hosts ./scripts/impl/run-remote-lifecycle.sh

# 내부적으로 /etc/hosts 추가/정리
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 5) rotation/recovery matrix

구성:

- 스크립트: `scripts/impl/run-rotation-recovery.sh`
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

- 항목별 회전 및 복구 동작 검증
- 단일 타깃 실패 주입 후 복구 검증
- 원격 노드에서 회전 후 bootstrap 재반영 검증

실행 단계(항목별 반복):

1. control node에서 대상 항목 회전
2. 각 remote node에서 `bootroot-remote bootstrap` 실행하여 재반영
3. 회전 후 인증서 발급이 정상 동작하는지 검증
4. 실패 cycle: 특정 서비스 실패 주입 후 복구 확인
5. 복구 cycle: 재회전/재반영 후 정상 동작 확인

실제 실행 명령(스크립트 발췌):

```bash
# 시나리오 실행
./scripts/impl/run-rotation-recovery.sh

# 회전/verify 루프에서 사용하는 핵심 명령
bootroot rotate --yes approle-secret-id --service-name "$service"
bootroot-remote bootstrap --service-name "$service" ...
bootroot verify --service-name "$service" --agent-config "$agent_config_path"
```

### 6) CA 키 회전 장애/복구

구성:

- 스크립트: `scripts/impl/run-ca-key-rotation-recovery.sh`
- Docker Compose 인프라 기반 단일 머신
- 서비스 구성(총 3개): `edge-proxy` (`daemon`, `local-file`),
  `web-app` (`docker`, `local-file`), `edge-proxy` (`daemon`,
  `remote-bootstrap`)
- 5개 장애 주입 시나리오를 동일 인프라에서 순차 실행

목적:

- `bootroot rotate ca-key`가 인프라 장애 후 올바르게 이어서
  진행되는지 검증
- CA 키 회전 중 mTLS가 중단되지 않는지 검증
- `rotation-state.json` 멱등 phase 추적 검증
- `--skip reissue`, `--force`, `--cleanup` 플래그 동작 검증
- 활성 회전 중 `trust-sync` 충돌 방지 검증

#### 시나리오

시나리오 1 — Phase 3 장애(OpenBao 접근 불가):

1. OpenBao 컨테이너 중지 → Phase 3(가산적 trust 기록) 실패
2. `rotate ca-key` 실행 → 실패 기대
3. 서비스 정상 동작 확인(cert 미변경, step-ca 실행 중)
4. OpenBao 재시작 후 회전 재실행 → 이어서 완료
5. 강제 재발급 후 새 인증서 검증

시나리오 2 — Phase 4 장애(step-ca 제거):

1. step-ca 컨테이너 제거 → Phase 4(재시작) 실패
2. `rotate ca-key` 실행 → Phase 0-3 성공, Phase 4 실패
3. 서비스 정상 동작 확인(전이 trust 활성)
4. step-ca 복구 후 회전 재실행 → 이어서 완료
5. 강제 재발급 후 새 인증서 검증

시나리오 3 — Phase 5 부분 재발급:

1. `rotate ca-key --skip reissue` 실행 → Phase 6 중단(미이전 서비스)
2. 서비스 1개(edge-proxy)만 강제 재발급
3. 기존 cert(web-app)과 신규 cert(edge-proxy) 모두 동작 확인
4. 나머지 서비스 강제 재발급
5. `--force`로 회전 재실행 → 완료

시나리오 4 — Phase 6 진입 차단:

1. `rotate ca-key --skip reissue` 실행 → Phase 6 차단
2. 오류 출력에 미이전 서비스 이름 포함 확인
3. `--force`로 재실행 → Phase 6 경고와 함께 완료
4. 강제 재발급 후 검증

시나리오 5 — 활성 회전 중 trust-sync 충돌:

1. step-ca 중지로 회전 중간에 중단 → 활성 회전 생성
2. `rotation-state.json` 존재 확인
3. `trust-sync` 실행 → 회전 진행 중 오류로 중단 기대
4. step-ca 복구 후 회전 완료
5. 전체 서비스 검증

실제 실행 명령(스크립트 발췌):

```bash
# AppRole 인증을 사용한 rotate ca-key 래퍼
bootroot rotate \
  --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://${STEPCA_HOST_IP}:8200" \
  --auth-mode approle \
  --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
  --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
  --yes \
  ca-key --skip reissue --force --cleanup

# Docker 조작을 통한 장애 주입
docker compose -f "$COMPOSE_FILE" stop openbao
docker compose -f "$COMPOSE_FILE" rm -sf step-ca
```

### 7) extended workflow 케이스

구성:

- 스크립트: `scripts/impl/run-extended-suite.sh`
- 케이스: `scale-contention`, `failure-recovery`, `runner-timer`, `runner-cron`,
  `ca-key-recovery`, `infra-lifecycle`
- 케이스 결과는 `extended-summary.json`에 집계
- 서비스 구성: 각 케이스가 사용하는 하위 시나리오/스크립트 구성을 그대로 상속하며,
  scale/contention, failure/recovery 케이스는 복수 서비스를 포함

목적:

- 무거운 stress/recovery 검증을 PR 필수 경로 밖에서 수행
- 회전 스케줄 동등성(`systemd-timer`, `cron`) 검증
- 더 긴 cycle/time window에서 반복 안정성 검증

실행 단계:

1. 케이스별로 독립 실행하고 케이스별 `run.log` 저장
2. `phases.log`에 케이스 단위 `start/pass/fail` 기록
3. 전체 결과를 `extended-summary.json`으로 집계
4. 케이스 하나라도 `fail`이면 워크플로 실패 처리

실제 실행 명령(스크립트 발췌):

```bash
# 확장 스위트 실행
./scripts/impl/run-extended-suite.sh

# 케이스별 내부 호출
./scripts/impl/run-baseline.sh
./scripts/impl/run-rotation-recovery.sh
RUNNER_MODE=systemd-timer ./scripts/impl/run-harness-smoke.sh
RUNNER_MODE=cron ./scripts/impl/run-harness-smoke.sh
./scripts/impl/run-ca-key-rotation-recovery.sh
./scripts/impl/run-local-lifecycle.sh
```

## 로컬 사전검증 표준

푸시 전 `scripts/preflight/` 스크립트를 실행합니다.

CI 워크플로 동등 스크립트(`scripts/preflight/ci/`):

| 스크립트 | CI 워크플로 대응 |
| --- | --- |
| `scripts/preflight/ci/check.sh` | `ci.yml` → Quality Check |
| `scripts/preflight/ci/test-core.sh` | `ci.yml` → test-core |
| `scripts/preflight/ci/e2e-matrix.sh` | `ci.yml` → test-docker-e2e-matrix |
| `scripts/preflight/ci/e2e-extended.sh` | `e2e-extended.yml` → run-extended |

로컬 전용 스크립트(`scripts/preflight/extra/`):

| 스크립트 | 설명 |
| --- | --- |
| `scripts/preflight/extra/agent-scenarios.sh` | 에이전트 시나리오 |
| `scripts/preflight/extra/cli-scenarios.sh` | CLI 시나리오 |

전체 실행:

```bash
scripts/preflight/run-all.sh
```

로컬에서 `sudo -n`이 불가능하면:

- `scripts/preflight/ci/e2e-matrix.sh --skip-hosts`을 실행합니다.
- 이유: `hosts` 케이스는 실행 중 호스트 머신의 `/etc/hosts`를
  추가/복원해야 하며, 이 작업은 비대화식 관리자 권한(`sudo -n`)이
  필요합니다.

이는 로컬 제약 우회용입니다. CI에서는 `hosts` 케이스도 실행됩니다.

## init 자동화 입출력 규칙

라이프사이클 스크립트는 `bootroot init --summary-json` 출력으로 자동화를
수행합니다. 사람용 요약 텍스트를 파싱해 토큰/시크릿을 추출하지 않습니다.
로컬 CLI 시나리오 실행도 같은 방식으로 `--summary-json`의 `.approles[]`에서
런타임 AppRole 자격증명을 사용합니다.
이 절차는 **테스트/자동화 편의용 규칙**이며, 운영 환경의 토큰 보관 정책을
대체하지 않습니다.

E2E가 사용하는 최소 머신 필드:

- `.approles[]` 항목 중:
  - `runtime_service_add` (`role_id`, `secret_id`)
  - `runtime_rotate` (`role_id`, `secret_id`)

E2E에서 OpenBao 언실/런타임 인증 사용 방식:

- E2E는 보통 `init` 단계에서 한 번 언실한 뒤 같은 실행 동안 재언실하지 않음
- 다시 언실이 필요한 경우는 OpenBao가 다시 `sealed` 상태가 되었을 때뿐임
  (예: 프로세스/컨테이너 재시작, 수동 seal, 복구 절차)
- 런타임 AppRole 자격증명은 `init-summary.json`의 `approles`에서 읽어
  `--auth-mode approle`로 `service add`/`rotate`에 전달
- 테스트 스크립트는 자격증명을 장기 저장하지 않고 실행 컨텍스트 변수로만 전달
- 요약 JSON 파일에는 root token/AppRole secret_id 등 민감 필드가 포함되므로
  아티팩트 보관 시 민감정보로 취급해야 함

운영 가이드:

- init summary JSON은 민감 아티팩트로 취급
- 로그에 원문 시크릿 출력 금지
- 시크릿 파일/디렉터리 권한 `0600`/`0700` 유지

## 원격 bootstrap 검증 기준

이 섹션의 목적은 "원격 bootstrap이 실제로 반영되었는지"를 E2E에서 어떤 기준으로
판정하는지 명확히 정의하는 것입니다.

검증 흐름:

1. control node의 `bootroot service add --delivery-mode remote-bootstrap`가
   목표 상태를 기록합니다.
2. remote node의 `bootroot-remote bootstrap`이 해당 상태를 읽어 로컬 파일/설정에
   반영합니다.
3. E2E는 bootstrap summary JSON 출력에서 모든 항목이 `applied`인지 확인합니다.

검증 항목(서비스별):

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

판정 규칙:

- 모든 bootstrap 항목이 summary 출력에서 `applied` 상태여야 함
- 회전 후 `bootroot-remote bootstrap` 재반영이 정상 완료되어야 함
- 하나라도 `failed`이면 해당 단계를 실패로 처리함

## E2E `phases.log` 형식

E2E 스크립트는 단계 진행 상태를 `phases.log` 파일로 남깁니다.
아래는 그 파일에 기록되는 이벤트 JSON 형식입니다.

라이프사이클 스크립트는 다음 형식으로 기록합니다.

```json
{"ts":"2026-02-17T04:49:01Z","phase":"infra-up","mode":"no-hosts"}
```

필드:

- `ts`: UTC 타임스탬프
- `phase`: 단계 식별자
- `mode`: 해석 모드(`no-hosts` 또는 `hosts`)

확장 스위트는 다음 형식으로 기록합니다.

```json
{"ts":"2026-02-17T04:49:01Z","phase":"runner-cron","status":"pass"}
```

필드:

- `ts`: UTC 타임스탬프
- `phase`: 케이스 식별자
- `status`: `start|pass|fail`

## 아티팩트 경로

일반 운영자 관점에서는 필수 정보가 아닙니다.  
CI 실패를 직접 디버깅하는 운영자/기여자 관점에서는 유용한 정보입니다.

PR 필수 아티팩트 예시:

- `tmp/e2e/ci-local-no-hosts-<run-id>`
- `tmp/e2e/ci-local-hosts-<run-id>`
- `tmp/e2e/ci-remote-no-hosts-<run-id>`
- `tmp/e2e/ci-remote-hosts-<run-id>`
- `tmp/e2e/ci-rotation-<run-id>`

확장 아티팩트 예시:

- `tmp/e2e/extended-<run-id>` (케이스별 하위 디렉터리 포함:
  `ca-key-recovery/`, `infra-lifecycle/` 등)

## 실패 점검 순서

실패 시 다음 순서로 확인하세요.

1. `phases.log` (어느 단계에서 멈췄는지)
2. `run.log` (상위 실행 흐름)
3. `init.raw.log` / `init.log` (init 단계 상세)
4. `compose-logs.log` 또는 케이스별 로그 (컨테이너 상세)
5. `extended-summary.json` (확장 스위트 케이스 상태)
