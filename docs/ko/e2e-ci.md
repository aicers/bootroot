# CI/E2E

이 문서는 bootroot의 CI 검증 구조와 로컬 재현 방법을 정리합니다.

## 파이프라인 모델

PR 필수 CI(`.github/workflows/ci.yml`)는 다음을 실행합니다.

- `test-core`: 단위/통합 스모크 경로
- `test-docker-e2e-matrix`: 라이프사이클 + 회전/복구 Docker E2E 매트릭스

확장 E2E(`.github/workflows/e2e-extended.yml`)는 별도 실행됩니다.

- `workflow_dispatch` 수동 실행
- `23:30 KST` 스케줄(UTC cron) + 당일 `main` 커밋 활동(KST) 게이팅

확장 워크플로는 복원력/경합 같은 무거운 검증을 위해 PR 필수 경로와
분리되어 있습니다.

## Docker E2E 커버리지

PR 필수 Docker 매트릭스는 다음을 검증합니다.

- main lifecycle (`fqdn-only-hosts`)
- main lifecycle (`hosts-all`)
- main remote lifecycle (`fqdn-only-hosts`)
- main remote lifecycle (`hosts-all`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac,trust_sync`)

주요 스크립트:

- `scripts/e2e/docker/run-main-lifecycle.sh`
- `scripts/e2e/docker/run-main-remote-lifecycle.sh`
- `scripts/e2e/docker/run-rotation-recovery.sh`

확장 워크플로는 다음을 검증합니다.

- baseline 경합/스케일 동작
- 반복 장애/복구 동작
- runner 모드 동등성(`systemd-timer`, `cron`)

주요 스크립트:

- `scripts/e2e/docker/run-extended-suite.sh`

## 로컬 사전검증 표준

푸시 전 최소 다음을 모두 실행하세요.

1. `cargo test`
2. `./scripts/ci-local-e2e.sh`
3. `./scripts/e2e/docker/run-extended-suite.sh`

로컬에서 `sudo -n`이 불가능하면 다음을 사용합니다.

- `./scripts/ci-local-e2e.sh --skip-hosts-all`

이는 로컬 제약 우회용입니다. CI에서는 `hosts-all` 케이스도 실행됩니다.

## init 자동화 계약

라이프사이클 스크립트는 `bootroot init --summary-json` 출력으로 자동화를
수행합니다. 사람용 요약 텍스트를 파싱해 토큰/시크릿을 추출하지 않습니다.

E2E가 사용하는 최소 머신 필드:

- `root_token`

운영 가이드:

- init summary JSON은 민감 아티팩트로 취급
- 로그에 원문 시크릿 출력 금지
- 시크릿 파일/디렉터리 권한 `0600`/`0700` 유지

## bootroot-remote 동기화 계약

원격 수렴은 다음 흐름으로 검증합니다.

- `bootroot-remote pull`
- `bootroot-remote ack`
- `bootroot-remote sync`

sync summary JSON과 `bootroot service sync-status`는 아래 항목 기준으로
일치해야 합니다.

- `secret_id`
- `eab`
- `responder_hmac`
- `trust_sync`

상태 라이프사이클 값:

- `none`
- `pending`
- `applied`
- `failed`
- `expired`

## phase 로그 스키마

main lifecycle 스크립트는 다음 형식의 phase 이벤트를 기록합니다.

```json
{"ts":"2026-02-17T04:49:01Z","phase":"infra-up","mode":"fqdn-only-hosts"}
```

필드:

- `ts`: UTC 타임스탬프
- `phase`: 단계 식별자
- `mode`: 해석 모드(`fqdn-only-hosts` 또는 `hosts-all`)

확장 스위트는 다음 형식의 phase 이벤트를 기록합니다.

```json
{"ts":"2026-02-17T04:49:01Z","phase":"runner-cron","status":"pass"}
```

필드:

- `ts`: UTC 타임스탬프
- `phase`: 케이스 식별자
- `status`: `start|pass|fail`

## 아티팩트 경로

PR 필수 아티팩트 예시:

- `tmp/e2e/ci-main-fqdn-<run-id>`
- `tmp/e2e/ci-main-hosts-<run-id>`
- `tmp/e2e/ci-main-remote-fqdn-<run-id>`
- `tmp/e2e/ci-main-remote-hosts-<run-id>`
- `tmp/e2e/ci-rotation-<run-id>`

확장 아티팩트 예시:

- `tmp/e2e/extended-<run-id>`

## 트리아지 순서

실패 시 다음 순서로 확인하세요.

1. `phases.log` (어느 단계에서 멈췄는지)
2. `run.log` (상위 실행 흐름)
3. `init.raw.log` / `init.log` (init 단계 상세)
4. `compose-logs.log` 또는 케이스별 로그 (컨테이너 상세)
5. `extended-summary.json` (확장 스위트 케이스 상태)

## 로컬 재현 명령

로컬 PR 필수 매트릭스:

```bash
./scripts/ci-local-e2e.sh
```

로컬 확장 스위트:

```bash
./scripts/e2e/docker/run-extended-suite.sh
```

E2E 전에 수행할 품질 게이트:

```bash
cargo fmt -- --check --config group_imports=StdExternalCrate
cargo clippy --all-targets -- -D warnings
biome ci --error-on-warnings .
cargo audit
markdownlint-cli2 "**/*.md" "#node_modules" "#target"
```
