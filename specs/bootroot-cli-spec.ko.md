# Bootroot CLI 스펙 (이슈 #57)

## 목적

단일 머신에서 OpenBao + step-ca(PostgreSQL) + HTTP-01 responder를 완전
부트스트랩하고, 신규 앱(데몬/Next.js)을 온보딩 및 검증하는 대화형
`bootroot` CLI를 정의한다. 이 문서는 구현용이며 i18n(영/한)을 전제로
한다.

## 제외 범위

- 멀티 호스트 오케스트레이션
- Kubernetes 지원
- HSM/PKCS11 통합
- 발급/갱신 검증을 넘는 전체 PKI 라이프사이클

## 가정

- OpenBao, PostgreSQL, step-ca, HTTP-01 responder는 동일 머신의 Docker
  이미지로 실행된다.
- CLI는 컨테이너 기동과 재시작 정책 설정을 담당하되, 로컬 이미지가
  있으면 pull을 생략할 수 있다.
- CLI는 OpenBao HTTP API(Vault 호환)를 직접 호출한다.
- CLI는 필요 시 로컬 docker/compose 명령을 실행할 수 있다.
- 시크릿은 OpenBao Agent가 파일로 렌더링하며 앱은 파일을 읽는다.

## CLI UX 요구사항

- 서브커맨드 기반 + 대화형 프롬프트.
- (선택) REPL 모드는 추후 추가 가능.
- 파괴적 작업(재초기화/덮어쓰기/삭제)은 명시적 확인 필요.
- 수행 내용/생성물/다음 단계 요약 제공.
- i18n: 초기 릴리스에 영어/한국어 제공, 문자열 키 외부화.

## 커맨드

- `bootroot infra up`:
  - OpenBao/PostgreSQL/step-ca/responder 이미지 로드/풀 및 기동.
- `bootroot init`:
  - 인프라 기동 이후 설정/부트스트랩 수행.
- `bootroot status`:
  - 준비 상태 점검.
- `bootroot app add`:
  - 신규 앱 온보딩(데몬/Next.js).
- `bootroot app info`:
  - 앱별 설정/가이드 조회.
- `bootroot verify`:
  - 발급 테스트 및 산출물 확인.

## 상태/설정 저장

- 기본 상태 디렉터리: `./state/bootroot` (설정 가능).
- 파일:
  - `state.json`: CLI 상태(OpenBao URL, 마운트, AppRole 이름, 앱 목록 등)
  - `templates/`: 템플릿 렌더 결과(감사/디버그 용)
- `root_token`, `unseal_keys`는 명시적 동의 없이 저장 금지.

## OpenBao API 호출(표준)

- 초기화: `POST /v1/sys/init`
- 언실: `POST /v1/sys/unseal`
- 헬스체크: `GET /v1/sys/health`
- KV v2 활성화: `POST /v1/sys/mounts/<mount>`
- AppRole auth 활성화: `POST /v1/sys/auth/approle`
- 정책 생성: `PUT /v1/sys/policies/acl/<name>`
- AppRole 생성: `POST /v1/auth/approle/role/<name>`
- role_id 조회: `GET /v1/auth/approle/role/<name>/role-id`
- secret_id 발급: `POST /v1/auth/approle/role/<name>/secret-id`
- 시크릿 저장(KV v2): `POST /v1/<mount>/data/<path>`

## OpenBao KV v2 설명

KV v2는 권장되는 키-값 시크릿 엔진으로, 시크릿 버전 관리와 메타데이터,
소프트 삭제(복구 가능) 기능을 제공해 회전/복구에 유리하다.

## 부트스트랩 플로우: `bootroot init`

### 0단계: 언어

- 언어 선택(EN/KR) 또는 `--lang`.

### 1단계: 인프라 준비 상태 확인

- OpenBao/PostgreSQL/step-ca/responder 컨테이너가 기동 중인지 확인.
- 미기동 시 `bootroot infra up` 실행을 안내하고 중단.

### 2단계: OpenBao

- OpenBao URL, 토큰 소스(root token), KV 마운트 경로(기본 `secret`) 입력.
- 미초기화 상태라면:
  - `sys/init` 실행 → unseal 키 + root token 확보.
  - 사용자에게 안전 보관 확인.
  - unseal 진행.
- KV v2, AppRole auth 활성화 확인.

### 3단계: 정책 + AppRole

- 다음 정책 생성:
  - bootroot-agent용 OpenBao Agent(필요 시크릿 경로 read)
  - responder용 OpenBao Agent(HMAC 경로만 read)
  - step-ca용 OpenBao Agent(password/DB 경로만 read)
- AppRole 생성 후 `role_id`/`secret_id` 출력.
- 수동 전달 필요 안내.
- 정책 내용은 기본 템플릿으로 자동 생성하며 이 단계에서 추가 입력은
  받지 않는다.

### 4단계: 시크릿 등록

- 입력:
  - step-ca 키 암호
  - DB 비밀번호 또는 DSN 구성값
  - HTTP-01 HMAC
- 각 항목은 직접 입력하거나 CLI가 안전하게 임의 생성하도록 선택할 수
  있다.
- 한 번 등록되면 이후에는 OpenBao/Agent가 주입·회전하므로 사용자가
  다시 알 필요는 없다.
- OpenBao 저장 경로:
  - `secret/bootroot/stepca/password`
  - `secret/bootroot/stepca/db`
  - `secret/bootroot/responder/hmac`
- EAB는 step-ca 초기화 이후 등록.

### 입력 우선순위 매트릭스

- OpenBao URL: `--openbao-url` → 기본값(`http://localhost:8200`)
- KV 마운트: `--kv-mount` → 기본값(`secret`)
- secrets dir: `--secrets-dir` → 기본값(`secrets`)
- compose file: `--compose-file` → 기본값(`docker-compose.yml`)
- root token: `--root-token` → `OPENBAO_ROOT_TOKEN` → 프롬프트(이미
  초기화된 경우)
- unseal key: `--unseal-key`(반복) → `OPENBAO_UNSEAL_KEYS`(쉼표 구분) → init 시
  자동 생성된 키
- step-ca 키 암호: `--stepca-password` → `STEPCA_PASSWORD` → `--auto-generate` → 프롬프트
- DB DSN: `--db-dsn` → `POSTGRES_*` 조합 → 프롬프트
  - `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` (필수)
  - `POSTGRES_HOST`(기본 `postgres`), `POSTGRES_PORT`(기본 `5432`)
- HTTP-01 HMAC: `--http-hmac` → `HTTP01_HMAC` → `--auto-generate` → 프롬프트
- EAB: `--eab-kid` + `--eab-hmac` 둘 다 필요(선택)
  - `EAB_KID`, `EAB_HMAC`

### 5단계: step-ca용 OpenBao Agent(선행)

- `password.txt`, `ca.json` 템플릿 렌더.
- 파일 권한(0600/0700) 검증.

### 6단계: step-ca 초기화

- 렌더된 `password.txt`로 `step ca init` 실행(Docker).
- `secrets/config/ca.json` 및 DSN 일치 확인.

### 7단계: EAB 발급 및 등록

- step-ca에서 EAB 발급.
- `secret/bootroot/stepca/eab`에 등록.

### 8단계: responder + bootroot-agent용 OpenBao Agent

- responder HMAC 템플릿 렌더.
- bootroot-agent 설정(EAB/HMAC) 렌더.

### 9단계: 요약

- 생성물/서비스 상태/다음 단계 출력.

## 앱 온보딩: `bootroot app add`

### 바이너리 데몬(호스트 기반)

- 데몬 이름, instance_id, hostname, domain, cert/key 경로 입력.
- bootroot-agent `profiles[]`에 추가(데몬별 cert, 공유 없음).
- bootroot-agent 리로드 안내.

### Next.js Docker 앱(사이드카)

- 앱 이름, 컨테이너 이름, domain, cert/key 마운트 경로 입력.
- 앱 전용 AppRole 생성(최소 권한).
- 사이드카(bootroot-agent + OpenBao Agent) 스니펫 출력.

### 검증

- `bootroot verify --app <name>` 즉시 실행 옵션.

## 조회: `bootroot app info`

- 앱 타입/경로/정책/AppRole/시크릿 경로/산출물 경로 출력.

## 검증: `bootroot verify`

- 대상 앱/프로필에 대해 one-shot 발급 후 확인:
  - 로그 성공 여부
  - cert/key 파일 존재
- 결과 요약 출력.

## i18n

- 문자열은 `i18n/en.json`, `i18n/ko.json` 등에 저장.
- 키 예: `prompt.openbao_url`, `error.unseal_failed`.
- 기본 언어는 영어, `--lang`으로 변경 가능.

## 에러 처리

- 조치 가능한 오류 메시지 제공.
- OpenBao/step-ca 미접속 시 즉시 실패.

## 보안 주의

- 시크릿 로깅 금지.
- root token/unseal 키는 명시적 동의 없이는 저장 금지.
- 키 파일 0600, 시크릿 디렉터리 0700 유지.
