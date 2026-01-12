# CLI

이 문서는 bootroot CLI 사용 방법을 정리합니다.

## 개요

CLI는 infra 기동/초기화/상태 점검을 제공합니다.

- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot app add` (현재 미구현)
- `bootroot app info` (현재 미구현)
- `bootroot verify` (현재 미구현)

## 공통 옵션

- `--lang`: 출력 언어 (`en` 또는 `ko`, 기본값 `en`)
  - 환경 변수: `BOOTROOT_LANG`

## bootroot infra up

Docker Compose로 OpenBao/PostgreSQL/step-ca/HTTP-01 리스폰더를 기동하고
상태를 점검합니다.

### 입력

- `--compose-file`: compose 파일 경로 (기본값 `docker-compose.yml`)
- `--services`: 기동 대상 서비스 목록 (기본값 `openbao,postgres,step-ca,bootroot-http01`)
- `--image-archive-dir`: 로컬 이미지 아카이브 디렉터리(선택)
- `--restart-policy`: 컨테이너 재시작 정책 (기본값 `unless-stopped`)

### 출력

- 컨테이너 상태/헬스 요약
- 완료 메시지

### 실패

- docker compose/pull 실패
- 컨테이너 미기동 또는 헬스 체크 실패

### 예시

```bash
bootroot infra up
```

## bootroot init

OpenBao 초기화/언실/정책/AppRole 구성, step-ca 초기화, 시크릿 등록을 수행합니다.

### 입력

- `--openbao-url`: OpenBao API URL (기본값 `http://localhost:8200`)
- `--kv-mount`: OpenBao KV v2 마운트 경로 (기본값 `secret`)
- `--secrets-dir`: 시크릿 디렉터리 (기본값 `secrets`)
- `--compose-file`: infra 상태 점검용 compose 파일 (기본값 `docker-compose.yml`)
- `--auto-generate`: 비밀번호/HMAC 등을 자동 생성
- `--show-secrets`: 요약 출력에 시크릿 표시
- `--root-token`: OpenBao root token
  - 환경 변수: `OPENBAO_ROOT_TOKEN`
- `--unseal-key`: OpenBao unseal key (반복 가능)
  - 환경 변수: `OPENBAO_UNSEAL_KEYS` (쉼표 구분)
- `--stepca-password`: step-ca 키 암호 (`password.txt`)
  - 환경 변수: `STEPCA_PASSWORD`
- `--db-dsn`: step-ca용 PostgreSQL DSN
- `--http-hmac`: HTTP-01 responder HMAC
  - 환경 변수: `HTTP01_HMAC`
- `--responder-url`: HTTP-01 responder 관리자 URL (선택)
  - 환경 변수: `HTTP01_RESPONDER_URL`
- `--responder-timeout-secs`: responder 요청 타임아웃(초, 기본값 `5`)
- `--eab-auto`: step-ca에서 EAB 자동 발급
- `--stepca-url`: step-ca URL (기본값 `https://localhost:9000`)
- `--stepca-provisioner`: step-ca ACME provisioner 이름 (기본값 `acme`)
- `--eab-kid`, `--eab-hmac`: 수동 EAB 입력

### 출력

- OpenBao 초기화/언실 결과, AppRole 생성 결과 요약
- `password.txt`, `secrets/config/ca.json` 갱신 결과
- step-ca 초기화 여부, responder 체크 결과
- EAB 등록 여부
- 다음 단계 안내

### 실패

- infra 컨테이너가 비정상인 경우
- OpenBao 초기화/언실/인증 실패
- responder 체크 실패(옵션 사용 시)
- step-ca 초기화 실패

### 예시

```bash
bootroot init --auto-generate --eab-auto --responder-url http://localhost:8080
```

## bootroot status

infra 및 OpenBao 상태를 점검합니다.

### 입력

- `--compose-file`: compose 파일 경로
- `--openbao-url`: OpenBao URL
- `--kv-mount`: OpenBao KV v2 마운트 경로
- `--root-token`: KV/AppRole 체크용 토큰(선택)

### 출력

- 컨테이너 상태 요약
- OpenBao/ KV 상태 요약

### 실패

- 컨테이너 미기동/비정상
- OpenBao 응답 불가

### 예시

```bash
bootroot status
```

## bootroot app add

현재 미구현입니다.

## bootroot app info

현재 미구현입니다.

## bootroot verify

현재 미구현입니다.
