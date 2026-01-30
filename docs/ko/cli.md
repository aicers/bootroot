# CLI

이 문서는 bootroot CLI 사용 방법을 정리합니다.

## 개요

CLI는 infra 기동/초기화/상태 점검과 앱 온보딩, 발급 검증,
시크릿 회전을 제공합니다.
또한 Prometheus/Grafana 기반 로컬 모니터링을 관리합니다.

- `bootroot infra up`
- `bootroot init`
- `bootroot status`
- `bootroot app add`
- `bootroot app info`
- `bootroot verify`
- `bootroot rotate`
- `bootroot monitoring`

## 공통 옵션

- `--lang`: 출력 언어 (`en` 또는 `ko`, 기본값 `en`)
  - 환경 변수: `BOOTROOT_LANG`

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
- `--restart-policy`: 컨테이너 재시작 정책 (기본값 `unless-stopped`)
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
- EAB 등록 여부
- step-ca/responder용 OpenBao Agent compose override 자동 적용
- 다음 단계 안내

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

## bootroot app add

새로운 앱(daemon/docker)이 step-ca에서 인증서를 발급받을 수 있도록
온보딩 정보를 등록하고 OpenBao AppRole을 생성합니다. 이 명령을 실행하면
**bootroot CLI**가 아래 작업을 수행합니다.

- 앱 메타데이터(서비스 이름, 배포 타입, hostname, domain 등) 저장
- AppRole/정책 생성 및 `role_id`/`secret_id` 발급
- 앱별 시크릿 경로 및 필요한 파일 경로 정리
- bootroot-agent/OpenBao Agent 실행에 필요한 안내 스니펫 출력

이 명령은 새 앱을 추가할 때 **인증서 발급 경로를 준비**하기 위한
필수 단계입니다. 이후 사용자는 안내된 내용대로 bootroot-agent와
OpenBao Agent를 구동하고, 앱을 실행해 **앱 간 통신에서 발급된
mTLS 인증서가 올바르게 사용되도록 구성**해야 합니다.

추가로, `bootroot app add`만으로는 인증서가 자동 발급되지 않습니다.
step-ca로부터 실제 인증서를 받으려면 **bootroot-agent 설정/실행**이
필수입니다. 자세한 bootroot-agent 설정은 매뉴얼의 해당 섹션을
참고하세요(설치/운영/설정 문서의 bootroot-agent 항목).

`bootroot init`이 OpenBao에 CA 지문을 저장해 둔 경우(예: `secret/bootroot/ca`),
이 명령은 `trusted_ca_sha256` 값을 **agent.toml 스니펫에 포함**해 출력합니다.
해당 값이 없다면 스니펫에는 포함되지 않으므로, 필요 시 수동으로 설정하세요.

앱이 다른 머신에서 실행된다면, 해당 머신에서 bootroot-agent가 같은
`agent.toml`을 사용하도록 설정해야 합니다. `--cert-path`/`--key-path`
도 앱이 실행되는 머신 기준으로 맞춰야 합니다. 이 명령은 경로/스니펫을
안내할 뿐이며, 실제 설정 파일과 실행은 앱이 동작하는 머신에서
진행해야 합니다.

### 입력

입력 우선순위는 **CLI 옵션 > 환경 변수 > 프롬프트/기본값**입니다.

- `--service-name`: 서비스 이름 식별자
- `--deploy-type`: 배포 타입 (`daemon` 또는 `docker`)
- `--hostname`: DNS SAN에 사용할 호스트명
- `--domain`: DNS SAN 루트 도메인
- `--agent-config`: bootroot-agent 설정 파일 경로
- `--cert-path`: 인증서 출력 경로
- `--key-path`: 개인키 출력 경로
- `--instance-id`: 앱 instance_id
- `--container-name`: 도커 앱 컨테이너 이름 (docker 필수)
- `--root-token`: OpenBao root token (환경 변수: `OPENBAO_ROOT_TOKEN`)
- `--notes`: 메모(선택)

### 대화형 동작

- 누락된 필수 입력을 프롬프트로 받습니다(배포 타입 기본값: `daemon`).
- 입력값은 빈 값 여부, 허용된 enum 값인지, 경로/상위 디렉터리가
  유효한지 확인합니다.
- 실행 전 계획 요약, 실행 후 최종 요약을 출력합니다.

### 출력

- 앱 메타데이터 요약
- AppRole/정책/secret_id 경로 요약
- 앱별 OpenBao Agent 안내(daemon/docker 분리)
- 타입별 온보딩 안내 (daemon 프로필 / docker sidecar)
- daemon/docker 스니펫(복붙용) 출력

### 실패 조건

다음 조건이면 실패로 판정합니다.

- `state.json` 누락
- 중복된 `service-name`
- `instance-id` 누락
- docker에 `container-name` 누락
- OpenBao AppRole 생성 실패

## bootroot app info

등록된 앱 정보를 조회합니다.

### 입력

- `--service-name`: 서비스 이름 식별자

### 출력

- 앱 타입/경로/AppRole/시크릿 경로 요약
- 앱별 OpenBao Agent 안내(daemon/docker 분리)

### 실패 조건

다음 조건이면 실패로 판정합니다.

- `state.json` 누락
- 등록되지 않은 앱

## bootroot verify

bootroot-agent를 one-shot으로 실행해 발급을 검증합니다. 앱 온보딩 직후
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
