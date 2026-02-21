# 문제 해결

자주 발생하는 장애를 증상별로 정리합니다.
명령/옵션의 전체 정의는 [CLI](cli.md), 실제 실행 흐름은 [CLI 예제](cli-examples.md),
검증 시나리오는 [CI/E2E](e2e-ci.md)를 함께 참고하세요.

## 먼저 확인할 공통 사항

- 실행 바이너리가 맞는지 확인 (`bootroot`, `bootroot-agent`, `bootroot-remote`)
- `bootroot` 실행 시 `--help`로 현재 버전의 옵션을 확인
- OpenBao/step-ca/PostgreSQL/responder 컨테이너(또는 데몬)가 실제로 기동 중인지 확인
- 이름 매핑(`/etc/hosts` 또는 DNS)이 설치 토폴로지와 일치하는지 확인

## "error: unexpected argument"가 발생할 때

가장 흔한 원인은 **다른 바이너리의 옵션을 섞어 쓴 경우**입니다.

- `bootroot` 옵션과 `bootroot-agent` 옵션은 다릅니다.
- `bootroot-remote`도 별도 옵션 집합을 사용합니다.
- 각 바이너리에서 `--help` 출력으로 실제 지원 옵션을 먼저 확인하세요.

## `bootroot infra up`/`bootroot init` 단계가 실패할 때

### OpenBao 관련

- OpenBao가 `sealed` 상태인지 확인하고, 필요 시 unseal 후 재시도
- root token/AppRole 자격증명이 유효한지 확인
- KV v2 마운트(`secret` 기본값)가 실제로 존재하는지 확인
- 언실 키와 root token은 역할이 다릅니다.
  - 언실 키: `sealed` 해제
  - root token: 부트스트랩/비상 관리자 작업 권한

### 런타임 인증 누락/인증 실패(`service add`/`rotate`)

증상:

- 인증 입력 누락/불일치(`root token 누락`, `permission denied`,
  AppRole 로그인 실패 등)

확인:

- 현재 인증 경로를 확인:
  - root 경로: `--auth-mode root` + `--root-token`/`OPENBAO_ROOT_TOKEN`
  - AppRole 경로: `--auth-mode approle` + role_id/secret_id(직접 전달 또는 파일)
- AppRole이면 role_id/secret_id 짝이 맞는지, secret_id 만료/폐기 여부 확인
- `permission denied`면 필요한 OpenBao 경로 권한과 현재 정책 범위를 비교
- preview/trust 확인 흐름이면 OpenBao 조회에 필요한 런타임 인증이 전달됐는지 확인

조치:

- 보호된 입력 경로(환경 파일/런타임 시크릿 주입/AppRole 파일)에서
  유효한 런타임 인증을 다시 주입
- AppRole secret_id가 만료됐다면 재발급/회전 후 런타임 입력 갱신
- root token은 부트스트랩/비상 작업 용도로만 제한

### step-ca 초기화/CA 파일 관련

- `secrets/certs/root_ca.crt`
- `secrets/certs/intermediate_ca.crt`

위 파일이 없으면 `bootroot init`이 실패할 수 있습니다.

### PostgreSQL DSN 관련

`dial tcp 127.0.0.1:5432: connect: connection refused`가 보이면
`secrets/config/ca.json`의 `db.dataSource` 호스트가 런타임 기준으로 잘못된 경우가 많습니다.

- `localhost`/`127.0.0.1`/`::1` 입력은 init 과정에서 `postgres`로 정규화되는지 확인
- `db.internal` 같은 원격 호스트는 단일 호스트 가드레일에서 실패(설계된 동작)
- init summary의 DB 호스트 변환 라인(`from -> to`) 확인

### responder 체크 관련

- step-ca에서 responder의 `:80`에 접근 가능한지 확인
- responder 관리자 API(`:8080`) 경로가 올바른지 확인

## `bootroot service add` 결과가 기대와 다를 때

### preview 모드와 기본 실행 모드를 구분

- `--print-only`/`--dry-run`은 preview 모드입니다.
- preview 모드는 파일/상태를 실제로 쓰지 않습니다.
- trust 프리뷰까지 보려면 preview에서도 런타임 인증이 필요할 수 있습니다.

### 전달 모드(`--delivery-mode`)를 확인

- `local-file`: step-ca/OpenBao/responder가 동작하는 같은 머신에 서비스 추가
- `remote-bootstrap`: 서비스가 다른 머신에 추가되며 `bootroot-remote` 방식으로 반영

모드와 실제 배치가 맞지 않으면 설정 반영 경로가 어긋납니다.

## `remote-bootstrap`이 실패할 때

- 서비스 머신에서 `bootroot-remote bootstrap`이 성공적으로 완료되었는지 확인
- secret_id 회전 후에는 서비스 머신에서 `bootroot-remote apply-secret-id`를 실행
- bootstrap summary JSON에서 모든 항목이 `applied` 상태인지 확인

## 인증서 발급/갱신이 실패할 때

### HTTP-01 실패

- step-ca가 서비스 FQDN을 responder IP로 찾을 수 있어야 합니다.
- 서비스 머신(원격 추가 시)도 step-ca/responder 이름을 올바른 IP로 찾을 수 있어야 합니다.

### `Finalize failed: badCSR`

- 요청 SAN이 step-ca 프로비저너 정책과 맞지 않을 때 발생합니다.
- 서비스 SAN 생성 규칙과 CA 정책을 함께 점검하세요.

### ACME 디렉터리 재시도 반복

- `server` URL이 `https://`인지 확인 (`http://` 거부)
- 시스템 trust 또는 `trust.ca_bundle_path`가 올바른지 확인
- 임시 진단 용도로만 `bootroot-agent --insecure` 사용 (운영 비권장)

### 발급 직후 자동 강화 실패

- 증상: 발급은 성공했지만 직후 bootroot-agent가 non-zero로 종료됨
- 원인: `trust.verify_certificates = true` 자동 기록/재로드 검증 실패
- 확인: `--config` 경로, 파일 권한, `agent.toml` 문법

## 파일/훅 관련 오류

- `profiles.paths`의 상위 디렉터리 존재 여부와 쓰기 권한 확인
- 실행 사용자 권한 확인
- 훅 실패 시 `command` 경로/권한, `working_dir` 존재 여부 확인
- 로그의 출력 잘림(트렁케이션) 경고 메시지 확인

## 로컬 E2E 실행에서만 주로 발생하는 이슈

- `hosts-all` 모드는 호스트 `/etc/hosts` 수정이 필요해 `sudo -n` 권한이 필요합니다.
- 로컬에서 `sudo -n`이 불가능하면 `--skip-hosts-all` 경로를 사용하세요.
- 이는 로컬 제약 우회이며, CI는 `hosts-all`도 검증합니다.
