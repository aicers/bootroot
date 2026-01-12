# 문제 해결

CLI를 사용하는 경우 `docs/ko/cli.md`를 참고하세요. 이 문서는 **수동 운영**
환경에서의 문제 해결을 기준으로 설명합니다.

## "error: unexpected argument" 발생

현재 CLI는 다음 옵션만 지원합니다.

- `--config`
- `--email`
- `--ca-url`
- `--eab-kid` / `--eab-hmac` / `--eab-file`
- `--oneshot`

## OpenBao 연결/인증 실패

- OpenBao가 `sealed` 상태인지 확인
- root token 또는 AppRole 자격증명이 유효한지 확인
- KV v2 마운트 경로가 존재하는지 확인

## OpenBao KV v2 관련 오류

- KV v2가 enable 되어 있는지 확인(`secret` 기본 경로)
- 마운트 경로가 다른 경우 CLI 옵션/환경 변수로 지정했는지 확인

## HTTP-01 챌린지 실패

- step-ca에서 리스폰더의 80 포트에 접속 가능해야 함
- 리스폰더가 80 포트에 바인딩되어 있는지 확인
- 도메인이 리스폰더 호스트로 해석되는지 확인
- 에이전트가 리스폰더 관리자 API(포트 8080)에 접근 가능한지 확인

## "Finalize failed: badCSR"

CSR에 포함된 SAN이 CA 정책에 맞지 않을 때 발생합니다.
step-ca 프로비저너 정책과 요청 DNS SAN을 확인하세요.

## 인증서 파일이 생성되지 않음

- `profiles.paths` 경로 권한 확인
- 상위 디렉터리 존재 여부 확인
- 실행 사용자 쓰기 권한 확인

## ACME 디렉터리 재시도 반복

- step-ca 기동 여부 확인
- TLS 신뢰 설정 확인
- `server` URL 확인

## 훅 실행 오류

- `command` 경로 및 권한 확인
- `working_dir` 존재 여부 확인
- 로그에서 출력 잘림 메시지 확인
