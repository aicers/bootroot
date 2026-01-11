# Bootroot CLI 설계 초안

## 목적

`bootroot` CLI 구현을 위한 상세 설계를 정리한다. 이 문서는 스펙을
구현 가능한 작업 단위로 쪼개는 용도이며, 실제 코드 작성 전에 합의된
입출력과 흐름을 고정한다.

## 범위

- 커맨드별 입력/출력 흐름
- OpenBao API 호출 순서
- 상태 저장 구조
- i18n 메시지 키 구조
- 검증 및 오류 처리 기준

## 커맨드 설계

### `bootroot infra up`

- 입력
  - 로컬 이미지 아카이브 디렉터리 (선택)
  - OpenBao/PostgreSQL/step-ca/responder 이미지 태그 (기본값 제공)
- 처리
  - 로컬 이미지가 있으면 `docker load` 우선
  - 없으면 `docker pull`
  - 컨테이너 기동 및 재시작 정책 설정
- 출력
  - 컨테이너 상태 요약
  - 다음 단계 안내: `bootroot init`

### `bootroot init`

- 사전 조건
  - infra 컨테이너가 기동 중이어야 함
- 입력(프롬프트)
  - OpenBao URL
  - KV 마운트 경로(기본 `secret`)
  - 시크릿 입력 방식: 직접 입력 vs CLI 자동 생성
- 처리
  - OpenBao 초기화/언실
  - KV v2 활성화
  - 정책 및 AppRole 생성
  - 시크릿 등록
  - step-ca 초기화
  - EAB 발급 및 등록
- 출력
  - 생성물 경로 요약
  - AppRole 전달 정보
  - 검증/다음 단계 안내

### `bootroot status`

- 입력 없음
- 처리
  - 컨테이너 상태 확인
  - OpenBao 헬스 체크
- 출력
  - OK/FAIL 요약 및 원인

### `bootroot app add`

- 입력
  - 앱 타입: daemon / nextjs
  - 앱 식별자, 도메인, cert/key 경로
- 처리
  - daemon: `profiles[]` 갱신
  - nextjs: AppRole 생성 및 사이드카 템플릿 출력
- 출력
  - 적용 결과 + 검증 옵션

### `bootroot app info`

- 입력
  - 앱 식별자
- 처리
  - 저장된 상태/경로/정책 확인
- 출력
  - 앱별 설정/경로 요약

### `bootroot verify`

- 입력
  - 앱 식별자 또는 프로필
- 처리
  - one-shot 발급 + 파일 존재 확인
- 출력
  - PASS/FAIL

## OpenBao API 호출 순서 (init 기준)

1) `sys/init` (필요 시)
2) `sys/unseal` (필요 시)
3) `sys/mounts/<mount>` (KV v2 활성화)
4) `sys/auth/approle` (AppRole 활성화)
5) `sys/policies/acl/<name>` (정책 생성)
6) `auth/approle/role/<name>` (AppRole 생성)
7) `auth/approle/role/<name>/role-id` (role_id 조회)
8) `auth/approle/role/<name>/secret-id` (secret_id 발급)
9) `<mount>/data/<path>` (시크릿 등록)

## 상태 저장 구조 (state.json)

- openbao_url
- kv_mount
- policies
- approles
- apps

예시:

```json
{
  "openbao_url": "http://localhost:8200",
  "kv_mount": "secret",
  "policies": {
    "bootroot_agent": "bootroot-agent",
    "responder": "bootroot-responder",
    "stepca": "bootroot-stepca"
  },
  "approles": {
    "bootroot_agent": "bootroot-agent-role",
    "responder": "bootroot-responder-role",
    "stepca": "bootroot-stepca-role"
  },
  "apps": {
    "daemon-001": {
      "type": "daemon",
      "cert_path": "certs/daemon-001.crt",
      "key_path": "certs/daemon-001.key"
    }
  }
}
```

## i18n 키 구조

- `prompt.*`
- `info.*`
- `error.*`
- `confirm.*`

예: `prompt.openbao_url`, `error.unseal_failed`

## 오류 처리 기준

- 실패 시 원인/다음 단계 안내 포함
- OpenBao 미접속 시 즉시 중단
- 파괴적 작업은 2회 확인

## 검증 기준

- bootroot-agent 로그에 성공 메시지 존재
- cert/key 파일 존재 및 권한 확인
