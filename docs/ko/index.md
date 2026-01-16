# Bootroot 매뉴얼

이 매뉴얼은 **bootroot**(bootroot CLI, bootroot-agent, HTTP-01 리스폰더)와
**step-ca**, **OpenBao**를 설치, 구성, 운영하는 전체 과정을 설명합니다.
PKI 배경 지식이 없는 사용자도 이 문서만으로 설치와 인증서 발급을
완료할 수 있도록 구성했습니다. bootroot CLI 실행 파일은 `bootroot`,
bootroot-agent 실행 파일은 `bootroot-agent`입니다.

## CLI

CLI 사용법은 [CLI 문서](cli.md)에 정리되어 있습니다.
이 매뉴얼의 나머지 섹션은 **CLI를 쓰지 않는 수동 절차**를 기준으로
설명합니다.

## Bootroot가 하는 일

Bootroot는 제품 내장형 PKI 부트스트랩 계층입니다. 부트스트랩은 시스템이 처음부터
동작할 수 있도록 **초기 환경을 준비하고 구동을 시작하는 과정**을 의미합니다.
CA는 **Certificate Authority**의 약어로, 인증서를 서명해 신원을 보증하는
기관(또는 서비스)을 뜻합니다. ACME(Automated Certificate Management
Environment)는 RFC 8555에서 정의된 표준 프로토콜입니다. 구성 요소는
다음과 같습니다.

- **step-ca**: ACME 호환 사설 CA (오픈 소스)
- **PostgreSQL**: step-ca가 사용하는 DB 서버 (오픈 소스)
- **OpenBao**: bootroot 시크릿을 관리/주입하는 시크릿 매니저 (오픈 소스)
- **bootroot-agent**: 이 프로젝트에서 직접 개발한 Rust ACME 클라이언트
- **HTTP-01 리스폰더**: 이 프로젝트에서 직접 개발한 HTTP-01 전용 데몬

## 매뉴얼 구성

- **CLI**: infra 기동/초기화/상태 점검, 앱 온보딩, 발급 검증/회전
- **개념**: PKI, ACME, CSR, SAN, mTLS, 시크릿 관리(OpenBao) 개요
- **빠른 시작**: Docker Compose 기반 첫 발급
- **설치**: OpenBao + step-ca + PostgreSQL + bootroot-agent + 리스폰더 설치
- **설정**: `agent.toml`, 프로필, 훅, 재시도, EAB
- **운영**: 갱신, 로그, 백업, 보안(OpenBao 포함)
- **문제 해결 / FAQ**: 자주 발생하는 오류와 답변

## 아키텍처(요약)

1. bootroot-agent가 step-ca의 ACME 디렉터리를 읽음
2. ACME 계정을 등록(EAB 선택)
3. 인증서 발급 주문 생성
4. HTTP-01 토큰을 리스폰더에 등록
5. 리스폰더가 포트 80에서 HTTP-01 응답
6. 인증서 발급 및 파일 저장
7. 훅 실행 및 주기적 갱신(데몬 모드)
8. OpenBao가 렌더링한 파일로 시크릿을 주입

## 주요 파일

- `agent.toml.example`: 전체 설정 템플릿
- `agent.toml.compose`: Docker Compose용 설정
- `secrets/config/ca.json`: step-ca 설정(개발용)
- `openbao-agent/*.hcl`: OpenBao Agent 템플릿(시크릿 파일 렌더링)
- `scripts/update-ca-db-dsn.sh`: DB DSN 갱신 스크립트
- `docs/en/*`, `docs/ko/*`: 매뉴얼 소스

## 안전 수칙

- 운영 시크릿은 git에 커밋하지 마세요.
- 개인키는 `0600`, 시크릿 디렉터리는 `0700` 권한을 권장합니다.
- OpenBao 토큰/unseal 키는 별도 안전 저장소에 보관하세요.
- CA와 DB 간 네트워크 접근을 제한하세요.
