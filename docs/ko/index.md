# Bootroot 매뉴얼

이 매뉴얼은 **bootroot**(bootroot CLI, bootroot-agent, bootroot-remote,
HTTP-01 리스폰더)와 **step-ca**, **OpenBao**, **Prometheus**, **Grafana**를
설치, 구성, 운영하는 전체 과정을 설명합니다. PKI 배경 지식이 없는 사용자도
이 문서만으로 설치와 인증서 발급을 완료할 수 있도록 구성했습니다.
bootroot CLI 실행 파일은 `bootroot`, bootroot-agent 실행 파일은
`bootroot-agent`, 원격 서비스 설정 CLI 실행 파일은 `bootroot-agent`입니다.

## Bootroot가 하는 일

Bootroot는 제품 내장형 PKI 부트스트랩 계층입니다. 부트스트랩은 시스템이 처음부터
동작할 수 있도록 **초기 환경을 준비하고 구동을 시작하는 과정**을 의미합니다.
여기서 Bootroot가 말하는 서비스는 서비스 간 mTLS 통신을 위해 인증서가 필요한
사용자 애플리케이션(daemon/docker 배포 대상)을 뜻합니다. Bootroot의 역할은
이 서비스들이 **mTLS 통신을 수행할 수 있도록 인증서를 자동 발급/갱신/회전**하는
것입니다. 또한 Prometheus/Grafana로
메트릭을 수집/시각화해 운영 가시성을 확보합니다. 구성 요소는 다음과 같습니다.

- **step-ca**: ACME 호환 사설 CA (오픈 소스)
- **PostgreSQL**: step-ca가 사용하는 DB 서버 (오픈 소스)
- **OpenBao**: bootroot 시크릿을 관리/주입하는 시크릿 매니저 (오픈 소스)
- **OpenBao Agent**: OpenBao 시크릿을 파일로 렌더링하는 에이전트 (오픈 소스)
- **bootroot CLI**: 이 프로젝트에서 직접 개발한 전체 설치/초기화/운영 자동화 CLI 도구
- **bootroot-agent**: 이 프로젝트에서 직접 개발한 Rust ACME 클라이언트 데몬
- **bootroot-remote**: 이 프로젝트에서 직접 개발한 원격 서비스의 설정을
  위한 동기화 CLI 도구
- **HTTP-01 리스폰더**: 이 프로젝트에서 직접 개발한 HTTP-01 전용 데몬
- **Prometheus**: 메트릭 수집기 (오픈 소스)
- **Grafana**: 메트릭 시각화 대시보드 (오픈 소스)

CA는 **Certificate Authority**의 약어로, 인증서를 서명해 신원을 보증하는
기관(또는 서비스)을 뜻합니다. ACME(Automated Certificate Management
Environment)는 RFC 8555에서 정의된 표준 프로토콜입니다.

## 매뉴얼 구성

- **CLI**: infra 기동/초기화/상태 점검뿐 아니라 서비스 온보딩, 발급 검증,
  시크릿 회전, 모니터링, 원격 동기화 운영 안내까지 포함
- **개념**: PKI, ACME, CSR, SAN, mTLS, 시크릿 관리(OpenBao) 개요
- **빠른 시작**: Docker Compose 기반 첫 발급
- **설치**: OpenBao + step-ca + PostgreSQL + bootroot-agent + 리스폰더 설치
- **설정**: `agent.toml`, 프로필, 훅, 재시도, EAB
- **운영**: 갱신, 로그, 백업, 보안(OpenBao 포함)
- **CI/E2E**: PR 필수 매트릭스, 확장 워크플로, 아티팩트, 로컬 재현
- **문제 해결 / FAQ**: 자주 발생하는 오류와 답변

CLI 사용법은 [CLI 문서](cli.md)와 [CLI 예제](cli-examples.md)에 정리되어 있습니다. CLI 문서에서는
`infra up/init/status`, `service add/verify`, `rotate`, `monitoring`과
`bootroot-remote pull/ack/sync` 등 주요 명령을 다룹니다.
이 매뉴얼의 나머지 섹션은 **CLI를 쓰지 않는 수동 절차**를 기준으로
설명합니다.

## 설치 토폴로지(요약)

`bootroot` CLI는 `step-ca (with PostgreSQL)`, `OpenBao`, `HTTP-01 responder`
가 **한 머신에 함께 설치되는 토폴로지**를 전제로 동작합니다. 이 전제는
보안성(경계 단순화), 편리성(구성 자동화), 운용성(장애 분석/운영 절차 단순화)
측면에서 가장 유리하고 자연스러운 기본 경로이기 때문입니다.
`Prometheus`와 `Grafana`도 `OpenBao`/`step-ca`를 모니터링하기 위해
일반적으로 같은 머신에 함께 배치합니다.

이 전제를 따르면 `step-ca`/`responder` 전용 OpenBao Agent도 같은 머신에서
각각 전용 인스턴스로 동작해야 합니다.

`step-ca`/`PostgreSQL`/`OpenBao`/`HTTP-01 responder`를 한 머신에 함께 두는
기본 전제를 벗어난 분산 배치도 이론적으로는 가능합니다. 다만 이 경우에는
`bootroot` CLI 자동화 대신 수동 설치/설정 절차가 필요합니다. 예를 들어
`step-ca+PostgreSQL`은 CA 머신에, `OpenBao`는 별도 시크릿 머신에,
`HTTP-01 responder`는 서비스 엣지 머신에 두는 구성입니다. 또한 현재
`bootroot` 구성에서 이러한 토폴로지를 충분히 지원한다고 단정할 수는
없습니다.

`bootroot service add`로 등록한 서비스는 step-ca가 설치된 머신에서
동작할 수도 있고, 다른 머신에서 동작할 수도 있습니다. 어떤 배치이든
서비스 런타임에는 OpenBao Agent와 bootroot-agent를 함께 구성해야 합니다.

OpenBao Agent 배치 규칙:

- Docker 서비스: 서비스별 **OpenBao Agent 사이드카**를 **필수**로 사용
- 데몬 서비스: 서비스별 **OpenBao Agent 데몬**을 **필수**로 사용

bootroot-agent 배치 규칙:

- Docker 서비스: 서비스별 **bootroot-agent 사이드카**를 권장
- 데몬 서비스: 호스트당 **bootroot-agent 통합 데몬** 1개를 권장

참고: Docker 서비스도 통합 데몬 사용은 가능하지만, 격리/라이프사이클
정합성과 장애 영향 범위 측면에서 비권장입니다.

bootroot-remote 배치 규칙:

- 서비스별로 개별 인스턴스가 주기적으로 실행되도록 해야 합니다.
- 여러 서비스가 동시에 sync할 때에는 서비스별 `--summary-json` 경로를
  분리해 파일 충돌을 피해야 합니다.

참고:
step-ca가 설치된 머신에 서비스가 추가되는 경우에는 bootroot-remote가
필요하지 않습니다.
서비스가 다른 머신에 추가되는 경우에는 해당 서비스 머신에 bootroot-remote를
배치해야 합니다.

## 아키텍처(요약)

1. CA 인프라 구동 및 초기화
2. 서비스 추가 및 서비스별 OpenBao Agent, bootroot-agent 설정
3. OpenBao Agent가 렌더링한 파일로 시크릿을 주입
4. bootroot-agent가 step-ca의 ACME 디렉터리를 읽음
5. ACME 계정을 등록(EAB 선택)
6. 인증서 발급 주문 생성
7. HTTP-01 토큰을 리스폰더에 등록
8. 리스폰더가 포트 80에서 HTTP-01 응답
9. 인증서 발급 및 파일 저장
10. bootroot-agent가 서비스 훅 실행
11. 인증서 주기적 갱신

## 안전 수칙

- 운영 시크릿은 git에 커밋하지 마세요.
- 시크릿 파일은 반드시 `0600`, 시크릿 디렉터리는 반드시 `0700` 권한으로
  설정하세요.
- OpenBao 토큰/unseal 키는 별도 안전 저장소에 보관하세요.
- Bootroot가 기본으로 설정하는 방식대로 CA와 DB는 같은 머신에 설치하고,
  DB는 외부에 오픈하지 마세요.
