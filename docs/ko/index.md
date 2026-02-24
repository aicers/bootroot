# Bootroot 매뉴얼

이 매뉴얼은 **bootroot**(bootroot CLI, bootroot-agent, bootroot-remote,
HTTP-01 리스폰더)와 **step-ca**, **OpenBao**, **Prometheus**, **Grafana**를
설치, 구성, 운영하는 전체 과정을 설명합니다. PKI 배경 지식이 없는 사용자도
이 문서만으로 설치와 인증서 발급을 완료할 수 있도록 구성했습니다.
bootroot CLI 실행 파일은 `bootroot`, bootroot-agent 실행 파일은
`bootroot-agent`, 원격 서비스 설정 CLI 실행 파일은 `bootroot-remote`입니다.

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
  위한 bootstrap CLI 도구
- **HTTP-01 리스폰더**: 이 프로젝트에서 직접 개발한 HTTP-01 전용 데몬
- **Prometheus**: 메트릭 수집기 (오픈 소스)
- **Grafana**: 메트릭 시각화 대시보드 (오픈 소스)

CA는 **Certificate Authority**의 약어로, 인증서를 서명해 신원을 보증하는
기관(또는 서비스)을 뜻합니다. ACME(Automated Certificate Management
Environment)는 RFC 8555에서 정의된 표준 프로토콜입니다.

## Bootroot의 설계 철학

### Bootroot의 1차 목표 — mTLS 인증서 회전

Bootroot는 (데몬 또는 도커) 서비스들 간 상호 인증을 mTLS로 하는 경우에
인증서 발급과 회전을 해 주는 시스템입니다. 보안 측면에서 강조되는 대목은
회전(rotation)이고, 갱신(renewal)이 만료에 대응하는 것이라면 회전은 만료
여부와 관계없이 주기적으로 교체한다는 점이 다릅니다. 회전을 구현하는 방법은
두 가지가 있습니다. 하나는 만료 여부와 관계없이 일정 주기마다 교체하는
것이고, 다른 하나는 유효 기간을 짧게 설정하여 만료 전에 갱신함으로써
결과적으로 주기적 교체가 이루어지게 하는 것입니다. Bootroot는 후자의 방식을
사용합니다.

### Bootroot의 2차 목표 — 자동화

초기 발급과 주기 회전의 전체 과정을 최대한 안전하게 자동으로 해 주는 것
역시 Bootroot의 중요한 목표입니다. 자동화가 안 되면 불편할 뿐만 아니라
사람이 수동으로 하면서 보안 허점을 만들기 쉽습니다. CA로부터 인증서를
새롭게 받아오는 역할을 `bootroot-agent` 데몬이 자동으로 수행합니다.

### 100% 자동화는 보안상 불가능

그러나 완전한 자동화는 보안 관점에서 보면 불가능합니다. 최초 신뢰 획득과
같은 절차마저 자동화를 함부로 하다 보면 그 자체가 보안 취약점이 될 수 있기
때문입니다. 그래서 Bootroot의 일부 과정은 사용자가 수동으로 할 수밖에
없는데, Bootroot는 이 수동 작업을 최대한 줄이도록 설계했습니다.

### Bootroot가 자동화하지 않는 것 (1) — CA의 키 갱신

현재 Bootroot는 CA의 비밀키/공개키가 최초 생성된 이후에 이를 변경하는 것을
별도의 기능으로 제공하고 있지 않습니다. CA 키 회전은 지원하지 않으며,
CA의 키를 교체하려면 현재는 전체 재초기화가 필요합니다. (향후 CA 키 교체
기능을 추가할 예정입니다.)

### 인증서 회전 자동화를 달성하기 위한 파생 목표 — 시크릿 관리

Bootroot가 사용하는 CA 프로토콜 ACME 방식은 CA가 요청자로부터 EAB
kid/hmac을 받아서 인증한 뒤에 인증서를 발급 또는 갱신해 줍니다. EAB
kid/hmac은 일종의 아이디와 비밀번호 같은 것으로서 `bootroot-agent`가 CA에
이 값을 제대로 전달해야 하고, 이 자동화 과정에서 이를 안전하게 관리해야
합니다. 따라서, 시크릿 매니저가 필요하고 Bootroot는 OpenBao를 사용합니다.
(안전하게 관리해야 할 비밀번호 같은 것을 시크릿이라 부릅니다.)

### Bootroot의 3차 목표 — 시크릿 회전

시크릿 역시 인증서와 마찬가지로 보안 측면에서 강조되는 대목은
회전입니다. 시크릿 매니저는 안전하게 보관해 주는 역할을 할 뿐이므로, 자동
회전은 Bootroot가 수행합니다.

### Bootroot가 자동화하지 않는 것 (2) — OpenBao의 Unseal Keys와 SecretID

시크릿 매니저 그 자체를 사용하기 위한 시크릿은 어쩔 수 없이 사용자가
수동으로 관리해야 합니다.

OpenBao를 사용하려면 언실 키와 루트 토큰이 필요합니다. 언실 키는 OpenBao를
처음 실행시킬 때 필요한 것이고, 루트 토큰은 OpenBao와 상호 작용을 할
때마다 필요합니다.

**언실 키.** OpenBao를 실행시킬 때에만 필요하므로 사용자가 직접 따로 잘
기억해 두고 수동으로 입력해야 합니다. (개발 편의를 위해서 언실 키를 파일에
쓰고 OpenBao가 구동될 때 그것을 읽어서 입력하는 기능이 제공됩니다.)

**루트 토큰.** Bootroot는 초기화 과정에서만 루트 토큰을 사용하고, 이후
일상 운영에서는 루트 토큰이 필요하지 않습니다. 대신 AppRole과 SecretID 입력
방식을 기본으로 사용합니다. AppRole과 SecretID는 EAB와 마찬가지로 OpenBao에
대한 인증 수단입니다. 보안상 중요한 대목은 SecretID의 회전입니다.
Bootroot는 SecretID 회전을 자동화해 주지 않습니다. 왜냐하면 SecretID가
다른 머신으로 전달되어야 하는 경우에는 이를 안전하게 하기 위해 추가적인
관리 체계를 도입해야 하기 때문입니다.

### 시크릿의 자동 회전과 수동 회전

SecretID의 회전과 전달은 사용자가 직접 Bootroot CLI(`bootroot` &
`bootroot-remote`) 명령을 사용해서 수행해야 합니다. SecretID를 제외한 다른
시크릿들은 모두 Bootroot가 자동으로 회전 및 전달을 수행합니다. SecretID는
OpenBao 자체에 대한 접근을 위한 것이지만, 나머지 다른 시크릿들은
OpenBao에 접속하여 받아올 수 있으므로 회전 과정의 자동화가 가능합니다.
OpenBao에 접속하여 시크릿을 받아 오는 것은 OpenBao Agent가 담당합니다.

### Bootroot가 자동화하지 않는 것 (3) — 최초 CA 인증

시크릿 매니저 측면만이 아니라 인증서 발급/갱신 측면에서도 최초 신뢰
문제는 있습니다. `bootroot-agent`가 CA와 통신할 때 올바른 CA인지 확인을
해야 하는데, 이를 위해서는 CA의 인증서를 미리 배포해야 합니다. 그런데, 이
과정을 수동으로 하는 것은 불편하고, 자동으로 하는 경우에는 이 배포 과정을
안전하게 수행하는 별도의 체계가 필요하게 됩니다. 다행히도 Bootroot의 기본
환경은 서비스를 처음 설치할 때 CA와 `bootroot-agent`를 사용자가 동시에 직접
제어하는 환경이니 최초 인증서 발급 시 CA 확인을 생략해도 별 문제가
없습니다. 이 최초 과정에서 CA 인증서를 받도록 되어 있으니 이후 자동화된
서비스 인증서 회전 과정에서 CA 확인이 담보됩니다.

### Bootroot가 자동화하지 않는 것 (4) — 설치와 운영 관련

설치와 운영 측면에서 Bootroot의 자동화 범위가 아닌 것이 있으므로 유의해야
합니다.

- **설치**: Bootroot CLI와 각 서비스를 위한 OpenBao Agent 및
  `bootroot-agent`의 설치는 사용자가 직접 해야 합니다. (CA를 포함하는 인프라
  구성 요소들과 이들을 위한 OpenBao Agent는 `bootroot infra up` 과정에서
  자동으로 설치됩니다.)
- **프로세스 관리**: 사용자가 직접 설치한 OpenBao Agent와
  `bootroot-agent`가 계속 실행될 수 있도록 systemd 또는 도커 restart 설정도
  사용자가 직접 설정 또는 확인해야 합니다.
- **회전 스케줄링**: Bootroot는 회전 명령(`bootroot rotate`)을 제공하지만
  그 주기적 실행(cron, systemd timer 등)은 사용자가 설정해야 합니다.

## 매뉴얼 구성

- **개념**: PKI, ACME, CSR, SAN, mTLS, 시크릿 관리(OpenBao) 개요
- **CLI**: infra 기동/초기화/상태 점검뿐 아니라 서비스 온보딩, 발급 검증,
  시크릿 회전, 모니터링, 원격 동기화 운영 안내까지 포함
- **CLI 예제**: 주요 CLI 시나리오별 실행 예시와 옵션 사용 패턴
- **설치**: OpenBao + step-ca + PostgreSQL + bootroot-agent +
  bootroot-remote + 리스폰더 설치
- **설정**: `agent.toml`, 프로필, 훅, 재시도, EAB
- **운영**: 갱신, 로그, 백업, 보안(OpenBao 포함)
- **CI/E2E**: PR 필수 매트릭스, 확장 워크플로, 아티팩트, 로컬 재현
- **문제 해결**: 자주 발생하는 오류와 대응 방법

CLI 사용법은 [CLI 문서](cli.md)와 [CLI 예제](cli-examples.md)에 정리되어 있습니다. CLI 문서에서는
`infra up/init/status`, `service add/verify`, `rotate`, `monitoring`과
`bootroot-remote bootstrap`/`apply-secret-id` 등 주요 명령을 다룹니다.
이 매뉴얼에서 **설치/설정 섹션은 CLI를 쓰지 않는 수동 절차**를 기준으로
설명하고, 나머지 섹션은 목적에 맞는 운영/개념/검증 관점으로 설명합니다.

## 자동화 경계(요약)

- bootroot가 자동화하는 것: 설정/산출물 생성과 갱신, 상태 기록,
  bootstrap 입력 준비, `bootroot infra up` 기반 인프라 Compose 구성/기동
- 운영자가 책임지는 것: 실행 구성요소 설치/업데이트(bootroot 관련 실행 파일과
  OpenBao Agent 포함), 프로세스 상시 실행 보장, 실행 환경 구성(예: Compose
  서비스 정의, systemd 유닛/타이머 등록)과 부팅 후 자동 시작/재시작 정책 적용

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

- 초기 설정 시 서비스별로 `bootroot-remote bootstrap`을 1회 실행하고,
  secret_id 회전 이후에는 `bootroot-remote apply-secret-id`를 실행합니다.

참고:
step-ca가 설치된 머신에 서비스가 추가되는 경우에는 bootroot-remote가
필요하지 않습니다.
서비스가 다른 머신에 추가되는 경우에는 해당 서비스 머신에 bootroot-remote를
배치해야 합니다.

## /etc/hosts 매핑 설정

인증서 발급/갱신이 정상 동작하려면, 이름 매핑(/etc/hosts 또는 DNS)이 아래 두
조건을 반드시 만족해야 합니다. DNS로 구성해도 되지만, 실무에서는 보통
`/etc/hosts` 매핑을 직접 구성하는 경우가 많습니다.

### 1) step-ca -> 서비스 FQDN(HTTP-01 검증 대상) -> 리스폰더 IP

- 접속 주체: step-ca
- 필수 조건: step-ca가 각 서비스의 검증 FQDN
  (`<instance_id>.<service_name>.<hostname>.<domain>`)을 리스폰더 IP로
  찾을 수 있어야 합니다.
- 설정 위치: step-ca가 동작하는 환경(컨테이너/호스트)의 `/etc/hosts` 또는 DNS

### 2) 원격 서비스 머신 -> step-ca/responder 이름 -> IP

- 접속 주체: step-ca/OpenBao와 다른 머신에 배치된 서비스
- 필수 조건: 해당 서비스 머신이 step-ca/responder를 이름으로 접근할 때
  올바른 IP로 찾을 수 있어야 합니다.
- 설정 위치: 해당 서비스 머신의 `/etc/hosts` 또는 DNS
- 예시 이름: `stepca.internal`, `responder.internal`
- 예외: step-ca/responder를 IP literal로 직접 접근하면 이 매핑은
  필요하지 않습니다.

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
