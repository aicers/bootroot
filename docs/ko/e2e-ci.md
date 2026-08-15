<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# CI/E2E

이 문서는 bootroot의 CI/E2E 검증 구조, 시나리오별 실행 흐름,
로컬 사전검증 방법, 실패 점검 기준을 정리합니다.

## CI 워크플로 구성

PR 필수 CI(`.github/workflows/ci.yml`)는 다음을 실행합니다.

- `test-core`: 단위/통합 스모크 경로
- `test-docker-e2e-matrix`: 전체 흐름 + 회전/복구 Docker E2E 조합 검증
  (10개 시나리오가 matrix 전략으로 병렬 실행)

확장 E2E(`.github/workflows/e2e-extended.yml`)는 별도 실행됩니다.

- `workflow_dispatch` 수동 실행
- `23:30 KST` 스케줄(UTC cron) + 당일 `main` 커밋 활동(KST) 게이팅

확장 워크플로는 복원력/경합 같은 무거운 검증을 위해 PR 필수 경로와
분리되어 있습니다.

## E2E 용어와 구성 축

용어 정의:

- `control node`: `bootroot`를 실행하며 step-ca와 OpenBao가 설치되어
  인프라 초기화와 서비스 상태 기록을 담당하는 머신
- `remote node`: `bootroot-remote`를 실행해 서비스 머신의 로컬 파일/설정을 반영하는 머신

E2E 시나리오는 다음 두 축의 조합으로 구성됩니다.

1. 전달 모드 (`bootroot service add --delivery-mode` 선택지)
2. 호스트 이름 매핑 모드 (E2E 스크립트 실행 모드)

전달 모드(`--delivery-mode`):

- `local-file`: `--delivery-mode`의 선택지입니다. 서비스가 step-ca/OpenBao/
  responder가 동작하는 같은 머신에 추가될 때 사용합니다.
- `remote-bootstrap`: `--delivery-mode`의 선택지입니다. 서비스가 다른
  머신에 추가될 때 사용하며, control node의 `bootroot`와 서비스 머신의
  `bootroot-remote bootstrap`을 함께 사용합니다.

호스트 이름 매핑 모드(E2E 실행 모드):

- `no-hosts`: E2E 스크립트가 사용하는 모드 이름입니다. 호스트 머신
  `/etc/hosts`는 수정하지 않고 `localhost`/IP 기반으로 step-ca, responder에
  접속합니다.
- `hosts`: E2E 스크립트가 사용하는 모드 이름입니다. 호스트 머신
  `/etc/hosts`에 `stepca.internal`, `responder.internal` entry를 추가해 해당
  이름으로 접속합니다. E2E에서는 실행 중에만 추가하고 cleanup에서 제거하며,
  운영 환경에서는 DNS/hosts를 지속적으로 관리해야 합니다.

공통 동작: 위 두 매핑 모드 모두 서비스 SAN(FQDN) 도달을 위해 step-ca
컨테이너 내부 `/etc/hosts`에 서비스 FQDN -> responder IP 매핑을 설정합니다.

운영 참고: E2E의 hosts 추가/정리는 테스트 편의를 위한 동작입니다. 운영 환경에서는
이름 매핑(DNS/hosts)과 서비스/에이전트 상시 실행을 지속적으로 관리해야 합니다.

## Docker E2E 검증 범위

PR 필수 Docker 조합 검증은 다음을 검증합니다.

- 로컬 전달 E2E 시나리오 (`no-hosts`)
- 로컬 전달 E2E 시나리오 (`hosts`)
- 원격 전달 E2E 시나리오 (`no-hosts`)
- 원격 전달 E2E 시나리오 (`hosts`)
- rotation/recovery matrix (`secret_id,eab,responder_hmac,trust_sync`)
- reinit 복구
- step-ca 인증서 SAN
- compose 델타 없는 OpenBao TLS 전환
- `secrets/` 소유자 변경 이후 OpenBao TLS 인증서 재발급
- 같은 호스트의 두 인스턴스가 서로 독립적으로 유지되는지(설치,
  컨테이너, 볼륨, 게시 포트, HTTP-01 리스폰더 DNS 별칭)

주요 스크립트:

- `scripts/impl/run-local-lifecycle.sh`
- `scripts/impl/run-remote-lifecycle.sh`
- `scripts/impl/run-rotation-recovery.sh`
- `scripts/impl/run-reinit-recovery.sh`
- `scripts/impl/run-stepca-san.sh`
- `scripts/impl/run-openbao-tls-no-delta.sh`
- `scripts/impl/run-openbao-tls-reown.sh`
- `scripts/impl/run-two-instance-isolation.sh`

위 스크립트 가운데 셋은 프로젝트 이름을 전혀 전달받지 **않고** 스스로
만들어 씁니다. `run-two-instance-isolation.sh`는 basename이 같은
두 compose 디렉터리에 두 인스턴스를 설치하고 각 인스턴스의 Compose
프로젝트를 그 인스턴스 자신의 `.env`에서 해석해야 하므로, 호출자가
`COMPOSE_PROJECT_NAME`을 넘기면 두 인스턴스가 하나로 합쳐집니다. 두
라이프사이클 스크립트는 다음 절이 설명하는 이유로 실행마다 하나의
정체성을 만들어 씁니다. 셋 모두 실행마다 고유한 `--instance-name` 값을
스스로 만들고 비어 있는 호스트 포트도 직접 고르며, 모든 정리와 잔여물
확인이 그 이름들로만 한정되므로 기본 `bootroot` 설치본이 이미 있는
호스트에서도 안전하게 실행할 수 있습니다.

### 라이프사이클 실행 두 개는 한 호스트를 공유할 수 있습니다

`run-local-lifecycle.sh`와 `run-remote-lifecycle.sh`는 실행마다 아이덴티티
전체를 스스로 만들어 냅니다. 그래서 두 번째 실행(다른 워크트리, 다른 에이전트
세션, 손으로 무언가를 확인하는 개발자)이 첫 번째 실행이 끝나기를 기다릴 필요가
없습니다. 각 실행은 다음을 수행합니다.

- 아티팩트 디렉터리의 basename과 자신의 pid로 인스턴스 이름을 만듭니다.
  앞에는 `e2e-local-` 또는 `e2e-remote-`가 붙고, `infra install`이 받아들이는
  39자에 맞춰 잘립니다. pid는 꼬리에 있고 자르기가 남기는 쪽이 꼬리이므로,
  아티팩트 basename이 같은 두 실행도 서로 다른 이름을 얻습니다.
- 그 이름을 `infra install --instance-name`에 넘기고 `BOOTROOT_INSTANCE`로
  내보내므로, Compose와 바이너리가 모든 컨테이너를 같은 이름으로 부릅니다.
- Compose 프로젝트는 같은 식별자에서 별도로, 자기 규칙에 따라 만듭니다. 앞에는
  `bootroot-e2e-local-` 또는 `bootroot-e2e-remote-`가 붙고, 잘리지 않습니다.
  프로젝트는 DNS 레이블 안에 들어갈 필요가 없기 때문입니다. 그래서 CI 길이의
  `GITHUB_RUN_ID` 아래에서는 인스턴스 이름에 허용되는 길이를 넘어섭니다.
  프로젝트는 `COMPOSE_PROJECT_NAME`으로 내보내져 바이너리에 전달되며, 이
  변수는 프로젝트에 한해서만 `--instance-name`보다 우선합니다. 따라서 실행
  안의 모든 `bootroot` 호출이 스크립트 자신의 `docker compose` 호출과 같은
  프로젝트를 대상으로 삼습니다. 실행은 그 프로젝트를 가정하지 않고 실제
  컨테이너의 `com.docker.compose.project` 레이블에서 다시 읽어 확인합니다.
- 비어 있는 `127.0.0.1` 포트 네 개를 고르고 `--postgres-host-port`,
  `--openbao-host-port`, `--stepca-host-port`, `--http01-admin-host-port`로
  `infra install`에 넘깁니다. 그래야 설치가 쓰는 `.env`에 기록되어, 같은
  실행의 이후 `bootroot` 호출이 모두 같은 포트를 해석합니다.
- `BOOTROOT_HTTP01_IMAGE`를 `bootroot-http01-responder:<인스턴스>`로
  내보냅니다. `docker-compose.yml`이 빌드하는 이미지는 응답기 하나뿐이고 그
  `image:`가 빌드 결과가 기록되는 태그이기 때문입니다. 배포된 기본값 그대로
  두면 두 실행이 같은 태그에 번갈아 쓰게 되고, 실행이 HTTP-01 DNS 별칭을
  적용하려고 응답기를 다시 만들 때 그 태그를 다시 해석해 다른 실행의 빌드로
  기동합니다. 실행은 끝날 때 그 태그를 제거합니다. `down`은 컨테이너를 지울
  뿐 이미지는 지우지 않습니다.
- 인스턴스, 프로젝트, 이미지, 포트 네 개를
  `<아티팩트 디렉터리>/run-identity.json`에 기록하므로 실패한 실행도 나중에
  읽을 수 있습니다.

### `hosts` 모드는 여전히 한 번에 하나만 실행됩니다

실행이 추가하는 entry는 고정된 호스트 이름(`stepca.internal`,
`responder.internal`)을 키로 삼고 고정된 마커 리터럴로 제거되며, `/etc/hosts`를
고쳐 쓰는 일은 머신 전체가 공유하는 한 파일에 대한 잠금 없는
읽기-수정-쓰기입니다. 마커 철자를 바꾼다고 어느 쪽도 해결되지 않습니다.

이 모드는 지금까지 우연히, 오직 우연히 직렬화되어 있었습니다. 두 실행은 그
파일에 닿기 훨씬 전에 Compose 프로젝트, 컨테이너 이름, 포트에서 먼저
충돌했기 때문입니다. 이제는 그것을 막는 것이 없고, 두 실행이 그 파일에서 서로에게
하는 일은 요란하지 않고 조용합니다. 두 번째 실행은 호스트 이름이 이미 있는 것을
보고 아무것도 추가하지 않으며, 그다음 첫 번째 실행의 정리가 두 마커 줄을 모두
지워 버립니다. 두 번째 실행이 아직 그 이름으로 해석하고 있는 동안에 말입니다.

그래서 직렬화를 물려받는 대신 명시합니다. `hosts` 모드 실행은 `sudo` 검사를
마친 뒤 첫 수정 전에 `/tmp/bootroot-e2e-hosts.lock`에 잠금을 잡고, 자신의
entry를 모두 지운 뒤에 놓습니다. 두 번째 실행은 파일에 손대기 전에 그 지점에서
거부되며, 잠금을 쥔 pid를 알려 줍니다. 종료된 실행이 남긴 잠금은 죽은 pid를
가리키므로 다음 실행이 지우고 가져갑니다. 거부된 실행이나 잠금을 잡기 전에
실패한 실행은 끝날 때 `/etc/hosts`를 건드리지 않습니다. 정리 시의 고쳐 쓰기는
그 스크립트의 마커가 붙은 줄을 모두 지우므로, 어느 실행의 entry인지 구별할 수
없기 때문입니다.

잠금 하나가 두 하네스를 모두 덮습니다. 둘 다 같은 호스트 이름 두 개를 추가하므로
로컬 실행과 원격 실행은 로컬 실행 두 개와 똑같이 서로를 덮어씁니다. 그 경로는
실행 마커 디렉터리와 달리 사용자별이 아니라 머신 전체입니다. `/etc/hosts`가
그렇기 때문입니다. 한 사용자의 실행만 볼 수 있는 잠금은 두 사용자의 실행이 한
파일을 동시에 고치도록 내버려 둡니다. 그 잠금에서 읽어 무언가에 사용하는 값은
없고(생존을 확인할 pid와 메시지에 넣을 이름뿐입니다), 그래서 누군가 그 경로에
파일을 심어 두면 철거를 겨냥하는 대신 `hosts` 실행을 요란하게 거부하게 됩니다.
마커 디렉터리에 있는 소유권 검사 장치가 여기에는 필요 없는 이유입니다.

`no-hosts` 실행은 잠금을 잡지 않으며 영향을 받지 않습니다. 라이프사이클 실행
두 개가 동시에 필요하면 그 모드를 쓰십시오.

### 종료된 실행을 수거합니다

고유한 이름은 종료된 실행을 우연히 정리해 주던 효과를 잃게 합니다. 어떤
것도 그 잔여물과 같은 이름을 다시 갖지 않으므로, 이후 어떤 실행도 시작할 때
그것을 정리하지 않고, 그대로 두면 머신이 켜져 있는 내내 쌓입니다.

그래서 각 실행은 자신의 생존을 명시적으로 기록합니다. 시작할 때
`${TMPDIR:-/tmp}/bootroot-e2e-runs-<uid>/<인스턴스>`에 자신의 pid와 Compose
프로젝트를 쓰고, 끝날 때 그 파일을 지웁니다. 지우는 것은 오직 자신의 pid를
기록한 파일뿐이며, 자신의 정리가 아무것도 남기지 않았을 때뿐입니다. 어떤
작업을 하기 전에 그 디렉터리의 모든 마커를 읽어
pid가 살아 있는 것은 건너뛰고, 죽은 것은 그 인스턴스의 컨테이너 아홉 개와
응답기 이미지 태그, 그리고 그 프로젝트 레이블이 붙은 볼륨과 네트워크를
제거한 뒤 마커를 지웁니다.
완전히 수거하지 못한 마커는 남으므로, 남은 것을 방치하지 않고 다음 실행이
다시 시도합니다.

재사용된 pid는 죽은 실행의 컨테이너를 한 번 더 살려 둘 수 있지만 이는
받아들일 수 있습니다. 다음 실행이 수거하고, 잘못 제거되는 것은 없습니다.
이 수거는 접두사나 와일드카드로 일치시키지 않습니다. `bootroot-*`는 같은
호스트의 실제 기본 아이덴티티 설치본까지 닿기 때문이며, 따라서 실행이
기록한 인스턴스에만 손댈 수 있습니다.

이 디렉터리는 사용자별이며 `0700`으로 만들어지고, 자신이 소유하지 않은
디렉터리는 거부합니다. 마커의 파일 이름은 수거가 정확한 컨테이너 이름으로
철거할 인스턴스이므로, 그곳에 쓸 수 있는 사람은 이후 실행이 무엇을 제거할지
고르는 셈이 됩니다. 그 경로가 심볼릭 링크이면 따라가지 않고 곧바로 거부합니다.
소유권 검사는 링크를 볼 수 없기 때문입니다. `-L`을 제외한 셸 검사는 모두 링크의
대상을 보므로, 이 사용자가 소유한 디렉터리를 가리키는 링크는 소유권 검사를
통과하면서 애초에 마커가 아니었던 파일들을 수거에 넘기게 됩니다.
경로에 들어가는 uid는 `$TMPDIR`가 macOS에 이미 주는
분리를 리눅스에도 주며, 덕분에 두 번째 사용자가 거부당하는 대신 두 사용자가
한 호스트에서 하네스를 실행할 수 있습니다.

`scripts/validate-e2e-run-scope.sh`가 Docker 없이 이름 생성, 마커, 수거,
`hosts` 잠금을 모두 확인하며 `check` CI 잡에서 실행됩니다.

### 남은 컨테이너는 실행이 시작되기 전에 실패시킵니다

나머지 하네스는 기본 아이덴티티로 설치하므로, 컨테이너 이름은 compose
디렉터리의 `.env`에 기록된 값을 따릅니다. 설치가 다른 값을 기록하지 않았다면
`bootroot-*`입니다. 라이프사이클 스크립트 두 개는 위에서 만든 인스턴스로
설치하고 같은 확인에 그 이름을 넘깁니다. 어느 쪽이든 이름은 Docker 데몬
전체에서 고유하므로 같은 이름을 쓰는 실행 두 개, 또는 그런 실행 하나와 실제
설치본은 한 호스트를 공유할 수 없습니다. `up` 시점에 `container_name`이
충돌합니다.

그래서 각 하네스는 어떤 작업도 하기 전에, 해석된 인스턴스 이름으로
bootroot가 만드는 아홉 개 컨테이너 이름
(`-openbao`, `-postgres`, `-ca`, `-http01`, `-prometheus`, `-grafana`,
`-grafana-public`, `-openbao-agent-stepca`, `-openbao-agent-responder`)이
하나도 없음을 먼저 확인합니다. `SIGKILL`로 종료된 실행은 자신의 cleanup에
도달하지 못하며, 그렇게 남은 컨테이너에는 이후 어떤 실행도 조회하지 않을
Compose 프로젝트 레이블이 붙어 있습니다. 확인이 레이블이 아니라 이름으로
이루어지는 이유입니다. 실패 메시지는 발견한 컨테이너와 그것을 제거하는
`docker rm -f` 명령을 함께 알려 줍니다. 그 명령을 실행하기 전에, 종료된
실행이 남긴 잔여물인지 필요한 설치본인지 먼저 확인하세요.

이 확인은 실행 시작 시점의 정리보다 **뒤가 아니라 앞**에 옵니다. 그
정리는 같은 호스트의 실제 설치본이 함께 쓰는 Compose 프로젝트에 대한
`down -v --remove-orphans`이므로, 먼저 실행하면 그 설치본을 볼륨까지
지워 버리고 확인은 방금 자신이 비운 데몬을 읽게 됩니다. 그런 설치본과
종료된 실행이 남긴 잔여물은 무엇으로도 구분할 수 없기에(그래서 메시지가
직접 확인하라고 요청합니다) 하네스는 둘 중 어느 것도 제거하지 않습니다.
확인을 통과한 뒤에야 하네스는 스택을 자기 것으로 넘겨받습니다. 뒤따르는
정리는 확인이 보지 않는 볼륨, 네트워크, 고아 컨테이너를 위한 것이며, 그
지점 이전에는 EXIT 트랩도 아무것도 제거하지 않으므로 확인에서 멈춘
실행은 호스트를 발견한 그대로 남겨 둡니다.

같은 확인은 `cleanup`에서도 한 번 더 실행됩니다. 거기서 발견된 잔여물은
실행을 실패시키지만(자기 쓰레기를 남기는 하네스는 고장 난 것입니다),
이미 다른 이유로 실패한 실행의 상태를 덮어쓰지는 않습니다. 정리 명령의
출력은 실행 로그(`<아티팩트 디렉터리>/run.log`, `run.log`가 없는
하네스에서는 `runner.log`)로 갑니다. 아무것도 지우지 못한 정리와 전부
지운 정리를 구분할 수 있어야 하기 때문입니다.

조회할 수 없는 데몬은 깨끗한 호스트가 아닙니다. 두 확인 모두 데몬이 가진
것을 목록으로 조회하며(기본 아이덴티티 하네스는 컨테이너 이름으로,
실행 범위 하네스는 `com.docker.compose.project` 레이블로), 그 조회가
실패하면 확인 자체가 Docker의 오류 메시지와 함께 실패합니다. 실패한
조회를 "아무것도 없음"으로 읽으면 시작 시점의 확인을 통과하고, 의도적으로
치명적이지 않게 둔 시작 정리의 `|| true`도 지나쳐, 결국 이 확인이 없애려던
바로 그 혼란스러운 중간 실패로 다시 나타납니다.

`scripts/validate-e2e-leftover-check.sh`가 이 모든 동작을 Docker 없이
검증하며, CI의 `check` 잡에서 실행됩니다.

확장 워크플로는 다음을 검증합니다.

- baseline 경합/스케일 동작
- 반복 장애/복구 동작
- 회전 스케줄 동등성(`systemd-timer`, `cron`)
- CA 키 회전 장애/복구(5개 장애 주입 시나리오)
- 인프라 라이프사이클(전체 로컬 전달 왕복)

주요 스크립트:

- `scripts/impl/run-extended-suite.sh`

## 시나리오별 구성과 실행 단계

이 섹션은 다른 메뉴의 핵심 맥락을 의도적으로 다시 설명합니다.
이 페이지 하나만 보고도 CI/E2E 시나리오를 이해하고 재현할 수 있도록 구성했습니다.

### 1) 로컬 전달 E2E 시나리오 (`no-hosts`)

구성:

- `scripts/impl/run-local-lifecycle.sh` 기반 단일 머신 시나리오
- Docker Compose에서 `openbao`, `postgres`, `step-ca`, `bootroot-http01` 실행
- 서비스는 `--delivery-mode local-file`로 추가
- 이 시나리오의 서비스 구성(총 2개): `edge-proxy`, `web-app`
- 해석 모드는 `no-hosts` (`/etc/hosts` 수정 없음)

목적:

- 기본 same-machine 온보딩 경로를 end-to-end로 검증
- `bootroot init` -> `service add` -> `verify` 흐름 검증
- same-machine 경로에서 회전 후 재발급 동작 검증

실행 단계:

1. `infra-up`: Compose 서비스 기동 및 readiness 대기
2. `init`: `bootroot init --summary-json` 실행 후 JSON에서 런타임 AppRole
   자격증명 파싱
3. `service-add`: 두 서비스를 `local-file` 모드로 추가
4. `verify-initial`: 초기 인증서 발급/검증 후 fingerprint 스냅샷 저장
5. `rotate-infra-secret-id`: 전용 `infra_rotate` 자격증명으로
   stepca/responder 인프라 AppRole secret_id를 회전한 뒤,
   `runtime_rotate` 자격증명이 인프라 역할 경로에서 거부되는지 검증
6. `rotate-openbao-recovery`: OpenBao 루트 토큰 수동 회전
7. `bootstrap-after-openbao-recovery`: remote bootstrap 재실행으로
   AppRole 기반 접근 연속성 검증
8. `rotate-responder-hmac`: 회전 실행 후 재발급 강제
9. `verify-after-responder-hmac`: 재검증 및 fingerprint 변경 확인
10. `cleanup`: 로그/아티팩트 수집 후 Compose 정리

실제 실행 명령(스크립트 발췌):

```bash
# 1) infra-install (.env 생성, 컨테이너 시작)
bootroot infra install --compose-file "$COMPOSE_FILE"

# 2) init
# DB 자격 증명은 infra install이 생성한 .env에서 자동으로 읽힙니다.
# POSTGRES_HOST와 POSTGRES_PORT는 스크립트에서 설정하여
# host-mapped 포트를 통해 연결합니다.
# 모든 프롬프트를 각자의 전용 플래그로 답하고 stdin을 닫아서 실행하므로,
# 파이프로 넘기는 답변 순서에도 남아 있는 파일에도 의존하지 않습니다.
# 대상 파일이 없는 overwrite 플래그는 아무 일도 하지 않습니다. init은
# EOF를 답으로 읽지 않고 실행을 실패시킵니다.
BOOTROOT_LANG=en bootroot init \
  --compose-file "$COMPOSE_FILE" \
  --secrets-dir "$SECRETS_DIR" \
  --summary-json "$INIT_SUMMARY_JSON" \
  --enable auto-generate,show-secrets,db-provision \
  --no-eab \
  --save-unseal-keys \
  --overwrite-password \
  --overwrite-ca-json \
  --overwrite-state \
  --confirm-db-provision \
  --db-user "step" \
  --db-name "stepca" \
  --responder-url "$RESPONDER_URL" </dev/null

# 3) service-add
# 서로 다른 로컬 서비스는 각자 자신의 에이전트 설정을 사용합니다
# (서비스마다 데몬 하나, [openbao] AppRole 아이덴티티 하나).
bootroot service add --service-name edge-proxy \
  --delivery-mode local-file --agent-config "$EDGE_AGENT_CONFIG"
bootroot service add --service-name web-app \
  --delivery-mode local-file --agent-config "$WEB_AGENT_CONFIG"

# 4) verify-initial / 9) verify-after-responder-hmac
bootroot verify --service-name edge-proxy --agent-config "$EDGE_AGENT_CONFIG"
bootroot verify --service-name web-app --agent-config "$WEB_AGENT_CONFIG"

# 5) rotate-infra-secret-id
# init summary에서
#   infra_rotate: role_id/secret_id
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  --yes approle-secret-id --infra stepca   # 이후 --infra responder
# 부정 검증: 같은 명령을 runtime_rotate 자격증명으로 실행하면
# permission denied로 실패해야 합니다

# 6) rotate-openbao-recovery (명시적 수동 실행)
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --root-token "$INIT_ROOT_TOKEN" \
  --yes \
  openbao-recovery \
  --rotate-root-token \
  --output "$OPENBAO_RECOVERY_OUTPUT_FILE"

# 8) rotate-responder-hmac
# init summary에서
#   runtime_service_add: role_id/secret_id
#   runtime_rotate: role_id/secret_id
bootroot rotate --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://127.0.0.1:8200" \
  --auth-mode approle \
  --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
  --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
  --yes responder-hmac
```

### 2) 로컬 전달 E2E 시나리오 (`hosts`)

구성:

- 위와 동일한 스크립트/토폴로지 사용
- `no-hosts`와 동일한 서비스 구성: `edge-proxy`, `web-app`
- 해석 모드는 `hosts`
- 스크립트가 `stepca.internal`, `responder.internal` 임시 host entry를
  추가/삭제 (`sudo -n` 필요)
- 두 라이프사이클 스크립트를 통틀어 `hosts` 모드 실행은 한 번에 하나입니다.
  두 번째 실행은 `/tmp/bootroot-e2e-hosts.lock`에서 거부됩니다

목적:

- `hosts` 이름 해석 경로 검증
- `/etc/hosts` 기반 이름 해석에서 발생하는 문제 조기 탐지

실행 단계:

1. 머신 전체 `hosts` 잠금을 잡은 뒤 `stepca.internal`, `responder.internal`
   host entry 추가
2. `no-hosts`와 동일한 전체 흐름 phase 실행
3. cleanup에서 임시 host entry 제거

실제 실행 명령(스크립트 발췌):

```bash
# hosts 모드로 실행
RESOLUTION_MODE=hosts ./scripts/impl/run-local-lifecycle.sh

# 내부적으로 /etc/hosts 추가/정리
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 3) 원격 전달 E2E 시나리오 (`no-hosts`)

구성:

- 한 번의 실행에서 두 workspace 사용:
  `control-node` (step-ca 머신 역할), `remote-node` (서비스 머신 역할)
- 서비스는 `--delivery-mode remote-bootstrap`으로 추가
- 이 시나리오의 서비스 구성(총 2개): `edge-proxy`, `web-app`
- 원격 bootstrap 반영은 `bootroot-remote bootstrap`으로 수행
- 해석 모드는 `no-hosts`

목적:

- remote-bootstrap 온보딩과 일회성 bootstrap 반영 방식 검증
- `secret_id` 자가 치유 검증: control node에서 `rotate approle-secret-id`
  실행 후, 실행 중인 `bootroot-agent` fast-poll 루프가 디스크의 자체
  `secret_id`를 갱신하여 원격에서의 수동 `apply-secret-id` / 재-bootstrap
  없이 계속 인증
- trust 자가 치유 검증: KV의 trust 업데이트 후 실행 중인 에이전트가
  fast-poll로 `[trust]` 핀과 `ca-bundle.pem`을 다시 렌더링하고 수동
  재-bootstrap 없이 계속 갱신
- `responder_hmac`의 bootstrap 재반영 및 원격 회전/복구 시퀀스 검증

실행 단계:

1. control node에서 `infra-up`, `init` 실행 후 summary JSON에서 런타임
   AppRole 자격증명 파싱
2. control node에서 `remote-bootstrap` 모드로 두 서비스 `service-add` 실행
3. bootstrap 재료(`role_id`, `secret_id`)를 remote node로 복사
4. `bootstrap-initial`: remote node에서 서비스별 `bootroot-remote bootstrap`
   실행
5. `verify-initial`: remote node에서 인증서 발급/검증
6. 자가 치유 주기(수동 재-bootstrap 없음): control node에서
   `rotate-secret-id`와 `rotate-trust-sync` 실행 후, `selfheal-<service>`가
   실행 중인 각 에이전트의 fast-poll 루프가 자체 `secret_id`를 갱신하고
   trust를 다시 렌더링함을 확인하며, 갱신된 자격증명으로 force-reissue
   왕복(`before-selfheal` -> `after-selfheal`)을 수행
7. `responder_hmac`는 여전히 bootstrap으로 전달:
   `rotate-responder-hmac` -> `bootstrap-after-responder-hmac` ->
   `verify-after-responder-hmac`
8. 각 단계 사이 인증서 fingerprint 변경 여부 확인

실제 실행 명령(스크립트 발췌):

```bash
# control node: infra-install / init / service-add
bootroot infra install --compose-file "$COMPOSE_FILE"
BOOTROOT_LANG=en bootroot init \
  --compose-file "$COMPOSE_FILE" --summary-json "$INIT_SUMMARY_JSON" \
  --enable auto-generate,show-secrets,db-provision \
  --no-eab --save-unseal-keys \
  --overwrite-password --overwrite-ca-json --overwrite-state \
  --confirm-db-provision \
  --db-user "step" --db-name "stepca" \
  --responder-url "$RESPONDER_URL" </dev/null
bootroot service add --service-name edge-proxy \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH"
bootroot service add --service-name web-app \
  --delivery-mode remote-bootstrap --agent-config "$REMOTE_AGENT_CONFIG_PATH_2"

# remote node: bootstrap (서비스별)
bootroot-remote bootstrap --openbao-url "http://127.0.0.1:8200" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$role_id_path" --secret-id-path "$secret_id_path" \
  --agent-config-path "$REMOTE_AGENT_CONFIG_PATH" \
  --output json

# control node: secret_id 회전 + trust 업데이트를 KV에 게시
bootroot rotate --yes approle-secret-id --service-name edge-proxy
bootroot rotate --yes approle-secret-id --service-name web-app
# remote node: 수동 재반영 없음. 실행 중인 bootroot-agent fast-poll 루프가
# 자체 secret_id를 갱신하고 trust를 다시 렌더링하며, 이후 force-reissue
# --wait 왕복으로 갱신된 자격증명으로 동작함을 증명(selfheal-<service> 단계).

# responder_hmac는 여전히 bootstrap으로 전달
bootroot rotate --yes responder-hmac
bootroot-remote bootstrap ...  # 서비스별 responder_hmac 재반영
```

### 4) 원격 전달 E2E 시나리오 (`hosts`)

구성:

- 위 원격 전달 E2E 시나리오와 동일한 control-node/remote-node 모델
- remote `no-hosts`와 동일한 서비스 구성: `edge-proxy`, `web-app`
- 해석 모드는 `hosts`
- 스크립트가 임시 `/etc/hosts` entry를 추가/정리
- 두 라이프사이클 스크립트를 통틀어 `hosts` 모드 실행은 한 번에 하나입니다.
  이 스크립트와 `run-local-lifecycle.sh`는 같은 호스트 이름 두 개를 추가하며
  잠금 하나를 공유합니다

목적:

- hosts 기반 이름 해석에서 remote-bootstrap 전체 흐름 검증
- remote sync/verify 단계의 해석 모드 의존 실패 탐지

실행 단계:

1. 머신 전체 `hosts` 잠금을 잡은 뒤 `stepca.internal`, `responder.internal`
   host entry 추가
    - `stepca.internal` entry 추가
    - `responder.internal` entry 추가
2. 원격 전달 E2E 시나리오의 phase 전체 실행
3. cleanup에서 임시 host entry 제거
    - `HOSTS_MARKER`가 붙은 행만 삭제

실제 실행 명령(스크립트 발췌):

```bash
# hosts 모드로 원격 전체 흐름 실행
RESOLUTION_MODE=hosts ./scripts/impl/run-remote-lifecycle.sh

# 내부적으로 /etc/hosts 추가/정리
echo "127.0.0.1 stepca.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
echo "127.0.0.1 responder.internal ${HOSTS_MARKER}" | sudo -n tee -a /etc/hosts
sudo -n awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' \
  /etc/hosts >"$tmp_file"
sudo -n cp "$tmp_file" /etc/hosts
```

### 5) rotation/recovery matrix

구성:

- 스크립트: `scripts/impl/run-rotation-recovery.sh`
- 기본 시나리오 입력:
  `tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json`

#### 서비스 구성(3개 노드, 총 8개 서비스)

- `node-a`: daemon-c1, daemon-c2, docker-c1
- `node-b`: daemon-c3, docker-c2, docker-c3
- `node-c`: daemon-c4, docker-c4

각 서비스에 대해 모든 회전 항목을 반복 검증합니다.

#### 회전 항목

- `secret_id,eab,responder_hmac,trust_sync`

목적:

- 항목별 회전 및 복구 동작 검증
- 단일 타깃 실패 주입 후 복구 검증
- 회전 후 재반영 검증

> **참고:** 이 회전/복구 매트릭스는 `secret_id`를 포함한 모든 회전 항목에
> `bootroot-remote bootstrap`을 일괄 사용합니다. 이전 `secret_id`가
> 테스트 기간 동안 유효하고, `bootstrap`과 `apply-secret-id` 모두 동일한
> 방식으로 인증하기 때문에 동작합니다. 운영 환경에서는 실행 중인
> `bootroot-agent`가 fast-poll 루프를 통해 운영자 개입 없이 `secret_id`와
> trust를 자가 치유하며, `apply-secret-id`(및 재-bootstrap)는 `secret_id_ttl`을
> 넘겨 오프라인 상태였던(따라서 스스로 갱신할 수 없는) 에이전트를 위한 복구
> 경로입니다(운영 가이드 참조). 위의 원격 전달 라이프사이클 시나리오가 이
> 자가 치유 경로를 직접 검증합니다.

실행 단계(항목별 반복):

1. control node에서 대상 항목 회전
2. 각 remote node에서 `bootroot-remote bootstrap` 실행하여 재반영
3. 회전 후 인증서 발급이 정상 동작하는지 검증
4. 실패 cycle: 특정 서비스 실패 주입 후 복구 확인
5. 복구 cycle: 재회전/재반영 후 정상 동작 확인

실제 실행 명령(스크립트 발췌):

```bash
# 시나리오 실행
./scripts/impl/run-rotation-recovery.sh

# 회전/verify 루프에서 사용하는 핵심 명령
bootroot rotate --yes approle-secret-id --service-name "$service"
bootroot-remote bootstrap --service-name "$service" ...
bootroot verify --service-name "$service" --agent-config "$agent_config_path"
```

### 6) CA 키 회전 장애/복구

구성:

- 스크립트: `scripts/impl/run-ca-key-rotation-recovery.sh`
- Docker Compose 인프라 기반 단일 머신
- 서비스 구성(총 3개): `edge-proxy` (`local-file`),
  `web-app` (`local-file`), `edge-proxy` (`remote-bootstrap`)
- 5개 장애 주입 시나리오를 동일 인프라에서 순차 실행

목적:

- `bootroot rotate ca-key`가 인프라 장애 후 올바르게 이어서
  진행되는지 검증
- CA 키 회전 중 mTLS가 중단되지 않는지 검증
- `rotation-state.json` 멱등 phase 추적 검증
- `--skip reissue`, `--force`, `--cleanup` 플래그 동작 검증
- 활성 회전 중 `trust-sync` 충돌 방지 검증

#### 시나리오

시나리오 1 — Phase 3 장애(OpenBao 접근 불가):

1. OpenBao 컨테이너 중지 → Phase 3(가산적 trust 기록) 실패
2. `rotate ca-key` 실행 → 실패 기대
3. 서비스 정상 동작 확인(cert 미변경, step-ca 실행 중)
4. OpenBao 재시작 후 회전 재실행 → 이어서 완료
5. 강제 재발급 후 새 인증서 검증

시나리오 2 — Phase 4 장애(step-ca 제거):

1. step-ca 컨테이너 제거 → Phase 4(재시작) 실패
2. `rotate ca-key` 실행 → Phase 0-3 성공, Phase 4 실패
3. 서비스 정상 동작 확인(전이 trust 활성)
4. step-ca 복구 후 회전 재실행 → 이어서 완료
5. 강제 재발급 후 새 인증서 검증

시나리오 3 — Phase 5 부분 재발급:

1. `rotate ca-key --skip reissue` 실행 → Phase 6 중단(미이전 서비스)
2. 서비스 1개(edge-proxy)만 강제 재발급
3. 기존 cert(web-app)과 신규 cert(edge-proxy) 모두 동작 확인
4. 나머지 서비스 강제 재발급
5. `--force`로 회전 재실행 → 완료

시나리오 4 — Phase 6 진입 차단:

1. `rotate ca-key --skip reissue` 실행 → Phase 6 차단
2. 오류 출력에 미이전 서비스 이름 포함 확인
3. `--force`로 재실행 → Phase 6 경고와 함께 완료
4. 강제 재발급 후 검증

시나리오 5 — 활성 회전 중 trust-sync 충돌:

1. step-ca 중지로 회전 중간에 중단 → 활성 회전 생성
2. `rotation-state.json` 존재 확인
3. `trust-sync` 실행 → 회전 진행 중 오류로 중단 기대
4. step-ca 복구 후 회전 완료
5. 전체 서비스 검증

실제 실행 명령(스크립트 발췌):

```bash
# AppRole 인증을 사용한 rotate ca-key 래퍼
bootroot rotate \
  --compose-file "$COMPOSE_FILE" \
  --openbao-url "http://${STEPCA_HOST_IP}:8200" \
  --auth-mode approle \
  --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
  --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
  --yes \
  ca-key --skip reissue --force --cleanup

# Docker 조작을 통한 장애 주입
docker compose -f "$COMPOSE_FILE" stop openbao
docker compose -f "$COMPOSE_FILE" rm -sf step-ca
```

### 7) extended workflow 케이스

구성:

- 스크립트: `scripts/impl/run-extended-suite.sh`
- 케이스: `scale-contention`, `failure-recovery`, `runner-timer`, `runner-cron`,
  `ca-key-recovery`, `infra-lifecycle`
- 케이스 결과는 `extended-summary.json`에 집계
- 서비스 구성: 각 케이스가 사용하는 하위 시나리오/스크립트 구성을 그대로 상속하며,
  scale/contention, failure/recovery 케이스는 복수 서비스를 포함

목적:

- 무거운 stress/recovery 검증을 PR 필수 경로 밖에서 수행
- 회전 스케줄 동등성(`systemd-timer`, `cron`) 검증
- 더 긴 cycle/time window에서 반복 안정성 검증

실행 단계:

1. 케이스별로 독립 실행하고 케이스별 `run.log` 저장
2. `phases.log`에 케이스 단위 `start/pass/fail` 기록
3. 전체 결과를 `extended-summary.json`으로 집계
4. 케이스 하나라도 `fail`이면 워크플로 실패 처리

실제 실행 명령(스크립트 발췌):

```bash
# 확장 스위트 실행
./scripts/impl/run-extended-suite.sh

# 케이스별 내부 호출
./scripts/impl/run-baseline.sh
./scripts/impl/run-rotation-recovery.sh
RUNNER_MODE=systemd-timer ./scripts/impl/run-harness-smoke.sh
RUNNER_MODE=cron ./scripts/impl/run-harness-smoke.sh
./scripts/impl/run-ca-key-rotation-recovery.sh
./scripts/impl/run-local-lifecycle.sh
```

## 로컬 사전검증 표준

푸시 전 `scripts/preflight/` 스크립트를 실행합니다.

CI 워크플로 동등 스크립트(`scripts/preflight/ci/`):

| 스크립트 | CI 워크플로 대응 |
| --- | --- |
| `scripts/preflight/ci/check.sh` | `ci.yml` → Quality Check |
| `scripts/validate-deploy-compose.sh` | `ci.yml` → Validate Deploy Compose |
| `scripts/validate-compose-instance-names.sh` | `ci.yml` → Validate Compose Instance Names |
| `scripts/validate-e2e-openssl-compat.sh` | `ci.yml` → Validate E2E OpenSSL Compatibility |
| `scripts/validate-e2e-leftover-check.sh` | `ci.yml` → Validate E2E Leftover Check |
| `scripts/validate-e2e-run-scope.sh` | `ci.yml` → Validate E2E Run Scope |
| `scripts/preflight/ci/deploy-no-build-smoke.sh` | `ci.yml` → Deploy Compose No-Build Smoke |
| `scripts/preflight/ci/test-core.sh` | `ci.yml` → test-core |
| `scripts/preflight/ci/e2e-matrix.sh` | `ci.yml` → test-docker-e2e-matrix |
| `scripts/preflight/ci/e2e-extended.sh` | `e2e-extended.yml` → run-extended |

`deploy-no-build-smoke.sh`만은 CI를 흉내 낸 스크립트가 아닙니다.
`Deploy Compose No-Build Smoke` 단계가 이 파일을 그대로 실행하므로 CI와
어긋날 수 없습니다.

로컬 전용 스크립트(`scripts/preflight/extra/`):

| 스크립트 | 설명 |
| --- | --- |
| `scripts/preflight/extra/agent-scenarios.sh` | 에이전트 시나리오 |
| `scripts/preflight/extra/cli-scenarios.sh` | CLI 시나리오 |

전체 실행:

```bash
scripts/preflight/run-all.sh
```

로컬에서 `sudo -n`이 불가능하면:

- `scripts/preflight/ci/e2e-matrix.sh --skip-hosts`을 실행합니다.
- 이유: `hosts` 케이스는 실행 중 호스트 머신의 `/etc/hosts`를
  추가/복원해야 하며, 이 작업은 비대화식 관리자 권한(`sudo -n`)이
  필요합니다.

이는 로컬 제약 우회용입니다. CI에서는 `hosts` 케이스도 실행됩니다.

`--skip-hosts`는 매트릭스 실행 두 개가 한 호스트를 공유하게 해 주는 방법이기도
합니다. 매트릭스는 자신의 단계를 순서대로 실행하므로 한 실행이 스스로와 충돌할
일은 없지만, 첫 번째 실행이 `hosts` 단계 안에 있는 동안 두 번째 실행이 그 단계에
닿으면 기다리지 않고 잠금에서 거부됩니다. 나머지 단계는 모두 실행별 범위를
가지므로 영향을 받지 않습니다.

하네스는 호스트 도구 세 가지를 전제하며, 각 검사는 실행 도중이 아니라
사전 조건 블록에서 실패합니다.

- `run-reinit-recovery.sh`, `run-stepca-san.sh`,
  `run-openbao-tls-no-delta.sh`, `run-openbao-tls-reown.sh`의 bind host
  가드는 `ip`(iproute2)로, 없으면 `ifconfig`로 로컬 IPv4 주소를
  열거합니다. 둘 다 없는 호스트에는 그 사실을 그대로 알립니다.
  열거 자체가 불가능한 검사는 `OPENBAO_BIND_HOST` /
  `STEPCA_BIND_HOST`를 어떤 값으로 바꿔도 통과하지 않기 때문입니다.
  두 변수의 기본값 `172.17.0.1`은 Linux의 Docker 브리지 게이트웨이이며,
  그 인터페이스가 없는 환경(예: Docker Desktop)에서는 호스트가 실제로
  가진 주소로 지정합니다.
- `run-remote-lifecycle.sh`는 원격 에이전트의 TOML 설정을 `tomllib`으로
  읽으므로 `python3`이 3.11 이상이어야 합니다. 사전 조건 블록에서
  컨테이너를 띄우기 전에 import를 확인합니다.
- `PATH`에서 찾은 `openssl`은 `x509 -ext`를 지원해야 합니다.
  `run-stepca-san.sh`가 step-ca의 `subjectAltName`을 이 옵션으로 읽기
  때문입니다. 이 옵션은 OpenSSL 1.1.1에서 추가되었고, macOS가
  `/usr/bin/openssl`로 제공하는 LibreSSL 3.3.6에는 없습니다. 검사는
  구현체 이름이 아니라 옵션 지원 여부를 확인하며 찾은 실행 파일 경로를
  함께 알립니다. 해결 방법은 해당 옵션을 지원하는 `openssl`이 있는
  디렉터리를 `PATH` 앞에 두는 것입니다. `-ext`를 실제로 호출하는
  스크립트는 하나뿐이지만 `openssl`을 검사하는 여섯 스크립트가 모두 이
  검사를 수행합니다. 매트릭스의 모든 단계가 같은 호스트에서 실행되기
  때문입니다.

## init 자동화 입출력 규칙

라이프사이클 스크립트는 `bootroot init --summary-json` 출력으로 자동화를
수행합니다. 사람용 요약 텍스트를 파싱해 토큰/시크릿을 추출하지 않습니다.
로컬 CLI 시나리오 실행도 같은 방식으로 `--summary-json`의 `.approles[]`에서
런타임 AppRole 자격증명을 사용합니다.
이 절차는 **테스트/자동화 편의용 규칙**이며, 운영 환경의 토큰 보관 정책을
대체하지 않습니다.

E2E가 사용하는 최소 머신 필드:

- `.approles[]` 항목 중:
  - `runtime_service_add` (`role_id`, `secret_id`)
  - `runtime_rotate` (`role_id`, `secret_id`)

E2E에서 OpenBao 언실/런타임 인증 사용 방식:

- E2E는 보통 `init` 단계에서 한 번 언실한 뒤 같은 실행 동안 재언실하지 않음
- 다시 언실이 필요한 경우는 OpenBao가 다시 `sealed` 상태가 되었을 때뿐임
  (예: 프로세스/컨테이너 재시작, 수동 seal, 복구 절차)
- 런타임 AppRole 자격증명은 `init-summary.json`의 `approles`에서 읽어
  `--auth-mode approle`로 `service add`/`rotate`에 전달
- 테스트 스크립트는 자격증명을 장기 저장하지 않고 실행 컨텍스트 변수로만 전달
- 요약 JSON 파일에는 root token/AppRole secret_id 등 민감 필드가 포함되므로
  아티팩트 보관 시 민감정보로 취급해야 함

운영 가이드:

- init summary JSON은 민감 아티팩트로 취급
- 로그에 원문 시크릿 출력 금지
- 시크릿 파일/디렉터리 권한 `0600`/`0700` 유지

## 원격 bootstrap 검증 기준

이 섹션의 목적은 "원격 bootstrap이 실제로 반영되었는지"를 E2E에서 어떤 기준으로
판정하는지 명확히 정의하는 것입니다.

검증 흐름:

1. control node의 `bootroot service add --delivery-mode remote-bootstrap`가
   목표 상태를 기록합니다.
2. remote node의 `bootroot-remote bootstrap`이 해당 상태를 읽어 로컬 파일/설정에
   반영합니다.
3. E2E는 bootstrap summary JSON 출력에서 모든 항목이 `applied`인지 확인합니다.

검증 항목(서비스별):

- `secret_id`
- `eab` (운영자가 EAB 자격증명을 프로비저닝하지 않은 경우 `skipped`로
  보고됩니다. 번들된 OSS step-ca 구성에서는 이것이 기본 동작입니다.)
- `responder_hmac`
- `trust_sync`

판정 규칙:

- 필수 bootstrap 항목은 summary 출력에서 `applied`, `unchanged`, 또는
  `skipped`(EAB만) 중 하나여야 함
- 회전 후 재반영이 정상 완료되어야 함 (회전/복구 매트릭스에서는 `bootstrap`
  사용, 운영 환경에서는 실행 중인 에이전트가 fast-poll로 `secret_id`/trust를
  자가 치유하고 `apply-secret-id` / 재-bootstrap은 오프라인 복구 경로)
- 하나라도 `failed`이면 해당 단계를 실패로 처리함

## E2E `phases.log` 형식

E2E 스크립트는 단계 진행 상태를 `phases.log` 파일로 남깁니다.
아래는 그 파일에 기록되는 이벤트 JSON 형식입니다.

라이프사이클 스크립트는 다음 형식으로 기록합니다.

```json
{"ts":"2026-02-17T04:49:01Z","phase":"infra-up","mode":"no-hosts"}
```

필드:

- `ts`: UTC 타임스탬프
- `phase`: 단계 식별자
- `mode`: 해석 모드(`no-hosts` 또는 `hosts`)

확장 스위트는 다음 형식으로 기록합니다.

```json
{"ts":"2026-02-17T04:49:01Z","phase":"runner-cron","status":"pass"}
```

필드:

- `ts`: UTC 타임스탬프
- `phase`: 케이스 식별자
- `status`: `start|pass|fail`

## 아티팩트 경로

일반 운영자 관점에서는 필수 정보가 아닙니다.  
CI 실패를 직접 디버깅하는 운영자/기여자 관점에서는 유용한 정보입니다.

PR 필수 아티팩트 예시:

- `tmp/e2e/ci-local-no-hosts-<run-id>`
- `tmp/e2e/ci-local-hosts-<run-id>`
- `tmp/e2e/ci-remote-no-hosts-<run-id>`
- `tmp/e2e/ci-remote-hosts-<run-id>`
- `tmp/e2e/ci-rotation-<run-id>`

확장 아티팩트 예시:

- `tmp/e2e/extended-<run-id>` (케이스별 하위 디렉터리 포함:
  `ca-key-recovery/`, `infra-lifecycle/` 등)

## 실패 점검 순서

실패 시 다음 순서로 확인하세요.

1. `phases.log` (어느 단계에서 멈췄는지)
2. `run.log` (상위 실행 흐름)
3. `init.raw.log` / `init.log` (init 단계 상세)
4. `compose-logs.log` 또는 케이스별 로그 (컨테이너 상세)
5. `extended-summary.json` (확장 스위트 케이스 상태)
