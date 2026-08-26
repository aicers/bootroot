# 운영

이 섹션은 운영 체크리스트와 장애 대응 절차에 집중합니다. 설치/설정은
**설치**와 **설정** 섹션을 참고하세요.
CLI 명령 자체는 [CLI 문서](cli.md)를 참고하세요.

CI/테스트 운영 기준은 [CI/E2E](e2e-ci.md)를 참고하세요.

## 자동화 경계(필독)

bootroot 자동화 범위:

- 설정/산출물 생성 및 갱신(`[openbao]` fast-poll 섹션을 포함한
  `agent.toml`, 서비스별 AppRole 자격증명 파일, `eab.json`, `init`가
  생성하는 인프라 OpenBao Agent 설정, bootstrap 관련 파일)
- 서비스 추가 시 전달 모드별 상태 기록과 bootstrap 입력 준비
- rotate/verify/status 등 운영 명령 실행 흐름 제공

운영자 책임 범위:

- 바이너리 설치/업데이트(`bootroot`, `bootroot-agent`, `bootroot-remote`,
  OpenBao Agent)
- 프로세스 상시 실행 보장(시작/재시작/부팅 시 자동 시작)
- 실행 환경 구성(예: `docker compose` 서비스 정의, `systemd` 유닛/타이머 등록)
  및 부팅 후 자동 시작/재시작 정책 적용

운영 원칙:

- 상시 실행/재시작/의존성 요건은 운영자가 직접 충족해야 합니다.
- 어느 경로든 bootroot가 전체 런타임 생명주기를 완전 관리하지는 않습니다.

## 운영 기본 점검 루틴

운영자는 아래 명령을 주기적으로 실행해 상태를 빠르게 점검할 수 있습니다.

```bash
bootroot status
bootroot verify --registration-id <service> --db-check
bootroot service info --registration-id <service>
bootroot monitoring status
```

- `bootroot status`: OpenBao/step-ca/상태 파일 기준의 전체 상태 확인
- `bootroot verify --registration-id <service> --db-check`:
  비대화형으로 발급/검증/DB/리스폰더 연동 점검
- `bootroot service info --registration-id <service>`:
  서비스별 전달 모드 등 현재 상태 확인
- `bootroot monitoring status`: Prometheus/Grafana 컨테이너 상태 확인

## bootroot-agent

- 발급/검증/훅 결과 로그를 모니터링합니다.
- 키/시크릿 권한이 `0600`/`0700`으로 유지되는지 확인합니다.
- 갱신 후 리로드가 필요하면 **설정**의 훅을 사용합니다.
  서비스 온보딩 시
  `bootroot service add --reload-style`/
  `--reload-target`(프리셋) 또는
  `--post-renew-command`/`--post-renew-arg`(저수준)로
  훅을 설정할 수 있으며, 이 플래그들은 관리 대상
  `agent.toml` 프로필에
  `[profiles.hooks.post_renew]` 항목을 기록합니다.
- mTLS를 사용하는 서비스는 CA 번들을 읽을 수 있어야 합니다
  (예: `trust.ca_bundle_path`).

## step-ca + PostgreSQL

- PostgreSQL을 정기적으로 백업합니다.
- 복구 테스트를 사전에 수행합니다.
- 백업 저장소 접근 권한을 최소화합니다.

## HTTP-01 리스폰더

- step-ca에서 리스폰더 80 포트에 접속할 수 있어야 합니다.
- 에이전트가 리스폰더 관리자 API(기본 8080)에 접근 가능해야 합니다.
- `acme.http_responder_hmac`와 동일한 시크릿을 사용합니다.
- systemd로 80 포트를 바인딩하려면 root 권한 또는
  `cap_net_bind_service` 설정이 필요합니다.

## OpenBao

- OpenBao **seal 상태**를 정기적으로 확인합니다.
- unseal keys와 root token은 안전한 보관소에 분산 보관합니다.
- AppRole/정책은 최소 권한 원칙으로 구성합니다.
- KV v2 경로를 백업/스냅샷 정책에 포함합니다.
- 시크릿 회전 시 bootroot-agent/step-ca 재시작 또는 리로드 정책을 확인합니다.

### 감사 로깅

파일 기반 감사 백엔드는 `openbao/openbao.hcl`에 선언되어 있으며
OpenBao 컨테이너 시작 시 자동으로 활성화됩니다. 감사 로그는 모든
OpenBao API 요청(인증, 시크릿 읽기/쓰기, 정책 변경)을 기록하며,
사후 조사에 필수적입니다.

`bootroot init`은 감사 백엔드가 활성 상태인지 확인합니다. 파일 감사
장치가 없는 경우(예: `openbao.hcl`에서 감사 스탠자가 제거되었거나
`openbao-audit` 볼륨이 마운트되지 않은 경우) init은 실패합니다.
감사 설정을 복원한 후 init을 다시 실행하세요.

- **로그 위치 (컨테이너 내부):** `/openbao/audit/audit.log`
- **호스트 접근:** 일반 호스트에서 로그는 `openbao-audit` Docker 볼륨에
  저장됩니다. `docker compose exec openbao cat /openbao/audit/audit.log`으로
  확인할 수 있습니다.
- **프로비저닝된 레지스트라 엔드포인트 호스트에서의 호스트 접근:** 감사
  장치는 대신 공용 감사 저장소에 기록하며, 호스트 경로는
  `<audit_store_dir>/openbao/audit.log`입니다. 컨테이너 경로는 동일한
  경로의 bind mount이므로 위의 `docker compose exec` 방법은 그대로
  동작합니다. 이는 `state.json`의 `registrar_endpoint.enabled`와 데몬
  설정의 `[registrar_endpoint] enabled`가 **일치**할 때만 적용됩니다.
  두 값이 다르면 `bootroot init`이 진행을 거부하고 감사 로그는 있던
  자리에 그대로 남습니다. 저장소가 프로비저닝되기 전에 기록된 항목은
  `openbao-audit` 볼륨에 그대로 남아 이전과 같이 읽을 수 있으며, 무엇도
  이를 옮기지 않습니다. 아래 [공용 감사 저장소](#공용-감사-저장소)를
  참고하세요.
- **로테이션:** OpenBao는 감사 로그를 자체적으로 로테이션하지 않습니다.
  외부 로그 로테이션 도구(예: bind-mount의 `logrotate` 또는 볼륨을
  tail하는 사이드카)를 사용하고, 로테이션 후 OpenBao 프로세스에
  `SIGHUP`을 보내 파일 핸들을 다시 열도록 합니다.
- **확인:** `docker compose exec openbao bao audit list`로 감사 장치가
  활성 상태인지 확인합니다.

#### 레지스트라 동사 속도 제한 {#registrar-verb-rate-limiting}

이 빌드에서 bootroot는 레지스트라 동사 요청을 처리하지 않으므로, 아직
이 버킷에 도달하는 호출은 없습니다. 속도 제한기는 동사의 구성 의존성이며
동사를 요청 핸들러에 연결하는 변경과 함께 도착합니다. 아래 네 개의 키는
지금도 로드되고 검증됩니다.

레지스트라의 `mint`/`deregister` 동사는 호출이 도착할 때 한 줄, 끝날 때
한 줄씩 감사 레코드를 남기며 거부된 호출도 예외가 아닙니다. 이는 공짜가
아닙니다. 거부되는 호출을 대량으로 밀어 넣는 호출자는 레코드 저장소를
키우고, 파일시스템이 가득 차는 것은 단순히 파일이 커지는 문제가
아닙니다. 이후의 모든 mint가 거부되고, 위의 OpenBao 파일 감사 장치는
**필수**이며 OpenBao는 감사를 남기지 못하는 요청을 실패시키므로,
재시작해서는 안 되는 그 호스트에서 OpenBao 자체가 요청을 처리하지
못하게 될 수 있습니다.

이를 막기 위해 클라이언트 신원별·동사별로 토큰 버킷 두 개를 둡니다.

- **`predecision_refusal`** — 레지스트라의 순수 로컬 검사만으로 거부되는
  호출입니다. 잘못된 `service_name`이나 `host`, 예약된 이름, 설정되지
  않은 컴포넌트, 맞지 않는 인스턴스 형태, 어긋나게 다시 진술된 스펙,
  범위를 벗어난 `wrap_ttl` 등이 여기에 속합니다. OpenBao 작업에 전혀
  닿지 않으므로 호출자가 만들 수 있는 가장 값싼 트래픽이며, 대량 공격이
  타는 경로입니다.
- **`admission`** — 그 검사를 통과해 OpenBao에 닿을 수 있는 호출입니다.
  결과가 무엇으로 판명되든 이 버킷입니다.

**이 분리가 보장하는 것과 보장하지 않는 것.** `predecision_refusal`
경로의 대량 공격은 `admission` 예산을 소모할 수 없습니다. 즉 유효한
입력도 OpenBao 비용도 없는 공짜 경로가 정상적인 mint를 굶길 수
없습니다. 반면 형식이 올바르고 파생 가능한 요청을 만들 수 있는 호출자는
결국 거부로 끝나는 호출로 `admission` 예산을 소모할 수 있습니다. 레코드를
쓰기 전에는 그런 호출과 진짜 mint를 구별할 방법이 없기 때문입니다. 이
잔여 위험은 이 메커니즘이 아니라 공격 비용으로 제한됩니다. 그런 시도는
토큰뿐 아니라 OpenBao 작업까지 소모합니다.

**호출자에게 보이는 것.** 제한은 *레코드*를 억제할 뿐 *답*을 바꾸지
않습니다. `predecision_refusal` 버킷에서 제한된 호출은 자기 입력이
받아야 할 거부를 그대로 — 같은 오류, 같은 분류로 — 돌려받고 감사 레코드
두 줄만 생략됩니다. `admission` 버킷에서 제한된 호출은 아예 시도되지
않습니다. 잠금을 잡지 않고 OpenBao를 호출하지 않으며, 초 단위 정수
`retry_after`를 담은 재시도 가능 거부 `RegistrarBusy`를 받습니다. 이
값은 결정적이므로, 동시에 여러 요청을 띄우는 호출자는 자기 쪽에서 지터를
넣어 재시도해야 합니다.

어느 쪽이든 데몬은 억제한 호출을 버킷별로 하나씩, 기동 이후 누적으로
셉니다. 다만 이 두 값은 아직 데몬의 메모리 안에만 있고 운영자가 읽을
수 있는 표면이 없습니다. 이를 보고하는 곳도 없고, 이 빌드에서는 버킷에
가산되는 호출 자체가 없습니다. 읽을 수 있게 되면 합계가 아니라 두 값을
따로 읽으세요. `predecision_refusal`이 오르는 것은 누군가 잘못된 입력을
대량으로 밀어 넣고 있다는 뜻이며 그 호출자들은 여전히 진짜 답을 받고
있습니다. `admission`이 오르는 것은 정상 트래픽이 막히고 있다는 뜻이며
진행 중인 브링업이 지연되고 있을 수 있습니다.

제한된 호출이 남기는 것은 이 카운터뿐입니다. 데몬 저널을 포함해 제한된
호출마다 기록되는 것은 아무것도 없습니다. 호출마다 로그 한 줄을 남기면
밀려드는 요청 하나하나가 무제한 쓰기 하나가 되어, 버킷이 없앤 디스크
압박을 그대로 되돌려 주기 때문입니다. 그러므로 진행 중인 폭주를 저널에서
찾으려 하지 마세요. 그 가시성은 카운터를 운영자가 읽을 수 있게 될 때 함께
옵니다.

**설정 키 네 개**는 `agent.toml`의 `[registrar]` 테이블에 있습니다. 모두
부호 없는 정수이며, 속도는 분수 비율이 아니라 토큰당 밀리초 간격으로
표현합니다. 덕분에 설정 표면에 부동소수점 값이 하나도 없습니다. 네 키
모두 0은 로드 시점에 거부됩니다.

```toml
[registrar]
rate_limit_admission_burst = 512
rate_limit_admission_refill_interval_ms = 500
rate_limit_predecision_refusal_burst = 32
rate_limit_predecision_refusal_refill_interval_ms = 1000
```

- `rate_limit_admission_burst` (기본값 `512`) — 한 클라이언트 신원이
  지속 속도의 제약을 받기 전에 한 번에 밀어 넣을 수 있는 mint 수입니다.
- `rate_limit_admission_refill_interval_ms` (기본값 `500`) — admission
  토큰 하나가 쌓이는 밀리초 간격입니다. 기본값은 초당 두 건을
  지속합니다.
- `rate_limit_predecision_refusal_burst` (기본값 `32`) — 로컬에서 거부되는
  경로의 같은 값입니다. 이 경로의 정상적인 거부는 운영자의 오타가 하나씩
  도착하는 것이므로 훨씬 작습니다.
- `rate_limit_predecision_refusal_refill_interval_ms` (기본값 `1000`) —
  초당 거부 토큰 하나를 지속합니다.

**admission 버스트 산정.** 정상 상태에서 mint가 드물다는 감이 아니라,
가장 큰 *정상* 브링업 파도를 기준으로 잡으세요.

```text
rate_limit_admission_burst >= wave_hosts × modules_per_host
```

여기서 `wave_hosts`는 한 번에 올리는 호스트 수의 최댓값,
`modules_per_host`는 한 호스트에 올라가는 컴포넌트 수의 최댓값입니다.
기본값은 레퍼런스 배치의 실제 숫자입니다.

| 배치             | 호스트 | 모듈 | 한 파도의 mint | 필요한 버스트 |
|------------------|--------|------|----------------|---------------|
| 레퍼런스(기본값) | 64     | 8    | 512            | 512           |
| 더 큰 플릿       | 200    | 8    | 1600           | 1600          |

버스트보다 큰 파도도 거부되지 않고 완료되며, 다음 시간만큼 더 걸릴
뿐입니다.

```text
(mint 수 − 버스트) × rate_limit_admission_refill_interval_ms / 1000
```

기본값 기준으로, 1600건짜리 파도는 기본 버스트 512에 대해 약 544초를 더
씁니다. 자기 플릿의 숫자를 이 식에 넣어 보고, 첫 브링업 *뒤*가 아니라
*앞*에서 버스트를 올리세요.

버킷은 메모리에만 존재하고 가득 찬 상태로 시작하므로, 재시작한 데몬은
곧바로 한 파도를 전부 흡수하며 제한 상태는 재시작을 넘어 남지 않습니다.
버킷의 키는 도착한 그대로의 호출자 신원이므로, 재접속으로 예산을
되돌릴 수 없습니다.

### 공용 감사 저장소

데몬의 레지스트라 동사 레코드와 OpenBao의 파일 감사 장치는 bootroot
호스트의 한 디렉터리를 공유합니다. `bootroot-agent` 설정 파일의
`[registrar] audit_store_dir`이 그 디렉터리 위치에 대한 **유일한
정의**입니다. `state.json`도, 플래그도, 환경 변수도 그 값을 따로
기록하지 않습니다. 서로 어긋날 수 있는 두 값은 결국 두 개의 디렉터리가
되기 때문입니다.

이 빌드에서는 `audit_store_reserve_bytes`를 강제하는 것이 없습니다.
설정된 예약량은 기록된 숫자일 뿐, 파일 시스템이 공간을 확보해 준다는
보장이 아닙니다.

**설치 측에서 값을 읽는 방법.** `bootroot init --agent-config <path>`는
운영자의 `bootroot-agent` 설정 파일을 지정합니다. `init`이 내부 자격
증명 디렉터리에 생성하는 bootroot 내부용 `agent.toml`이 아닙니다.
`init`은 이 파일에서 정확히 두 테이블만 읽습니다. 저장소 위치를 위한
`[registrar]`와, `state.json`과 교차 확인할 활성화 값을 위한
`[registrar_endpoint]`입니다. 이 플래그는 `state.json`이 레지스트라
엔드포인트를 활성으로 기록한 실행과, 렌더링된 audit compose 오버라이드가
디스크에 존재하는 실행에서 **필수**입니다. 그런 실행에서 플래그를
생략하면 오류이며 아무것도 생성·렌더링·삭제되지 않습니다. 따라서 데몬의
설정 파일이 그런 실행보다 먼저 존재해야 합니다.

**`bootroot init`이 하는 일.** 엔드포인트가 활성인 호스트에서
`audit_store_dir`과 그 아래의 `records/`, `openbao/`를 생성하고,
`<audit_store_dir>/openbao`를 `/openbao/audit`에 바인딩하는 Compose
오버라이드를 렌더링한 뒤 OpenBao를 그 위로 재생성합니다. 이 실행은
**반드시 root여야 합니다.** `audit_store_dir`과 `records/`는 uid 0
소유에 모드 `0700`이며, 그것이 권한 없는 프로세스가 기록을 읽지 못하게
하는 장치입니다. 저장소를 프로비저닝할 실행이 uid 0이 아니면, 아무것도
생성하거나 렌더링하기 전에 그 사실을 지목하며 거부합니다. 그러지 않으면
디렉터리가 실행한 사용자 소유로 만들어지고, 나중의 root 실행이 그것을
다른 소유자의 것이라며 거부하되 고치지는 않기 때문입니다. `openbao/`는
OpenBao 컨테이너의 entrypoint에 맡겨지며, 첫 기동 시 그 소유권을
가져갑니다.

**저장소 위의 모든 디렉터리는 world-traversable해야 합니다.** `bootroot
init`은 `audit_store_dir` 위의 기존 경로 구성요소가 모두 심볼릭 링크가
아닌 디렉터리이고 world-execute 비트를 가질 것을 요구하며, 없는 것은
`0755`로 생성합니다. 그래야 권한 없는 `bootroot infra up`이 저장소
내부로 들어가지 않고도 `audit_store_dir`에 도달해 검사할 수 있습니다.
`o+x`가 없는 상위 디렉터리는 그 디렉터리를 지목하는 오류이며, 그런
실행에서는 아무것도 생성되거나 렌더링되지 않습니다.

**두 명령 모두 저장소를 고치지 않습니다.** `bootroot init`은 기존
`audit_store_dir`과 `records/`를 위 계약에 비추어 검사하고, 경로와 발견한
상태, 그리고 이를 고치는 `chown 0:0` / `chmod 0700`을 알리며 실패합니다.
`bootroot infra up`은 `audit_store_dir`만 검사하며, 아무것도 만들지 않고
아무것도 고치지 않습니다.

**프로비저닝된 저장소를 옮기는 절차**는 수동입니다. 마운트를 조용히 다시
가리키면 이전 감사 기록이 남겨지기 때문입니다.

1. 스택을 중지합니다.
2. 디렉터리를 새 경로로 옮깁니다.
3. `[registrar] audit_store_dir`을 갱신하고 렌더링된 오버라이드
   `secrets/openbao/docker-compose.openbao-audit.yml`을 삭제합니다.
4. root로 `bootroot init`을 `--agent-config`와 함께 다시 실행합니다.

**레지스트라 엔드포인트 호스트를 끄는 절차**는 두 번의 수정이 필요하며,
두 값이 일치하기 전까지 `bootroot init`은 거부합니다.

1. 데몬 설정 파일에서 `[registrar_endpoint] enabled = false`로 설정합니다.
2. `state.json`의 `registrar_endpoint.enabled`를 `false`로 설정합니다.

기록된 술어가 `false`가 되는 즉시 bring-up은 audit 오버라이드를 적용하지
않으므로, OpenBao는 다음 재생성 때 `openbao-audit` 볼륨으로 돌아갑니다.
렌더링된 오버라이드는 두 출처가 `false`로 일치하는 것을 확인한 `init`이
삭제할 때까지 디스크에 비활성 상태로 남습니다. 그 마지막 실행에도
`--agent-config`가 필요합니다. 렌더링된 오버라이드가 있는 한 플래그는
필수이기 때문입니다. **저장소의 디렉터리와 그 내용은 이 과정에서 결코
건드리지 않습니다.** 호스트를 끄는 것은 무엇이 마운트되는지를 바꿀 뿐,
무엇이 저장되어 있는지를 바꾸지 않습니다. 삭제는 수동입니다.

## 모니터링 운영

- `bootroot monitoring up --profile lan|public`으로 모니터링 컨테이너를 기동합니다.
- `bootroot monitoring status`는 실행 중 프로필의 컨테이너 상태와 Grafana URL/관리자 비밀번호 상태를 출력합니다.
- `bootroot monitoring down`으로 모니터링 컨테이너를 중지/삭제합니다.
- Grafana 관리자 비밀번호를 초기 상태로 되돌리려면
  `bootroot monitoring down --reset-grafana-admin-password`를 사용합니다.

## Compose 운영 절차(권장)

- 워크로드 컨테이너와 인프라 OpenBao Agent 컨테이너
  (`openbao-agent-stepca`, `openbao-agent-responder`)가 상시 실행
  상태인지 확인합니다.
- `restart: always` 또는 `restart: unless-stopped` 정책을 명시합니다.
- 호스트 재부팅 후 자동 기동되도록 Docker/Compose 서비스 자체를
  systemd 등으로 관리합니다.
- 기본 점검 순서:
  `docker compose ps` -> `docker compose logs --tail=200 <service>`
  -> `bootroot verify --registration-id <service>`.

## systemd 운영 절차(bootroot-agent 권장)

`bootroot-agent`는 오직 **호스트 데몬**으로만 실행됩니다 — Docker
사이드카로 실행하지 않습니다. 두 전달 모드 모두에서 fast-poll 루프가
유일한 시크릿 전달 메커니즘입니다(서비스별 OpenBao Agent는 실행되지
않습니다). 한 호스트는 **서로 다른 서비스마다** `bootroot-agent`
프로세스 하나와 agent 구성 하나를 실행합니다 — 아래의 "서로 다른 서비스
여러 개" 항목을 참고하세요.

- `bootroot-agent`를 long-running 서비스로 등록하고 `Restart=on-failure`,
  `WantedBy=multi-user.target`를 적용합니다.
- `bootroot service add`가 출력한 실행 명령을 `ExecStart`로 사용합니다:
  `bootroot-agent --config <agent.toml> --eab-file <eab.json>`.
  **EAB 회전이 적용되려면 `--eab-file`이 필수입니다** — 없으면 EAB KV
  갱신과 `rotate eab-clear`가 해당 에이전트에서 조용히 무시됩니다.
- (remote-bootstrap) 초기 설정 시 서비스별로 `bootroot-remote bootstrap`을 1회 실행합니다.
  이후 *실행 중인* 에이전트는 스스로 최신 상태를 유지합니다: fast-poll
  루프가 자신의 `secret_id`를 갱신하고 OpenBao KV에서 trust를 다시
  렌더링하므로 수동 작업이 필요 없습니다. `bootroot-remote apply-secret-id`는
  `secret_id_ttl`을 넘겨 오프라인 상태였던(자격증명이 이미 만료되어 스스로
  갱신할 수 없는) 에이전트를 복구할 때만 필요합니다.
- **한 호스트에서 서로 다른 서비스 여러 개**: 서비스마다 `bootroot-agent`
  하나와 agent 구성 하나를 사용하며, 각각 자체 `[openbao]` 자격증명과
  고유한 `state_path`를 가집니다. 서로 다른 서비스는 하나의 구성을 공유할
  수 없습니다 — `[openbao]` 섹션은 AppRole 자격증명을 하나만 담고 fast-poll
  루프는 한 번만 로그인해 그 토큰으로 모든 서비스의 KV를 읽으므로,
  서비스별 AppRole 정책 아래에서는 교차 서비스 읽기가 `403`을 반환합니다.
  로컬 `service add`는 이를 강제합니다: 다른 서비스에 이미 등록된
  `--agent-config` 경로로 추가하면 거부됩니다.
  두 프로비저닝 경로 — 로컬 `service add`와 `bootroot-remote bootstrap`
  — 모두 기본 제공하는 `state_path` basename을 서비스 이름 기반으로
  설정하므로 서비스별 구성이 fast-poll 상태 파일 충돌 없이 한 디렉터리를
  공유할 수 있으며, bootstrap은 추가로 두 sibling 구성이 여전히 같은
  `state_path`로 해석되면 경고합니다. `docs/ko/remote-bootstrap.md`를
  참고하세요.
- 점검 순서:
  `systemctl status <unit>` -> `journalctl -u <unit> -n 200`
  -> `bootroot verify --registration-id <service>`.

### 하드닝된 systemd 유닛 예시

데몬을 전용 비루트 계정으로, 파일시스템 접근을 최소화해 실행하세요.
`service add`는 데몬의 입력 파일 — `agent.toml`, `role_id`,
`secret_id`, `eab.json` — 을 실행한 사용자(보통 root) 소유의 소유자
전용(`0600`) 파일로 기록하므로, 유닛에는 첫 시작 전에 이 파일들의
소유권을 한 번 넘겨받을 **고정** 시스템 계정이 필요합니다.
`DynamicUser=yes`는 여기서 동작하지 않습니다: UID가 시작할 때마다
할당되므로 미리 프로비저닝된 영속 파일을 재시작 간에 소유할 수 없고,
디렉터리 그룹 권한만으로는 `0600` 파일을 읽을 수 없습니다.

`service add` 후 1회 준비 작업(경로는 아래 예시 유닛과 일치):

```sh
useradd --system --user-group --no-create-home \
  --shell /usr/sbin/nologin bootroot-agent
chown -R bootroot-agent:bootroot-agent \
  /etc/bootroot /opt/edge-proxy-mtls /srv/bootroot/secrets/services/edge-proxy
```

`ReadWritePaths=`에는 같은 세 위치만 필요합니다: agent 설정 디렉터리
(`agent.toml`과 fast-poll 상태 파일 `bootroot-agent-state-<svc>.json`이
여기에 있음), 인증서 출력 디렉터리(발급된 인증서와 관리되는
`ca-bundle.pem`), 서비스별 시크릿 디렉터리(`role_id`, `secret_id`,
`eab.json`). 세 위치 모두 읽기만이 아니라 쓰기 권한이 필요합니다:
fast-poll 루프가 `agent.toml`(responder HMAC), `secret_id`,
`eab.json`, `ca-bundle.pem`을 다시 쓰고, 갱신이 cert/key를 기록합니다.

```ini
[Unit]
Description=bootroot-agent certificate daemon
After=network-online.target
Wants=network-online.target

[Service]
User=bootroot-agent
Group=bootroot-agent
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/bootroot /opt/edge-proxy-mtls /srv/bootroot/secrets/services/edge-proxy
ExecStart=/usr/local/bin/bootroot-agent \
  --config /etc/bootroot/agent.toml \
  --eab-file /srv/bootroot/secrets/services/edge-proxy/eab.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

참고:

- 준비 작업의 `chown`은 회전 후에도 유지됩니다: `bootroot rotate
  approle-secret-id`는 `secret_id`를 기존 파일의 소유자/그룹을
  보존하면서 원자적으로 다시 쓰므로, root로 실행되는 예약 회전이
  non-root 데몬의 자격증명 접근을 차단하지 않습니다. 그 외의 모든
  갱신(`agent.toml`, `eab.json`, `ca-bundle.pem`, cert/key)은 데몬이
  자신의 계정으로 fast-poll을 통해 직접 기록합니다.
- 데몬의 자격증명 파일은 데몬 계정 소유의 `0600`으로 유지하세요. 다른
  프로세스가 소비하는 *출력물* — 발급된 cert/key와 관리되는
  `ca-bundle.pem` — 을 공유하려면 자격증명 파일 모드를 넓히지 말고
  `--cert-group`을 사용하세요.
- post-renew 훅은 이 데몬 프로세스 안에서 실행되므로 유닛의 권한이 훅이
  할 수 있는 일의 한계를 정합니다. `docker-restart`와의 상호작용은
  [컨테이너화된 소비 애플리케이션](#컨테이너화된-소비-애플리케이션)을
  참고하세요.

### 레지스트라 엔드포인트 (Linux 전용) {#registrar-endpoint-linux-only}

레지스트라 자체 컨트롤 플레인을 운영하는 호스트, 즉 **bootroot-host**
배포에서는 `bootroot-agent`가 레지스트라의 `mint`/`deregister` 동사를
호스트 로컬 소켓으로 제공하게 할 수 있습니다. Linux 전용이고, `AF_UNIX`
전용이며, systemd 소켓 활성화 전용입니다. 그 밖의 모든 배포는 기본값
그대로 비활성 상태로 둡니다.

활성화가 지원됩니다. 데몬은 `[registrar]` 설정으로 동사 계층을 만들고 그
위에 프로덕션 요청 핸들러를 등록하므로,
`registrar_endpoint.enabled = true`이면 데몬이 기동하여 요청을
처리합니다.

#### 활성화된 엔드포인트에 필요한 것, 그리고 빠졌을 때

핸들러를 만드는 데 필요한 모든 것은 작업을 하나라도 spawn하기 **전에**
해결됩니다. 따라서 없거나 사용할 수 없는 의존 대상이 있으면 그것을
지목하는 진단과 함께 실행 단위가 실패합니다. accept만 하고 답하지 못하는
소켓, 즉 모든 호출자를 무한 대기시키는 상태는 결코 만들지 않습니다.

- **배포 상태 파일** — `[registrar] state_file`에서 옵니다. 엔드포인트가
  활성화되면 **필수**입니다. 실패 시 키와 경로, 그리고 `openbao_url`과
  `kv_mount` 중 무엇이 없거나 비었거나 평문이었는지를 알려줍니다.
- **시크릿 디렉터리** — 상태 파일의 `secrets_dir`, 없으면 상태 파일 옆의
  `secrets`입니다. 실패 시 해석된 경로를 알려줍니다.
- **배포의 활성 루트** — `<secrets_dir>/certs/root_ca.crt`입니다. 실패 시
  어느 디렉터리 아래에서 읽었는지를 알려줍니다.
- **렌더링된 프로비저닝 설정** — `[registrar] provisioning_config_path`
  입니다. 실패 시 키와 경로를 알려주며, 다이제스트 불일치도 포함합니다.
- **내부 자격 증명** — 시크릿 디렉터리 아래의 고정 레이아웃입니다. 실패 시
  bootroot 내부 자격 증명이 없는지, 잘못됐는지, 배포가 폐기한 루트로
  발급됐는지를 알려줍니다.
- **감사 레코드 저장소** — `[registrar] audit_record_dir`입니다. 실패 시
  저장소와 그 디렉터리를 알려줍니다.

엔드포인트가 **비활성화된** 호스트는 이 중 어느 것도 열지 않습니다.
레지스트라 표면은 bootroot 자신이 도는 곳에만 존재하므로, 표면이 없는
것은 서비스 호스트의 정상 상태이지 결함이 아닙니다.

`SIGHUP`이 오면 데몬 실행 단위 전체가 다시 구성되므로 위 전부가 다시
읽힌 설정으로 재구성됩니다. listen 소켓은 그렇지 않으므로 소켓 inode는
그대로이고, `[registrar_endpoint] enabled`는 프로세스 수명 동안 고정된
채로 남습니다.

!!! warning "`mint`는 아직 제공할 수 없습니다"
    `deregister`는 끝에서 끝까지 처리됩니다. `mint`는 그렇지 않습니다.
    mint 요청은 `reload`와 `cert_group`이 불투명한 문자열인 `spec`을
    싣는데, 이 두 문자열의 와이어 표기법은 이 저장소 밖에서 소유하며
    아직 확정되지도, `docs/reference/registrar-wire-contract.md`에
    전사되지도 않았습니다. 확정되기 전까지 모든 mint는 동사가 실행되기
    전에 거부되고 — 응답 바이트 0, 정상 종료, 즉 엔드포인트가 디코딩할
    수 없는 페이로드에 주는 평소의 답 — 데몬은 어떤 변환이 실패했는지를
    로그로 남깁니다. 아무것도 발급되지 않으며, 어떤 표기도 추측하지
    않습니다.

#### 소켓과 그 소유자

`systemd`가 `/run/bootroot/registrar.sock`을 만들고 이름과 모드를
소유하며, 이미 listen 상태인 디스크립터를 fd 3으로 데몬에 넘깁니다.
`bootroot-agent`는 소켓을 bind·unlink·rename·`chmod`하지 않고, 경로를
지정하는 설정 키도 없습니다. 스스로 경로를 정할 수 있는 데몬은 보호되지
않은 경로를 향하게 만들 수도 있는 데몬이기 때문입니다.

기동 시 데몬은 `getsockname()`이 알려준 경로명을 검사합니다.

- 소켓 모드는 정확히 `0700`이어야 합니다.
- 소켓 소유자는 데몬의 실효 uid와 같아야 합니다.
- 소켓이 들어 있는 디렉터리도 같은 소유자여야 하고, group-write도
  other-write도 없어야 합니다. 이 검사는 비트마스크이므로 `0700`과
  배포 유닛의 `RuntimeDirectoryMode=0755`가 모두 통과합니다.

배포 유닛에서 그 uid는 0입니다. 모드가 다르거나, 소유자가 다르거나,
상위 디렉터리에 쓰기 권한이 열려 있거나, 디스크립터가 listen 중인
`AF_UNIX` 스트림이 아니거나, 주소가 파일시스템 경로명이 아니면 서비스를
시작하지 않고 진단 메시지와 함께 거부합니다.

이후 각 연결은 경로 메타데이터가 아니라 *연결된 소켓*의 피어 자격증명으로
인증합니다. 데몬의 실효 uid와 같은 uid를 가진 피어만 다음 단계로
넘어갑니다. 피어의 pid와 gid는 연결 진단 로그로만 남고 호출자 신원에는
포함되지 않습니다.

#### 누가 호출할 수 있고, 엔드포인트는 무엇을 제시하는가 {#who-may-call-and-what-the-endpoint-presents}

피어 검사가 답하는 것은 "이 호스트의 root인가"입니다. 그것은 동사가
실행될 때의 신원이 아니며, 마지막 검사도 아닙니다. 수락된 모든 연결은
이어서 상호 TLS로 감싸집니다.

- **엔드포인트가 제시하는 것**은 `[registrar_endpoint]
  server_cert_path`의 체인이고, 키는 `server_key_path`의 것이며, 데몬이
  기동 시점에 스스로 발급합니다.
  호출자는 배포의 신뢰 앵커를 핀으로 지정하고, 제시된 리프의 유일한 DNS
  SAN이 정확히
  `<instance>.bootroot-registrar-endpoint.<host>.<network.domain>`일 것을
  요구합니다.
- **클라이언트 인증서는 필수입니다.** 인증서는 `trust.ca_bundle_path`의
  핀으로 지정된 부분집합 — 번들 안에서 SHA-256이
  `trust.trusted_ca_sha256`에 있는 인증서들 — 으로 검증됩니다. 인증서를
  제시하지 않는 연결이나 체인이 검증되지 않는 연결은 요청 바이트를 단 하나도
  읽기 전에 **핸드셰이크에서 실패합니다**.
- **받아들이는 신원은 정확히 하나입니다.** 핸드셰이크가 끝나면 제시된
  리프의 유일한 DNS SAN이 레지스트라 클라이언트 신원,
  `<instance>.bootroot-registrar.<host>.<network.domain>`이어야 합니다. 두
  레이블 모두 `bootroot service add`가 거부하는 `bootroot-` 접두사 아래에
  있으므로, 운영자가 발급한 인증서로는 어느 이름도 만들어질 수 없습니다.
  배포 CA로는 검증되지만 그 신원이 *아닌* 인증서 — 예를 들어 레지스트라와
  같은 호스트에 발급된 일반 서비스 리프 — 는 거부됩니다. 응답 바이트는 0개,
  그리고 깨끗한 종료로, 다른 모든 동사 이전 거부와 똑같습니다.
- **동사가 보는 호출자**는 `registrar-client:<san>`이며, 피어 자격증명 값이
  동사에 도달하는 일은 없습니다.

연결을 열어 놓고 `ClientHello`를 보내지 않는 피어는 5초 뒤에 버려집니다.
인증되지 않은 피어가 16개의 연결 슬롯 중 하나를 계속 붙잡고 있을 수 없게
하기 위해서입니다.

#### 거부된 연결을 로그에서 읽기 {#reading-a-refused-connection-in-the-log}

**호출자는 자신이 왜 거부됐는지 아무것도 알지 못하므로, 진단은 데몬의
로그가 유일합니다.** 실패한 핸드셰이크는 호출자에게 TLS 경보로만 전달되고,
핸드셰이크 이후의 거부는 바이트 없는 깨끗한 종료로만 전달됩니다. 모든
로그 줄에는 그 연결의 나머지 줄들과 이어 볼 수 있게 해 주는 연결 id와
`reason` 필드가 들어 있습니다.

| `reason` | 무슨 일이 있었나 |
| --- | --- |
| `no-client-certificate` | 호출자가 클라이언트 인증서를 제시하지 않았습니다. |
| `client-chain-rejected` | 체인이 번들의 핀으로 지정된 부분집합으로 검증되지 않았습니다. |
| `handshake-timeout` | 제한 시간 안에 핸드셰이크가 완료되지 않았습니다. |
| `handshake-failed` | 그 밖의 이유로 핸드셰이크가 실패했습니다. |
| `no-peer-certificate` | 핸드셰이크는 끝났지만 신원을 알아볼 인증서가 없습니다. |
| `not-registrar-client` | 인증서는 검증됐지만 레지스트라 클라이언트 신원이 아닙니다. |
| `unauthorized-peer` | 피어의 uid가 데몬의 실효 uid가 아닙니다. |

#### 데몬이 기동 시점에 두 리프를 발급합니다 {#the-daemon-issues-both-leaves-at-start}

두 이름 모두 예약된 `bootroot-` 네임스페이스에 속하므로
`bootroot service add`가 어느 쪽도 거부합니다. 결국 이 이름들을 만들 수
있는 것은 bootroot 자신의 데몬뿐입니다. 기동 시, 엔드포인트의 TLS 자재를
로드하기 **전에**, `bootroot-agent`는 사용할 수 없는 리프를 발급해 각 리프와
키를 설정된 고유한 경로 쌍에 씁니다.

- `server_cert_path` / `server_key_path` — 엔드포인트가 제시하는 리프.
- `client_cert_path` / `client_key_path` — 레지스트라 자신의 클라이언트
  리프. **이 둘은 공개된 계약입니다.** 같은 호스트의 레지스트라 프로세스가
  이 파일들을 읽고, 프로비저닝 도구가 설치 시점에 *최초* 인증서를 여기에
  배치하며, 엔드포인트의 앵커 핀 파일
  `registrar-endpoint-anchors.sha256`은 이 인증서와 같은 디렉터리에서
  찾습니다. 인증서를 옮기면 핀 파일도 함께 옮겨집니다.

`enabled = true`일 때 네 경로는 모두 필수이며, 설정되지 않은 경로는 무엇을
읽거나 요청하기도 전에 설정 검증 시점에 거부됩니다.

발급은 bootroot 자신의 **bootroot-internal 특권 자격 증명** — `auth/cert`
에서 `OpenBao`에 인증하는 root 소유 신원 — 으로, 다른 모든 발급과 동일한
로컬 step-ca로의 아웃바운드 ACME 경로를 통해 이뤄집니다. 이 경로 어디에도
`AppRole`도, 만료되는 비밀도 없습니다. 엔드포인트가 **비활성화된** 호스트는
아무것도 발급하지 않고 아무것도 요청하지 않습니다.

**설정된 경로에 이미 있는 자재가 사용 가능하면 그대로 둡니다.** 두 파일이
존재하고, 읽을 수 있고, 파싱되며, 키가 리프와 맞고, DNS SAN이 정확히
하나이며 그것이 해당 쌍의 예약된 이름이고, `not_before`가 지났고
`not_after`가 지나지 않았으며, `trust.ca_bundle_path`가 설정되어 있다면 그
앵커까지 체인이 이어지는 경우입니다. 사용 가능한 쌍은 기동 시점에 결코
재발급하지 않습니다.

**그 밖의 모든 상태는 발급으로 복구합니다.** 조건마다 하나씩입니다. 없음,
읽을 수 없음, 파싱 불가, 키 불일치, SAN 불일치, 아직 유효하지 않음, 만료됨,
체인 이탈. 각각은 평범한 사고가 남기는 상태 — 쓰기 도중 전원이 끊긴 갱신,
두 rename 사이에서 죽은 갱신, `not_after`를 지나도록 내려가 있던 데몬,
파괴적인 신뢰 앵커 회전 — 이며, 거부하면 데몬이 실행되어야만 고칠 수 있는
상태에 호스트를 가둬버립니다.

다음 세 경우는 여전히 데몬 기동으로 이어지지 않습니다.

- **쓰기가 이뤄질 수 없는 경우**(경로가 디렉터리, 끊어진 심볼릭 링크,
  불변 파일, 데몬에게 없는 권한). 경로와 쓰기 오류를 밝히는 발급 실패입니다.
- **`trust.ca_bundle_path`를 쓸 수 없는 경우.** 읽을 수 없는 번들은
  *게시 이전에* 실패합니다. 데몬이 내용을 확인할 수 없는 번들을 덮어쓰기를
  거부하므로 리프는 쓰이지 않고 번들도 그대로입니다. 없는 번들과 파싱되지
  않는 번들도 같은 방식으로 판단되고 병합 자체는 둘 다 복구하겠지만,
  아웃바운드 ACME 클라이언트가 자신의 TLS를 같은 파일에 앵커하므로 먼저
  거부합니다. 세 경우 모두 번들을 밝히는 거부로 끝나며, 이는 엔드포인트가
  활성화된 호스트라면 어차피 도달하는 결과입니다. TLS 로더도 읽을 수 있고
  파싱되며 핀에 맞는 번들을 요구하기 때문입니다.
- **교체본이 이 호스트의 시계 기준으로 여전히 유효 기간 밖인 경우**(양방향
  모두). 발급은 성공했고, 그 뒤 TLS 로더가 원래 갖고 있던 거부가 기동을
  멈춘 것입니다.

이 발급이 쓰는 EAB와 HTTP-01 responder HMAC은 배포 `state.json`이 기록한
KV 마운트 아래의 `bootroot/agent/eab`와 `bootroot/responder/hmac`에서 같은
자격 증명을 통해 읽습니다. 그리고 리프를 실제로 발급해야 할 때에**만**
읽으므로, 자재가 멀쩡한 호스트는 `OpenBao`가 내려가 있어도 기동합니다.
`agent.toml` 자신의 `[acme] http_responder_hmac`이나 `[eab]`로 대체하지
않으며, 읽은 값을 디스크에 되쓰지도 않습니다. 신뢰 회전 구간에서 발급이
필요한 기동은 자격 증명 자신의 복구 진단과 함께 거부됩니다. 회전을 끝내는
것이 해결책입니다.

**이미 만료된 리프는 그 기동 시점에**, TLS 자재를 로드하기 전에
복구합니다. 데몬의 첫 갱신 틱이 아닙니다. 첫 틱까지 미루면 복구하려고 수행한
바로 그 재시작에서 활성화된 엔드포인트가 리드 타임 내내 서비스를 하지 못한
채 남습니다. 누가 복구하는가는 그대로입니다. `bootroot-agent`이며, 호스트
재프로비저닝은 아닙니다.

#### TLS 자재에 대한 기동 거부 {#startup-refusals-for-the-tls-material}

엔드포인트가 활성화된 상태에서 데몬은 다음의 경우 문제가 된 설정 키를,
그리고 그 설정에 값이 있으면 설정된 경로까지 밝히면서 기동을 거부합니다.
`server_cert_path`·`server_key_path`·`client_cert_path`·`client_key_path`
중 하나라도 없을 때, 발급 자체가 실패했을 때, 인증서 파일이 발급자 체인
없이 리프만 담고 있거나 `trust.trusted_ca_sha256`에 핀으로 지정된
인증서까지 올라가지 못하는 체인을 담고 있거나 앵커가 만료됐거나 아직
유효하지 않거나 CA가 아닐 때, 그리고 `trust.ca_bundle_path`가 없거나 읽을
수 없거나 파싱할 수 없거나 핀에 맞는 인증서를 하나도 담고 있지 않을 때입니다.

설정된 경로에 *있는* 자재가 없음·읽을 수 없음·파싱 불가·키 불일치·SAN
불일치인 경우는 더 이상 이 목록에 없습니다. 위에서 설명한 대로 각각 발급으로
복구됩니다.

체인 요구 사항은 그러지 않았다면 로컬에 아무 증상도 남기지 않았을 실패를
잡아냅니다. 호출자는 서버가 제시한 인증서들 중에서 신뢰 앵커를 고르므로,
리프만 담긴 파일은 데몬이 멀쩡해 보이는 동안 올바르게 설정된 모든 호출자에게
거부당합니다. 그래서 데몬이 호출자의 규칙을 자신의 자재에 그대로 적용합니다.

데몬이 엔드포인트를 띄우지 못하면 데몬 자체가 올라오지 않으므로, 호출자는
계속 엔드포인트가 도달 불가하다고 보고하며, 해결책은 기동 진단이 밝히는
내용입니다. 여기에는 발급 실패와, 발급은 성공했으나 TLS 로더가 그 교체본을
거부한 경우가 모두 포함됩니다. CA 장애를 가정하지 말고 진단을 읽으십시오.

인증서 경로는 어느 것도 리로드할 수 없습니다. `enabled`이나 네 경로 중
하나라도 바꾸는 `SIGHUP`은 바뀐 키를 밝히는 진단과 함께 거부되고, 실행 중인
데몬은 그대로 남습니다. 실행 중인 데몬 아래에서 바뀔 수 있는 것은 그
경로들의 *내용*뿐입니다.

#### 유닛 설치

두 유닛 모두 이 저장소의 `systemd/` 아래에 포함되어 있습니다.
`/etc/systemd/system/`에 복사한 뒤 활성화합니다.

```sh
install -m 0644 systemd/bootroot-registrar.socket /etc/systemd/system/
install -m 0644 systemd/bootroot-registrar.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now bootroot-registrar.socket
systemctl enable --now bootroot-registrar.service
```

소켓 유닛은 `ListenStream=/run/bootroot/registrar.sock`,
`SocketMode=0700`, `SocketUser=root`, `SocketGroup=root`, `Accept=no`,
`RuntimeDirectory=bootroot`, `RuntimeDirectoryMode=0755`,
`RuntimeDirectoryPreserve=yes`, `WantedBy=sockets.target`를 사용합니다.
`RuntimeDirectoryPreserve=yes`가 있어야 서비스 재시작이 런타임 디렉터리를
함께 없애지 않습니다.

서비스 유닛은 `Requires=bootroot-registrar.socket`,
`After=bootroot-registrar.socket`, `User=root`, `Group=root`,
`Restart=on-failure`, `WantedBy=multi-user.target`과 다음 `ExecStart`를
사용합니다.

```ini
ExecStart=/usr/local/bin/bootroot-agent --config /etc/bootroot/agent.toml
```

이 서비스는 연결이 들어올 때 지연 기동되는 것이 아니라 **부팅 시
시작**됩니다. 레지스트라가 접속하든 하지 않든 갱신 루프와 fast-poll
루프는 돌아야 하기 때문입니다. 소켓 유닛은 데몬이 시작되기 전에 listen
디스크립터가 존재하고 그것을 상속받게 하기 위한 의존성일 뿐입니다.

다른 에이전트 유닛과 마찬가지로, EAB 자격증명을 회전하는 배포는 실제로
프로비저닝된 `--eab-file` 경로를 `ExecStart`에 추가해야 합니다. 그렇지
않으면 EAB KV 갱신과 `rotate eab-clear`가 해당 에이전트에서 조용히
무시됩니다. 위의
[systemd 운영 절차](#systemd-운영-절차bootroot-agent-권장)를 참고하세요.

#### bootroot 내부 자격 증명

두 동사는 bootroot가 직접 보유한 자격 증명으로 실행됩니다. 데몬이 `auth/cert`로
`OpenBao`에 제시하는 `001.bootroot-registrar-internal.<host>.<domain>` 리프
인증서입니다. 호출자에게 전달되지도, 응답에 언급되지도, 요청으로 선택되지도
않습니다. 레지스트라는 신원의 구성 요소만 제공합니다.

인증서 인증에는 TLS가 필요하므로, 엔드포인트가 활성화된 호스트는 **루프백에서도**
`OpenBao`의 `:8200`에서 TLS를 종단하며 기록된 `state.openbao_url`이 `https://`가
됩니다. 엔드포인트를 쓰지 않는 호스트는 평문 루프백 리스너와 `http://` URL을 그대로
유지합니다. 어느 쪽에서도 리스너 측 클라이언트 인증서 옵션은 도입하지 않습니다.
TLS 리스너는 이미 클라이언트 인증서를 요청하며, 여기서 이를 강제하면 인증서가 없는
`AppRole` 에이전트와 토큰 인증 명령이 모두 깨집니다.

`bootroot init`이 자격 증명을 프로비저닝하고 상태에 기록된 secrets 디렉터리 아래에
전용 `registrar-internal/agent.toml`과 전용 CA 번들을 작성합니다. 다른 에이전트와
마찬가지로 갱신 프로세스는 시작하지 않으므로 운영자가 직접 시작합니다.

```sh
bootroot-agent --config <secrets-directory>/registrar-internal/agent.toml
```

그때부터 해당 설정의 `daemon`/`retry` 값과 다른 모든 프로파일이 사용하는 동일한
판정 로직으로 일상적인 갱신이 이뤄집니다. 시작하기 전에는 갱신할 것도, 신호를 보낼
대상도 없습니다. 회전이 `HUP`을 보냈는데 프로세스가 없으면 성공으로 처리합니다.

갱신에는 전제 조건이 하나 있습니다. 데몬은 발급을 시작하기 전에 자격 증명 옆에
기록된 루트가 여전히 배포의 활성 루트인지 확인하고, 아니라면 ACME 요청도 로그인도
쓰기도 하지 않은 채 거부합니다. 전체 CA 회전은 3단계와 4단계 뒤의 복구 단계 사이에
바로 그 간극을 만들므로, 그 사이에 만료가 임박한 리프는 인증 항목이 아직 신뢰하지
않는 루트로 재발급되는 대신 그대로 남습니다. 거부는 프로파일의 일반적인 갱신 후
실패 훅으로 보고되고 데몬은 계속 주기를 돌기 때문에, 복구 이후의 주기에서 정상적으로
갱신됩니다. 다시 시작할 것은 없습니다.

같은 비교는 갱신에만 적용되지 않고 자격 증명의 특권 `OpenBao` 로그인도 지킵니다.
시작할 때 읽어 둔 값을 믿지 않고 그때마다 활성 루트를 다시 읽으므로, 루트가 바뀐 뒤
도달한 레지스트라 동사는 로그인을 시도하지 않고 — 바뀌기 전에 받아 둔 토큰으로 계속
쓰지도 않고 — 동일한 복구 필요 오류로 거부됩니다.

**회전.** 중간 CA만 교체하는 회전은 자격 증명, 인증 항목, 설정, 전용 번들을 모두
그대로 둡니다. 인증 항목이 신뢰하는 대상은 루트이고, 그 회전은 루트를 교체하지
않기 때문입니다. 전체 회전은 3단계에서 누적 신뢰 집합을 전용 번들과 설정 핀에
게시하고, 4단계 뒤의 필수 후속 단계에서 인증 항목·리프·저장된 루트 지문을 교체하며
(`--skip reissue`로 건너뛸 수 없습니다), 6단계에서 마무리를 건너뛰지 않은 경우에만
번들과 핀을 최종 세대로 좁힙니다.

**복구.** 자격 증명이 만료되었거나 회전이 중단되었거나 자료가 유실·부분 기록된
경우, 데몬은 ACME 요청·로그인·쓰기를 시도하지 않고 복구 필요 오류로 즉시
실패합니다. 다음 명령으로 복구합니다.

```sh
bootroot rotate registrar-internal-credential
```

이 명령은 `root` 정책을 가진 `OpenBao` 토큰을 요구하며 `AppRole` 토큰은 거부합니다.
설치를 다시 실행하지 않고 서비스 자격 증명도 변경하지 않습니다. 기록된 회전 상태가
가리키는 신뢰 상태를 복원하고, 자료와 저장된 지문을 교체한 뒤 내부 에이전트를
재로드합니다.

자격 증명이 부여받는 정확한 `OpenBao` 정책을 포함한 전체 계약은
[`docs/reference/registrar-internal-credential.md`](https://github.com/aicers/bootroot/blob/main/docs/reference/registrar-internal-credential.md)에
있습니다.

#### 하드닝된 비루트 유닛과의 차이

위의 [하드닝된 systemd 유닛 예시](#하드닝된-systemd-유닛-예시)는 데몬을
전용 비특권 계정으로, 제한된 파일시스템 뷰에서 실행합니다. 일반 서비스
호스트에는 여전히 그 형태가 맞습니다. 레지스트라 유닛은 의도적으로 그와
다릅니다. `mint`와 `deregister`가 특권 내부 자격증명을 필요로 하므로
root로 실행합니다. 비특권으로 활성화된 엔드포인트는 기동은 하되 두 동사가
성공할 수 없다는 경고를 남깁니다. 조용히 정상인 척하지 않습니다. 두
유닛은 계층이 아니라 택일 관계이며, 한 호스트에서 같은 설정으로 둘을 함께
쓰지 않습니다.

#### 저장소 밖 레지스트라 유닛의 순서

레지스트라 프로세스 자체는 다른 저장소에 있으며 여기서 관리하지 않습니다.
그것을 실행하는 유닛은 반드시 소켓 뒤로 순서를 잡아야 합니다.

```ini
[Unit]
After=bootroot-registrar.socket
Requires=bootroot-registrar.socket
```

*서비스* 뒤로 잡는 것으로는 부족하고, 그것이 원하는 바도 아닙니다.
경로명을 만드는 것은 소켓 유닛이므로, 소켓 뒤로 잡아야 레지스트라가 접속할
대상이 존재함이 보장됩니다. 데몬 뒤로 잡으면 레지스트라의 기동이 재시작될
수 있는 유닛에 묶이기까지 합니다.

#### 설정 값

`agent.toml`의 `registrar_endpoint.enabled`는 프로세스 수명 동안
고정됩니다. listen 디스크립터는 리로드 루프보다 앞에서 한 번만
상속되므로, 실행 중인 값과 다른 값으로 `SIGHUP`이 들어오면 그 리로드는
거부됩니다. 실행 중인 데몬은 현재 설정 그대로 계속 동작하고 거부 사실이
로그에 남습니다. 값을 바꾸려면 `systemctl restart`가 필요합니다. 값을
바꾸지 않는 리로드는 종전과 동일하게 동작하며, 리스너를 리로드 위쪽에서
유지하고 리로드가 다시 획득하지 않기 때문에 엔드포인트는 같은 소켓 inode를
그대로 유지합니다.

#### 감사 레코드

`state.json`이 `registrar_endpoint.enabled = true`를 기록한 호스트에서는
root로 실행한 `bootroot init`이 `audit_store_dir`과 그 아래의 `records/`,
`openbao/`를 생성합니다. 저장소는 uid 0 소유에 모드 `0700`이므로 이 실행은
반드시 root여야 합니다. 레지스트라 엔드포인트가 활성화되지 않은 호스트에는
여전히 저장소가 없습니다.

데몬은 두 동사에 대한 자체 추가 전용 감사 기록을
`audit_record_dir`(`<audit_store_dir>/records`, 기본값
`/var/lib/bootroot/audit-store/records`)에 남깁니다. 이는 OpenBao의
파일 감사 장치를 대체하지 **않습니다**. 그 장치는 여전히 필수이고
`bootroot init`이 계속 확인합니다. 이 기록은 그 장치가 남길 수 없는
것을 남깁니다. 누가 요청했는지, 어떤 `(service_name, host, instance)`
조합이었는지, 그리고 OpenBao 쓰기가 일어나기 전에 거부된 요청까지입니다.

산출물의 소유자는 처음부터 끝까지 데몬입니다. 레지스트라는 이 파일을
읽거나, 추가하거나, 삭제하거나, 다른 경로로 돌릴 수 없고, 요청의 어떤
필드도 경로나 정책을 고르지 못합니다. 설정은 `agent.toml`의
`[registrar]` 테이블에 있습니다. 여덟 개의 감사 키와 레코드 형식은
[레지스트라 감사 레코드](configuration.md#registrar-audit-records)를
참고하십시오.

호스트에서 운영자가 확인해야 할 것:

- `audit_record_dir`와 그 직속 상위 디렉터리는 root 소유여야 하고,
  그룹이나 다른 사용자에게 쓰기 가능해서는 안 되며, 둘 다 심볼릭 링크가
  아니어야 합니다. 없는 구성 요소는 데몬이 직접 만듭니다. 상위 경로는
  root 소유 `0755`, 저장소 디렉터리는 root 소유 `0700`이며, 이미 존재하는
  항목의 소유자나 권한은 절대 바꾸지 않습니다.
- 저장소는 핸들러를 만드는 도중, 실행 단위가 무엇이든 spawn하기 전에
  열립니다. 따라서 안전하지 않거나 사용할 수 없는 디렉터리는 기록 없이
  동사를 계속 서비스하는 대신 그 실행 단위를 실패시킵니다. 엔드포인트가
  활성화된 호스트에서는 이것이 곧 데몬 정지이며, 갱신과 fast-poll도
  함께 멈춥니다. 다른 핸들러 의존 대상과 똑같이 원인을 지목하는 실패이고,
  accept만 하고 답하지 못하는 표면을 남기지 않으려는 의도적인 선택입니다.
  엔드포인트가 비활성화된 호스트는 저장소를 아예 열지 않으므로 여기서
  갱신이 멈추는 일도 없습니다.
- 디스크는 보존 목표가 아니라 하드 상한 기준으로 확보하십시오.
  `audit_max_file_bytes` × (`audit_max_retained_files` + 1)이며,
  기본값에서는 8 MiB × 17 ≈ **136 MiB**입니다.

기록을 읽는 일은 평범한 줄 단위
작업입니다. 형식이 JSON Lines라서 한 줄이 완전한 레코드 하나입니다.

```sh
# 최근 거부 기록. 아래쪽이 최신입니다.
cat /var/lib/bootroot/audit-store/records/registrar-audit.jsonl |
  jq -c 'select(.outcome.class == "refused")'

# 하나의 상관 관계 핸들에 해당하는 모든 기록. 활성 파일뿐 아니라 회전
# 세대까지 포함합니다. 이름은 오래된 것부터 정렬됩니다.
cd /var/lib/bootroot/audit-store/records &&
  cat $(ls registrar-audit-*.jsonl) registrar-audit.jsonl |
  jq -c --arg id "$REQUEST_ID" 'select(.request_id == $id)'
```

`bootroot status --agent-config /path/to/agent.toml`은 저장소를 필요할 때
스캔합니다. outcome이 없는 60초 초과 intent, 잘못된 줄 수, 그리고 보존된
세대가 모두 설정된 보존 목표보다 새로워 보이는지를 보고합니다. 짝 없는
intent에는 30일 조회 창을 쓰지만, 로테이션 경계를 넘어선 outcome도 짝지을
수 있도록 바로 앞 세대도 읽습니다. 잘못된 JSON, 중복 request ID, 지원하지
않는 레코드 버전, phase/outcome 불일치, 너무 긴 줄, 마지막의 개행 없는 줄은
신호이며, 잘못된 줄 하나가 나머지 스캔을 중단시키지는 않습니다.

보존 경고는 설정된 모든 로테이션 세대가 있을 때만 계산합니다. 가장 오래
보존된 세대에서 파싱할 수 있는 가장 이른 레코드 타임스탬프를 설정된 보존
기준과 비교하고, 파싱할 수 있는 레코드가 없는 세대는 더 새 세대로
넘어갑니다. 세대 파일명이나 잘못된 줄은 이 타임스탬프를 대신하지 않습니다.

상태 섹션에는 세 가지 상태가 있습니다. 저장소가 없으면 “구성되지 않음”을
표시하고, 활성 파일조차 아직 없는 조용한 프로비저닝 저장소는 0/0/아니요를
표시하며, 읽을 수 없거나 안전하지 않은 저장소는 거짓 정상 대신 스캔 실패
경고를 표시합니다. 리더는 저장소 디렉터리와 직속 상위 디렉터리가 심볼릭
링크가 아닌 디렉터리이고 root 또는 호출 사용자 소유이며 그룹이나 다른
사용자가 쓸 수 없는지 확인합니다. 그보다 위의 조상은 이 명령이 검증하지
않는 프로비저닝 신뢰 영역입니다. 이 검사는 디렉터리 교체 경쟁을 없애는
것이 아니라, 이미 저장소를 읽을 수 있는 신뢰된 주체만 시도할 수 있게
제한합니다.

한 줄은 완전한 레코드이거나 아예 없거나 둘 중 하나입니다. 레코드를 쓰다가
중간에 실패한 경우 데몬은 실패를 보고하기 전에 이미 기록된 바이트를 파일에서
다시 걷어내고, 그 되돌림까지 디스크에 반영하므로 정전이 나도 그 바이트가
되살아나지 않습니다. 따라서 위와 같은 조회가 잘린 줄을 건너뛸 일이 없습니다.
유일한 예외는 스스로를 드러냅니다. 그 바이트를 제거하지 못했거나 제거를
디스크에 반영하지 못하면 데몬은 평범한 쓰기 실패가 아니라 바로 그 사실을
보고하며, 잘린 줄이 남아 있다면 그것은 활성 파일의 마지막 줄입니다.

이 파일들을 `logrotate`나 다른 외부 도구로 회전시키지 마십시오. 작성기가
연결되면 데몬이 직접 회전과 정리를 수행하며, 이름 형식
`registrar-audit-<YYYYMMDDTHHMMSSZ>-<NNNNNN>.jsonl`의 고정 너비가 바로
오래된 것부터 정렬되게 하는 근거입니다. 다른 회전 도구가 데몬 아래에서
활성 파일을 옮기면 기록이 사라집니다.

세대로 인정되는 이름은 그 형식과 정확히 일치하는 것뿐입니다. 초 단위
정밀도의 실재하는 UTC 달력 시각과 여섯 자리 순번이어야 합니다. 디렉터리에
들어 있는 그 밖의 파일은 `audit_max_retained_files` 계산에 포함되지 않고
정리로 삭제되지도 않습니다. 따라서 옆에 남겨 둔 보관용 사본은 보존되지만,
디스크를 소리 없이 채우는 파일도 마찬가지로 남습니다.

보존에는 하드 제약 하나와 목표 하나가 있습니다.
`audit_max_retained_files`가 제약이고 언제나 이깁니다.
`audit_min_retain_days`는 해당 배포가 얼마나 과거까지 볼 수 있기를
*원하는지*를 기록합니다. 거부 폭주는 그 목표보다 훨씬 이른 시점에 보존
구간 전체를 소진할 수 있습니다. 디스크를 제한하는 것은 파일 개수이고,
일수는 상한을 올릴지 판단할 때 결과와 비교할 기준입니다.

## 회전 스케줄링

`bootroot rotate ...`는 크론/systemd 타이머로 주기 실행합니다. 토큰 등
민감값은 환경 파일이나 안전한 저장소로 관리하세요.
day-2 자동화에서는 root token 대신 AppRole 런타임 인증
(`--auth-mode approle`)을 사용하세요. root token은 부트스트랩/비상
절차용으로만 유지하는 것을 권장합니다.
`bootroot`는 root token 영구 저장소를 기본 제공하지 않습니다.

예시(크론; crontab 항목은 물리적으로 한 줄이어야 합니다 — 크론은 `\`
줄 연속을 이어 붙이지 않습니다 — 변수 할당은 별도 라인에 둘 수
있습니다):

```cron
OPENBAO_APPROLE_ROLE_ID=...
OPENBAO_APPROLE_SECRET_ID=...
0 3 * * 0 bootroot rotate --auth-mode approle stepca-password --yes
```

예시(systemd 타이머):

```ini
[Unit]
Description=step-ca 암호 주간 회전

[Service]
Type=oneshot
EnvironmentFile=/etc/bootroot/rotate.env
ExecStart=/usr/local/bin/bootroot rotate stepca-password --yes
```

```ini
[Unit]
Description=주간 step-ca 암호 회전

[Timer]
OnCalendar=Sun 03:00
Persistent=true

[Install]
WantedBy=timers.target
```

### AppRole secret_id 회전 스케줄링

bootroot가 발급하는 모든 AppRole `secret_id`는 짧은 TTL(기본 `24h`)을
가지므로, `secret_id` 회전은 수동 작업이 아니라 스케줄된 작업이어야
합니다 — 그렇지 않으면 마지막 회전 후 TTL이 지나는 시점부터 OpenBao
Agent 로그인이 `403 invalid role or secret ID`로 실패하기 시작합니다.
주기 불변식(TTL ≥ 회전 주기의 2배)과 TTL 조절 방법은
[SecretID TTL과 회전 주기](#secretid-ttl과-회전-주기)에 문서화되어
있으며, 이 절은 실제 동작하는 스케줄 작업 예시를 제공합니다.

모델은 **하나의 스케줄 작업, 소수의 호출**입니다. 서비스와 인프라
역할은 의도적으로 분리된 자격증명을 사용하고
(`bootroot-runtime-rotate-role`은 인프라 역할을 다룰 수 없고,
`bootroot-infra-rotate-role`은 서비스 역할과 KV를 다룰 수 없는 권한
상승 경계), 단일 `rotate` 호출은 정확히 한 번만 인증하므로, 작업은
자격증명을 섞는 대신 자격증명 표면당 하나의 호출을 실행합니다:

- **배치 서비스 호출 1회**: `bootroot rotate approle-secret-id
  --all-services --yes`는 runtime-rotate 자격증명으로 `state.json`에
  등록된 모든 서비스(`local-file`과 `remote-bootstrap` 전달 모드
  모두)를 회전합니다. 레지스트리를 따르므로 스케줄러 작성 이후에
  추가된 서비스도 자동으로 포함됩니다 — 서비스별 유닛을 동기화할
  필요가 없습니다. 서비스별 실패가 있어도 계속 진행하고, 대상별 요약을
  출력하며, 하나라도 실패하면 0이 아닌 코드로 종료합니다. 빈
  레지스트리는 no-op 성공입니다.
- **인프라 대상별 호출 2회** (`--infra stepca`, `--infra responder`)는
  infra-rotate 자격증명을 사용합니다.
  [인프라 AppRole secret_id 회전](#인프라-approle-secret_id-회전-stepca-responder)을
  참고하세요. 서비스 배치만 스케줄하지 **마세요**: 인프라 역할도
  동일한 TTL을 공유하며, 빠뜨리면 인프라 OpenBao Agent 뒤의 인증서 발급
  체계가 멈춥니다.

기본 `24h` TTL이라면 작업을 **8–12시간마다** 실행하세요. 서비스별
`--secret-id-ttl` 재정의가 있으면 모든 대상(서비스와 인프라 역할 모두)
중 **가장 작은** TTL에 대해 불변식을 만족하도록 스케줄해야 합니다.

각 rotate 자격증명의 `role_id`/`secret_id`는 root 소유 파일(모드
`0600`)에 저장하세요. 예:
`/etc/bootroot/runtime-rotate/{role_id,secret_id}`와
`/etc/bootroot/infra-rotate/{role_id,secret_id}`. 그리고
`--approle-role-id-file`/`--approle-secret-id-file`로 전달해 시크릿이
유닛 파일, crontab, 프로세스 목록에 남지 않게 하세요. `bootroot init`이
두 자격증명을 모두 출력합니다(`--show-secrets`가 없으면 마스킹됨).
`bootroot-infra-rotate-role`이 생기기 전에 초기화된 배포에서는 루트
토큰 `--infra` 실행이 역할을 프로비저닝하고 자격증명을 출력합니다
(인프라 절의 업그레이드 노트 참고). 파일 기반 인증은 rotate 자격증명
자체를 신선하게 유지하는 수단이기도 합니다: 성공한 호출마다 자기
자신의 `secret_id`를 재발급해 `--approle-secret-id-file` 파일을
원자적으로 교체하므로([자체 재발급 절 참고](#rotate-자격증명-자체의-secret_id-자체-재발급)),
설치 시 한 번 시드한 파일에 대해 정기적인 수동 재발급이 필요 없습니다.

동작 예시 — systemd 타이머 + oneshot 유닛
(`bootroot-rotate-secret-ids.service`):

```ini
[Unit]
Description=bootroot AppRole secret_id 회전 (서비스 + 인프라)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/runtime-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/runtime-rotate/secret_id \
  approle-secret-id --all-services --yes
ExecStart=/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/infra-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/infra-rotate/secret_id \
  approle-secret-id --infra stepca --yes
ExecStart=/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/infra-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/infra-rotate/secret_id \
  approle-secret-id --infra responder --yes
```

```ini
[Unit]
Description=bootroot AppRole secret_id 8시간 주기 회전

[Timer]
OnCalendar=00/8:00
Persistent=true

[Install]
WantedBy=timers.target
```

`Type=oneshot`에서는 실패한 `ExecStart` 라인이 나머지 라인을 중단시키고
유닛을 실패로 표시합니다. 회전은 멱등이고(기존 `secret_id`는 TTL까지
유효) 2배 이상 TTL 버퍼가 한 번의 누락을 흡수하지만, 연속 누락이 TTL을
넘기지 않도록 유닛 실패에 대한 알림을 설정하세요.

크론 동등 구성. crontab 항목은 물리적으로 한 줄이어야 하므로(크론은
`\` 줄 연속을 이어 붙이지 않습니다), 세 호출을 작은 래퍼 스크립트 —
예: `/usr/local/sbin/bootroot-rotate-secret-ids`, root 소유, 모드
`0700` — 에 넣고 크론 항목 하나가 이를 가리키게 하세요. `Type=oneshot`
유닛과 달리 이 스크립트는 실패한 호출이 있어도 계속 진행하고, 하나라도
실패하면 0이 아닌 코드로 종료합니다:

```bash
#!/bin/sh
set -u
status=0
/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/runtime-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/runtime-rotate/secret_id \
  approle-secret-id --all-services --yes || status=1
/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/infra-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/infra-rotate/secret_id \
  approle-secret-id --infra stepca --yes || status=1
/usr/local/bin/bootroot rotate --auth-mode approle \
  --approle-role-id-file /etc/bootroot/infra-rotate/role_id \
  --approle-secret-id-file /etc/bootroot/infra-rotate/secret_id \
  approle-secret-id --infra responder --yes || status=1
exit "$status"
```

```cron
0 */8 * * * /usr/local/sbin/bootroot-rotate-secret-ids
```

### rotate 자격증명 자체의 secret_id (자체 재발급)

스케줄 작업은 두 AppRole로 인증하는데, 이들의 `secret_id`도 다른 모든
것과 동일한 TTL의 적용을 받습니다. 각 rotate 정책은 **자기 자신의**
`auth/approle/role/<self>/secret-id` 경로에 대한 `update` 권한을
가지며(오직 그 경로만 — 교차 발급은 없습니다: 어느 rotate 자격증명도
상대의 표면에 닿을 수 없어 권한 분리 경계가 유지됩니다), 모든
`approle-secret-id` 호출은 해당 호출의 모든 대상이 성공한 뒤 **자신이
인증에 사용한 자격증명을 마지막 단계로 재발급**하고, 스케줄러가 읽는
자격증명 파일을 원자적으로 교체합니다
([#672](https://github.com/aicers/bootroot/issues/672)). 따라서 정상
운영은 루트 토큰을 전혀 사용하지 않으며, 루트 토큰은 엄격하게
비상(break-glass) 용도로만 남습니다.

자체 재발급의 동작:

- **호출 단위, 마지막에 자기 자신 발급.** 각 호출은 모든 대상이 성공한
  뒤에만 자기 자격증명을 재발급합니다. runtime-rotate(작업당 배치 호출
  1회)에서는 작업 수준의 mint-own-last와 동일하고, 두 호출(`--infra
  stepca`, `--infra responder`)이 소비하는 infra-rotate에서는 성공한
  호출이 끝날 때마다 자격증명 파일이 교체되며 다음 호출이 시작 시 새
  파일을 읽습니다. 작업당 추가 발급 1회는 무해합니다: 고아 `secret_id`는
  TTL로 만료됩니다.
- **파일 계약.** 자체 재발급은 `--approle-secret-id-file`로 전달된
  파일을 교체합니다 — 위의 스케줄러 예시가 이미 사용하는 형태입니다.
  `secret_id`가 인라인(`--approle-secret-id`)이나
  `OPENBAO_APPROLE_SECRET_ID`로 공급되면 교체할 파일이 없으므로, 실행은
  눈에 띄는 경고를 출력하고 자체 재발급을 건너뜁니다(그 경우 자격증명은
  여전히 TTL에 만료됩니다). 루트 토큰 실행은 자체 재발급을 수행하지
  않습니다 — 루트 실행에는 연장할 "자기 자격증명"이 없으며, 루트 인증으로
  rotate 자격증명을 재발급하는 것은 아래의 비상 복구 절차입니다.
- **교체 전 검증, 즉시 폐기 없음.** 새 `secret_id`는 로그인 검증을
  통과해야 파일이 교체되며, 이전 `secret_id`는 폐기되지 않습니다(TTL로
  만료). 여러 `secret_id`가 동시에 유효하므로 어느 지점의 크래시나
  실패도 자가 치유됩니다: 다음 실행이 여전히 유효한 기존 자격증명으로
  로그인해 다시 발급합니다.
- **사용 횟수 제한.** 자체 발급된 rotate `secret_id`는
  `num_uses = 6`을 갖습니다: 재발급 주기당 열거된 로그인(다음 호출의
  기본 로그인 + 새 자격증명의 검증 로그인)의 3배로, 일시 오류 재시도와
  크래시 복구 로그인의 여유분입니다. 탈취된 자격증명 스냅샷은 소모성
  자산이 되고, 정상 주기는 결코 고갈되지 않습니다. 스케줄러가 멈췄을 때
  복구 창이 넓어지도록 넉넉한 역할 TTL(`--secret-id-ttl`, 최대 `168h`)과
  함께 사용하세요.

#### CIDR 바인딩 (`--rotate-bound-cidrs`)

선택적으로 rotate 자격증명을 컨트롤 플레인 호스트에 바인딩할 수
있습니다: `bootroot init --rotate-bound-cidrs <cidr>`는 두 rotate
자격증명을 모두 바인딩하고, 루트 토큰 인프라 프로비저닝 실행은
`bootroot-infra-rotate-role`에 대해 같은 플래그를 받습니다. 바인딩은
`state.json`에 기록되어 이후 자체 발급되는 모든 `secret_id`에 다시
적용됩니다.

값은 **운영자가 직접 지정하며, 자동 유추하지 않습니다**: OpenBao가
컨트롤 플레인 호스트에 대해 보는 소스 IP는 배포 모드에 따라 다릅니다 —
기본 루프백 게시 OpenBao 포트에서는 보통 `127.0.0.1/32`(Linux)이거나
Docker 브리지 게이트웨이(Docker Desktop)이고, 루프백이 아닌 바인딩에서는
호스트의 LAN 주소입니다. 바인딩 전에 OpenBao가 실제로 보는 값(예: 감사
로그의 로그인 항목 `remote_address` 필드)을 확인하세요. 잘못된 CIDR은
스케줄 작업을 잠급니다 — 자체 재발급의 로그인 검증이 이를 잡아내지만
(실행이 실패하고 기존의 동작하는 자격증명 파일을 유지), TTL이 다하기
전에 바인딩을 고쳐야 합니다: 루트 토큰 인프라 프로비저닝을 수정된
`--rotate-bound-cidrs`로 다시 실행하거나, `--clear-rotate-bound-cidrs`로
바인딩을 완전히 제거하세요. 플래그를 생략하면 바인딩이 적용되지
않습니다(옵트인). 이후 플래그 없이 실행한 프로비저닝은 기록된 바인딩을
유지하고 출력하므로, 강화 조치가 조용히 사라지는 일은 없습니다.

이는 **호스트 경계 통제이지 프로세스 격리가 아닙니다**: OpenBao는 소스
IP만 보므로, 컨트롤 플레인 호스트에 함께 있는 프로세스는 회전 작업과
구분되지 않습니다.

#### rotate 자격증명 발급에 대한 감사 알림

파일 감사 백엔드는 init에서 활성화·검증되지만 bootroot는 알림
파이프라인을 제공하지 않습니다 — 다음 규칙을 자체 로그 파이프라인에
연결하세요. 두 rotate 역할 경로에 대한 `secret_id` 발급 요청, 즉
`request.path`가 다음과 같은 감사 항목에 대해 알림을 설정하세요:

- `auth/approle/role/bootroot-runtime-rotate-role/secret-id`
- `auth/approle/role/bootroot-infra-rotate-role/secret-id`

예상 빈도는 스케줄 실행당 rotate 자격증명별 발급 1회(2회 호출 흐름에서
작업당 infra-rotate 추가 발급 1회, 그리고 init/프로비저닝 중 운영자
주도 발급)입니다. 스케줄러 주기를 벗어나거나 예상 밖의
`remote_address`에서 온 발급은 페이징할 가치가 있는 신호입니다: 탈취된
rotate 자격증명이 자신을 연장할 때 사용하는 바로 그 표면입니다.

#### 데드맨 모니터링과 비상 복구

조용히 멈춘 타이머는 남아 있는 유일한 잠금 경로이며, 그 실패 모드는
순수한 부재입니다 — 실행이 없으면 실패 로그도 없습니다. 그래서 성공한
`approle-secret-id` 호출마다 `state.json`에 타임스탬프
(`last_secret_id_rotation`)가 기록되고, `bootroot status`는 마지막 회전
성공 시각을 출력하며 **rotate 역할 `secret_id` TTL의 절반보다 오래되면
경고합니다**(2배 이상 주기 불변식 아래에서 한 번 누락 예산; 기본 TTL
`24h` → `12h` 초과 시 경고). 모니터링 훅에서 `bootroot status`를
확인하거나 스케줄러 유닛 자체에 알림을 설정하세요.

작업이 TTL을 넘겨 실행을 누락하면 rotate 자격증명이 만료되고 스케줄
실행은 `403 invalid role or secret ID`로 실패합니다. **비상 루트
토큰**으로 복구하세요(이는 정기 작업이 아니라 복구 경로입니다):

- infra-rotate: 루트 토큰 `--infra` 회전을 한 번 실행합니다
  (`bootroot rotate --auth-mode root --root-token-file <path>
  --show-secrets approle-secret-id --infra stepca --yes`) — 루트
  토큰 실행마다 새 infra-rotate 자격증명이 발급되어 출력됩니다
  (여기서 `--rotate-bound-cidrs`는 기록된 바인딩을 바꿀 때만 다시
  지정하세요; 생략하면 기록된 바인딩이 유지되고 재적용된 바인딩이
  출력됩니다. 기록된 CIDR 자체가 작업을 잠근 원인이라면
  `--clear-rotate-bound-cidrs`로 제거하고 바인딩 없이 발급하세요).
- runtime-rotate: 루트 토큰으로 OpenBao에 직접 발급합니다. 예:
  `docker compose exec -e BAO_TOKEN=<root-token> openbao bao
  write -f auth/approle/role/bootroot-runtime-rotate-role/secret-id`.

재발급 후에는 스케줄 작업이 참조하는 자격증명 파일(예:
`/etc/bootroot/` 아래)에 새 값을 기록하세요. 다음 스케줄 실행이 이어받아
자체 재발급을 재개합니다. 컴플라이언스 규정이 자체 발급 권한을 금지하는
배포는 이 루트 토큰 재발급을 TTL보다 짧은 주기의 정기 절차로 대신 유지할
수 있습니다.

## 회전과 in-FD 함정

`bootroot rotate ca-key`와 `bootroot rotate force-reissue`는 각
`local-file` 서비스의 인증서/키 파일 쌍(`entry.cert_path`와
`entry.key_path`, 예: `/opt/<svc>-mtls/{cert,key}.pem`)을 디스크에서
삭제하고 로컬 `bootroot-agent`에**만** 시그널을 보냅니다. 현재 해당
파일을 서빙 중인 컨슈머 프로세스에는 시그널을 보내지 **않습니다**.

회전 이전에 시작된 네이티브 데몬(`review`, `aimer` 등)은 디스크의 파일이
교체되었더라도 이미 열린 파일 디스크립터를 통해 **이전** leaf 인증서를
계속 서빙합니다. 한편 *다른* 컨슈머의 `bootroot-agent`는 새 PKI
세대로 서명된 새 CA 번들을 해당 컨슈머의 신뢰 저장소에 기록합니다.
결과적으로 신뢰 번들과 서빙되는 leaf가 서로 다른 PKI 세대에 속하게
되어 mTLS 핸드셰이크가 `UNABLE_TO_GET_ISSUER_CERT`로 실패하고, 두
중간 CA가 동일한 `Subject DN` / `Issuer DN`을 공유하기 때문에 로그에는
아무 단서도 남지 않는 조용한 회전 후 실패가 발생합니다.

구체적으로 식별자는 **DN이 아니라** leaf의 Authority Key
Identifier(AKI)와 신뢰 번들 내 중간 CA의 Subject Key Identifier(SKI)
입니다. 진단 절차는
[트러블슈팅 → 회전 후 FD 비동기 문제](troubleshooting.md#회전-후-fd-비동기-문제-이슈-614)를
참조하세요.

### 등록 시점에 갱신 후 훅을 구성하기

확실한 해결책은 서비스를 등록할 때 갱신 후 훅을 선언하는 것입니다.
`bootroot-agent`는 모든 성공적인 발급 시 훅을 실행하므로(렌더링된
`agent.toml`의 `[profiles.hooks.post_renew]` 참조), 컨슈머 프로세스가
운영자 개입 없이 새 인증서를 적용합니다.

```bash
# systemd 하의 네이티브 데몬
bootroot service add --registration-id review --service-name review \
  --reload-style systemd --reload-target review.service ...

# 직접 실행되는 네이티브 데몬 (pkill -HUP <process-name> 사용)
bootroot service add --registration-id review --service-name review \
  --reload-style sighup --reload-target review ...

# 컨테이너 컨슈머 (`docker restart <container>` 실행)
bootroot service add \
  --registration-id aice-web-next \
  --service-name aice-web-next \
  --reload-style docker-restart --reload-target aice-web-next ...
```

명시적으로 옵트아웃하려면 `--reload-style none`을 사용하거나, 임의의
명령에는 저수준 `--post-renew-command` / `--post-renew-arg` /
`--post-renew-timeout-secs` / `--post-renew-on-failure` 플래그를
사용하세요.

하나의 리프를 서로 다른 갱신 동작이 필요한 두 프로세스가 소비할
때(예: 컨테이너 `docker restart` **및** 컨테이너 내부의
`nginx -s reload`), 프리셋과 저수준 커스텀 명령을 함께 전달하세요 —
단일 갱신에서 두 훅이 모두 등록되며, 프리셋이 먼저 그다음 커스텀
순서로 방출됩니다 (이슈 #702):

```bash
bootroot service add --registration-id aimer-web --service-name aimer-web \
  --reload-style docker-restart --reload-target aimer-web-next-app-1 \
  --post-renew-command docker --post-renew-arg exec \
    --post-renew-arg aimer-web-nginx-prod-1 \
    --post-renew-arg nginx --post-renew-arg -s --post-renew-arg reload ...
```

이렇게 하면 두 소비자의 갱신 동작이 모두 갱신 이벤트에 결합되어,
슬립되어 한 소비자가 만료된 리프를 계속 제공할 수 있는 취약한
대역 외 리로드 타이머를 대체합니다.

### 기존 서비스에 훅 재구성

서비스가 `--reload-style` 없이 등록되었더라도 더 이상 제거 후 재등록할
필요가 없습니다: `bootroot service update`가 동일한 훅 플래그를 받아
관리되는 `agent.toml` 프로필 블록을 그 자리에서 다시 렌더링합니다. 이것이
`service add`, `rotate ca-key`, `rotate force-reissue`의 CLI 안내가
운영자에게 가리키는 표준 한 줄 복구 명령입니다.

```bash
bootroot service update --registration-id review \
  --reload-style sighup --reload-target review
```

`remote-bootstrap` 서비스의 경우 동일한 `service update` 호출이
`state.json`을 갱신하지만, 원격 agent는 원격 호스트의 부트스트랩으로
렌더링된 `agent.toml`을 읽습니다. `service update`는 이 경우 경고를
출력하며, 운영자는 `bootroot service add`로 부트스트랩 아티팩트를
재발행하고 원격 호스트에서 `bootroot-remote bootstrap --artifact <path>`를
다시 실행해 새 훅이 원격 agent 구성에 반영되도록 해야 합니다.

이전에 등록된 훅을 제거하려면 `--reload-style none`을 사용하세요.

### 완료 시 안내

`service add`, `rotate ca-key`(phase 5), `rotate force-reissue`는
영향받은 서비스 목록과 각각의 갱신 후 훅 상태를 보여주는 "Consumer
reload/restart required" 안내를 출력합니다. 훅이 없는 서비스는
명시적으로 플래그되며 `service update --reload-style ...` 복구
안내가 함께 표시됩니다.

특히 `rotate ca-key`의 경우 안내에는 이번 호출에서 실제로 인증서를
삭제하고 재서명한 서비스만 포함됩니다. 이미 새 intermediate로 발급된
서비스(재개 또는 재시도 회전의 skip-migrated 분기)는 이번 회전이 디스크
상 leaf를 바꾸지 않았고 컨슈머도 다시 로드할 필요가 없으므로 안내에
나타나지 않습니다.

`bootroot reinit`은 인증서 파일이 아니라 서비스 레지스트리를 지웁니다.
완료 안내는 컨슈머의 다음 갱신 주기 전에 갱신 후 훅이 미리 구성되도록
`bootroot service add ... --reload-style ...`로 각 컨슈머를 재등록할
것을 운영자에게 상기시킵니다.

## SecretID TTL과 회전 주기

서비스 AppRole `secret_id` 값은 재사용 가능한 런타임 자격증명입니다.
정상적인 재시작과 재인증을 거쳐 다음 계획된 회전까지 유효합니다.
`secret_id_ttl`은 발급 후 SecretID가 유효한 기간을 제어합니다.

**기본 TTL 모델:**

- `24h`는 `bootroot init` 시 설정되는 역할 수준 기본값입니다. 보안
  보수적 선택으로, 짧은 수명은 SecretID 유출 시 노출을 제한합니다.
- `48h`(`RECOMMENDED_SECRET_ID_TTL`)는 CLI 경고 임계값입니다. `48h` 초과
  시 CLI 경고가 표시되며, `168h`(7일) 초과 시 거부됩니다. 누락된 회전
  실행, 유지보수 기간, 재시작 복구를 견디는 것이 노출 창 최소화보다
  중요할 때 `48h` 이상을 사용하세요.

**회전 주기 규칙:**

`secret_id_ttl`을 **회전 주기의 최소 2배** 이상으로 설정하세요. 이
여유는 단일 누락 또는 지연된 회전 실행이 자격증명을 만료시켜 서비스가
재인증할 수 없는 상황을 방지합니다.

| 회전 주기 | 최소 권장 TTL   |
|-----------|-----------------|
| 8시간     | 16시간          |
| 12시간    | 24시간 (기본값) |
| 24시간    | 48시간          |

예를 들어, 12시간 회전 스케줄에서 기본 `24h` TTL은 정확히 한 번의 누락
버퍼를 제공합니다. 자동화가 적시 실행을 보장할 수 없다면 TTL을 늘리거나
회전 주기를 줄이세요.

이 주기를 모든 서비스와 인프라 역할에 걸쳐 구현하는 동작하는 스케줄
작업(systemd 타이머 / 크론)은
[AppRole secret_id 회전 스케줄링](#approle-secret_id-회전-스케줄링)을
참고하세요.

**서비스별 재정의:**

- `bootroot service add --secret-id-ttl 48h`는 발급 시 TTL을 설정합니다.
- `bootroot service update --secret-id-ttl 48h`는 저장된 정책을
  변경합니다(이후 `bootroot rotate approle-secret-id` 실행 필요).
- `--secret-id-ttl inherit`를 사용하면 서비스별 재정의를 지우고 역할
  수준 기본값으로 복원합니다.

`service add` 시 `--secret-id-ttl`을 생략하면 `bootroot init` 시
설정된 역할 수준 TTL을 상속합니다.

서비스별 재정의가 있는 경우, 회전 스케줄은 모든 대상 중 **가장 작은**
TTL에 대해 2배 이상 불변식을 만족해야 합니다 — 서비스 하나가 `12h`로
재정의되면 전체 작업을 최소 6시간마다 실행해야 합니다.

## 서비스 secret_id 정책 변경

`bootroot service update`를 사용하면 `service add`를 다시 실행하지 않고
서비스별 `secret_id` 정책을 변경할 수 있습니다:

```bash
bootroot service update --registration-id edge-proxy --secret-id-ttl 12h
bootroot service update --registration-id edge-proxy --no-wrap
```

이 명령은 `state.json`만 수정합니다. 갱신된 정책을 실제 `secret_id`에
적용하려면 이후 `rotate approle-secret-id`를 실행합니다:

```bash
bootroot rotate approle-secret-id --registration-id edge-proxy
```

`"inherit"`를 사용하면 서비스별 오버라이드를 지우고 OpenBao의 AppRole에
설정된 역할 수준 기본값으로 되돌립니다:

```bash
bootroot service update --registration-id edge-proxy --secret-id-ttl inherit
bootroot service update --registration-id edge-proxy --secret-id-wrap-ttl inherit
```

## 원격 bootstrap 및 secret_id handoff 운영

`--delivery-mode remote-bootstrap`으로 추가한 대상의 운영 모델은 일회성
bootstrap이며, 이후 실행 중인 에이전트는 스스로 자립합니다:

1. `bootroot service add` 이후 서비스 머신에서 `bootroot-remote bootstrap`을
   1회 실행해 첫 `bootroot-agent` 실행 전에 trust 설정과 CA 번들을 포함한
   초기 설정 번들을 반영합니다.
2. 이후 실행 중인 `bootroot-agent`의 fast-poll 루프가 호스트별 운영자 조치
   없이 스스로 최신 상태를 유지합니다: `bootroot/services/<registration_id>/secret_id`
   에서 자신의 `secret_id`를 갱신하고(`secret_id_ttl`을 넘겨서도 유지), control
   node에서 `bootroot rotate approle-secret-id`나 CA/trust 회전이 일어나면
   `bootroot/services/<registration_id>/trust`에서 `agent.toml`의 `[trust]` 핀과
   `ca-bundle.pem`을 다시 렌더링합니다. `bootroot-remote apply-secret-id`와
   `bootroot-remote bootstrap` 재실행은 복구 경로일 뿐입니다 — 에이전트가
   `secret_id_ttl`을 넘겨 오프라인 상태였고 자격증명이 이미 만료되어 더 이상
   스스로 갱신할 수 없을 때 필요합니다.

최소 환경/설정 체크리스트:

- OpenBao 엔드포인트, KV 마운트
- 서비스 이름, AppRole 파일 경로(`role_id`, `secret_id`)
- EAB 파일 경로(ACME CA가 EAB를 요구할 때만 사용하며, OpenBao KV에 EAB
  자격증명이 없으면 bootroot가 해당 단계를 건너뜁니다), `agent.toml` 경로
- 프로필 식별/경로 입력(hostname, instance_id, cert/key 경로)
- 관리되는 step-ca trust bundle을 쓸 CA 번들 출력 경로

보안 참고:

- 시크릿 디렉터리 `0700`, 파일 `0600`
- 서비스 계정 권한을 서비스별 경로로 최소화
- `bootroot init --summary-json` 산출물은 `root_token`을 포함할 수 있으므로
  민감 아티팩트로 취급하고 접근/보관 기간을 제한하기
- 래핑이 활성(기본값)이면 `bootstrap.json`에 `wrap_token`이 포함되므로
  `secret_id`와 동일한 수준의 민감 자격증명 파일로 취급해야 합니다

### 멱등 service add 재실행

기존 `remote-bootstrap` 서비스에 동일한 인자로 `bootroot service add`를
다시 실행하면 멱등합니다. 래핑이 활성(기본값)이면 재실행 시 래핑된 새
`secret_id`를 발급하고 새 `wrap_token`이 포함된 bootstrap 아티팩트를
재생성합니다. 운영자는 갱신된 `bootstrap.json`을 원격 호스트로 전달한 뒤
`bootroot-remote bootstrap`을 다시 실행해야 합니다.

정책 필드(`--secret-id-ttl`, `--secret-id-wrap-ttl`, `--no-wrap`)만
다르면 명령이 거부되며 `bootroot service update` 사용을 안내합니다.

### 실행 중인 에이전트로의 회전 전파

`local-file` 서비스의 경우, `bootroot rotate approle-secret-id`가 새
`secret_id`를 서비스의 `secret_id` 파일에 원자적으로 기록합니다. 시그널이나
재시작은 필요 없습니다: 에이전트의 fast-poll 루프가 재로그인 때마다 이
파일을 다시 읽으므로, 회전된 자격증명은 다음 로그인 주기에 반영됩니다.
`rotate responder-hmac`, `rotate eab-clear`, CA/trust 회전도
마찬가지입니다 — 로컬 에이전트의 fast-poll 루프가 `fast_poll_interval`
이내에 OpenBao KV에서 갱신된 값을 가져오며, 서비스별 프로세스 재시작이나
리로드는 없습니다.

`remote-bootstrap` 서비스의 경우, 회전된 `secret_id`는 서비스별 KV 경로
(`bootroot/services/<registration_id>/secret_id`)에 기록됩니다. *실행 중인* 원격
`bootroot-agent`는 운영자 조치가 필요 없습니다: fast-poll 루프가 아직 유효한
자격증명으로 그 경로를 읽어 회전된 `secret_id`를 에이전트의 로컬 파일에
원자적으로 기록하고, 다음 재로그인 시 AppRole로 재인증합니다 — 그래서 루프는
수동 작업 없이 `secret_id_ttl`을 넘겨서도 유지됩니다. 같은 루프가
`bootroot/services/<registration_id>/trust`를 읽어 `agent.toml`의 `[trust]` 핀과
`ca-bundle.pem`을 다시 렌더링하므로 CA/trust 회전도 동일한 방식으로
전파됩니다.

`bootroot-remote apply-secret-id`는 정상 상태가 아니라 **복구** 경로입니다:
`secret_id_ttl`을 넘겨 오프라인 상태였던(자격증명이 이미 만료되어 스스로
갱신할 수 없는) 에이전트에 새 `secret_id`를 전달합니다:

```bash
bootroot-remote apply-secret-id --openbao-url https://<ip>:8200 \
  --registration-id <svc> --role-id-path <dir>/role_id \
  --secret-id-path <dir>/secret_id --ca-bundle-path <dir>/ca-bundle.pem
```

OpenBao가 사설 CA로 HTTPS를 통해 제공될 때 — 즉 non-loopback
`--openbao-bind`에 필요한 posture — `bootroot-remote bootstrap`이 기록한
것과 동일한 CA 파일(에이전트의 `[openbao].ca_bundle_path`)을 가리키는
`--ca-bundle-path`를 전달해 TLS를 해당 사설 CA에 고정하세요. `--openbao-url`이
`http://`일 때만 생략합니다.

참고: `bootroot-agent`는 어느 전달 모드에서도 별도의 OpenBao Agent가
유지하는 토큰 파일에 의존하지 않습니다. fast-poll 루프에서 직접 AppRole
로그인을 수행하며, 서비스에 대해서는 OpenBao Agent 아티팩트
(`agent.hcl`/`.ctmpl`/token 파일)가 생성되지 않습니다.

### Wrap token 만료 복구

래핑이 활성이면 `bootstrap.json`에 포함된 `wrap_token`의 TTL은 제한적입니다
(기본값 30분). 토큰이 만료되기 전에 `bootroot-remote bootstrap`을 실행하지
않으면 언래핑 호출이 **만료** 오류로 실패합니다.

복구 절차:

1. control node에서 동일한 인자로 `bootroot service add`를 다시 실행합니다.
   서비스가 이미 존재하므로 새 `wrap_token`을 발급하는 멱등 재실행입니다.
2. 갱신된 `bootstrap.json`을 원격 호스트로 전송합니다.
3. 원격 호스트에서 `bootroot-remote bootstrap --artifact <경로>`를
   실행합니다.

언래핑 호출이 토큰이 **이미 언래핑됨**(비인가 당사자가 소비)으로 실패하면,
`bootroot-remote`가 잠재적 보안 사고로 표시합니다. 이 경우 `secret_id`를
즉시 회전하고 비인가 접근을 조사하세요.

## 인프라 AppRole secret_id 회전 (stepca, responder)

bootroot가 init 시 생성하는 인프라 AppRole(`bootroot-stepca-role`,
`bootroot-responder-role`)은 장기 실행 인프라 OpenBao Agent
(`openbao-agent-stepca`, `openbao-agent-responder`)가 사용하며, 서비스와
동일한 `secret_id` TTL을 공유합니다. 따라서 이들의 `secret_id`도
주기적으로 회전해야 합니다 — 그렇지 않으면 에이전트가 결국
`403 invalid role or secret ID`로 OpenBao 로그인에 실패하고, 그 뒤에
있는 인증서 발급 체계가 멈춥니다. 이 두 호출은 서비스 배치와 같은
작업에 스케줄하세요 —
[AppRole secret_id 회전 스케줄링](#approle-secret_id-회전-스케줄링)을
참고하세요.

`--infra` 선택자로 회전합니다:

```bash
bootroot rotate \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  approle-secret-id --infra stepca
bootroot rotate \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  approle-secret-id --infra responder
```

인프라 대상에는 전용 `bootroot-infra-rotate-role` 자격증명(다른 역할과
함께 `bootroot init`에서 생성됨)이 필요합니다. 범용
`bootroot-runtime-rotate-role` 자격증명은 인프라 역할 경로에서
의도적으로 거부됩니다: 인프라 역할은 CA 핵심 시크릿을 읽으므로, 해당
`secret_id`를 발급할 수 있는 자격증명은 그 시크릿으로 권한을 상승시킬 수
있기 때문입니다. 반대로 infra-rotate 자격증명은 두 인프라 `secret_id`
발급(및 `role_id` 읽기)만 가능하고 KV 접근 권한은 없습니다.

이 명령은 새 `secret_id`를
`<secrets_dir>/openbao/<stepca|responder>/secret_id`에 원자적으로(모드
`0600`) 기록하고, 해당 인프라 에이전트 컨테이너를 재시작해 재인증시키며,
AppRole 로그인으로 새 자격증명을 검증한 뒤 성공을 보고합니다.

**이 역할이 생기기 전에 초기화된 배포의 업그레이드 참고:** 해당 스택에는
`bootroot-infra-rotate-role`과 정책이 없으며, 명령은 이들이 존재한다고
가정하지 않습니다. 루트 토큰으로 `--infra` 회전을 실행해
프로비저닝하세요:

```bash
bootroot rotate \
  --auth-mode root --root-token-file <path> --show-secrets \
  approle-secret-id --infra stepca
```

이 실행은 정책과 역할을 생성해 `state.json`에 기록하고, 새 역할의
`role_id`/`secret_id`(`--show-secrets`가 없으면 마스킹됨)를 출력한 뒤
요청한 회전을 수행합니다. 출력된 자격증명을 보관하고 이후 `--infra`
회전에 사용하세요.

프로비저닝은 멱등입니다. 루트 토큰으로 `--infra`를 실행할 때마다
정책을 다시 기록하고, 역할 설정을 다시 적용하고, `state.json`에
누락된 항목을 채우고, 새 운영자 `secret_id`를 발급합니다. 이전 시도가
중간에 실패했거나 출력된 자격증명을 보관하기 전에 잃어버렸다면 루트
토큰으로 명령을 다시 실행하면 됩니다. 새 자격증명이 잃어버린 것을
대체합니다(이전에 발급된 `secret_id`는 TTL까지 유효합니다).

## OpenBao 재기동/복구 체크리스트

- OpenBao가 `sealed` 상태면 먼저 unseal keys로 언실을 완료합니다.
- 언실 완료 후 운영 명령에 맞는 런타임 인증을 주입합니다.
  - day-2 `service add`/`rotate`: AppRole 우선(`--auth-mode approle`)
  - 부트스트랩/비상 관리자 작업: root token(`--auth-mode root`)
- 언실(unseal)과 런타임 인증 주입은 별도 단계입니다. 언실이 끝났다고
  OpenBao 인증 요구가 사라지지는 않습니다.

## CA 번들(trust) 운영

이 섹션은 `trust.ca_bundle_path`와 `trust.trusted_ca_sha256`의 운영
기준을 설명합니다.

- `trust.ca_bundle_path`와 `trust.trusted_ca_sha256`를 구성하면
  bootroot-agent는 발급 응답에서 리프 인증서와 체인을 분리합니다.
  리프 인증서/키는 서비스 경로에 저장하고, 체인(중간/루트)은
  `trust.ca_bundle_path`에 저장합니다.
- `trust.trusted_ca_sha256`가 설정되어 있으면 체인 지문 검증을 통과한 경우에만
  번들을 저장합니다. 지문이 불일치하면 발급이 실패합니다.
- 응답에 체인이 없으면 CA 번들은 갱신하지 않으며 로그에 경고를 남깁니다.
- bootroot-agent는 기본적으로 ACME 서버(step-ca)의 TLS 인증서를
  검증합니다. trust 설정이 있으면 관리되는 번들과 지문을 사용하고,
  없으면 시스템 CA 저장소를 사용합니다.
- CLI 오버라이드: `bootroot-agent --insecure`
  (해당 실행에서만 검증 비활성화).
- managed onboarding 흐름에서는 첫 `bootroot-agent` 실행 전에 trust를
  준비합니다.
  - `local-file`: `bootroot service add`가 trust 설정과
    `ca-bundle.pem`을 로컬에 기록하고, 실행 중인 bootroot-agent의
    fast-poll 루프가 계속 동기화합니다.
  - `remote-bootstrap`: `bootroot service add`가 OpenBao에 trust 상태를
    기록하고, `bootroot-remote bootstrap`이 서비스 머신에 trust 설정과
    CA 번들을 반영합니다.

권한/소유권:

- CA 번들을 **읽는 서비스**가 파일을 읽을 수 있어야 합니다.
- 가장 단순한 방법은 bootroot-agent와 서비스가 **같은 계정/그룹**으로
  실행되도록 맞추는 것입니다.

## Trust 회전

CA 인증서를 갱신하거나 교체한 후, `bootroot rotate trust-sync`를 실행해
갱신된 지문과 번들 PEM을 전파합니다:

```bash
bootroot rotate trust-sync --yes
```

이 명령은:

1. `secrets/certs/` 아래의 루트/중간 CA 인증서에서 SHA-256 지문을 계산합니다.
2. 지문과 연결된 PEM 번들을 OpenBao(`bootroot/ca`)에 기록합니다.
3. 로컬과 원격을 가리지 않고 등록된 서비스마다
   `bootroot/services/<name>/trust`에 trust 페이로드를 기록합니다.

`trust-sync` 이후에는 어느 전달 모드든 호스트별 조치가 필요 없습니다. 실행
중인 `bootroot-agent`의 fast-poll 루프가 갱신된
`bootroot/services/<name>/trust` payload를 읽어 `agent.toml` `[trust]` 핀을
다시 렌더링하고 `ca-bundle.pem`을 약 1 fast-poll 주기 내에 다시 기록합니다.
`remote-bootstrap` 서비스의 경우 `bootroot-remote bootstrap` 재실행은
에이전트가 `secret_id_ttl`을 넘겨 오프라인 상태였고 더 이상 스스로 갱신할 수
없는 경우의 복구 경로일 뿐입니다.

## 강제 재발급

서비스의 인증서/키를 삭제하고 bootroot-agent가 재발급하도록 하려면:

```bash
bootroot rotate force-reissue --registration-id edge-proxy --yes
```

`local-file` 서비스의 경우 기록된 cert/key 파일을 삭제하고 bootroot-agent
호스트 데몬에 SIGHUP을 보내(데몬의 설정 경로에 대한 `pkill -HUP`) 다음
루프 틱에 재발급하게 합니다. `remote-bootstrap` 서비스의 경우 OpenBao KV에
버전이 부여된 reissue 요청을 기록하며, 원격 에이전트의 fast-poll 루프가
대략 한 폴링 주기 안에 이를 적용합니다
([CLI > rotate force-reissue](cli.md) 참고).

## 컨테이너화된 소비 애플리케이션

로컬 실행 모델은 데몬 전용입니다: `bootroot-agent`는 항상 호스트 데몬으로
실행되며 Docker 사이드카로는 절대 실행되지 않습니다 — 인증서를 소비하는
애플리케이션이 컨테이너로 동작하는 경우에도 마찬가지입니다. 지원되는
패턴:

1. 호스트 데몬이 cert/key를 호스트 디렉터리(`service add` 시점의
   `--cert-path`/`--key-path`)에 기록합니다.
2. 애플리케이션 컨테이너가 그 디렉터리를 bind-mount(읽기 전용)합니다.
3. post-renew 훅이 갱신 때마다 컨테이너를 리로드합니다:
   `--reload-style docker-restart --reload-target <container>`. 대상은
   명시적 컨테이너 이름이며, 폴백이나 자동 탐색은 없습니다.

```bash
bootroot service add --registration-id web-app --service-name web-app \
  --delivery-mode local-file \
  --cert-path /opt/web-app-mtls/web-app-cert.pem \
  --key-path /opt/web-app-mtls/web-app-key.pem \
  --reload-style docker-restart --reload-target web-app \
  ...
```

컨테이너 프로세스가 bind-mount된 키를 읽어야 하는 비루트 사용자로
동작한다면 `--cert-group`을 사용하세요
([CLI > bootroot service add](cli.md) 참고).

### `docker-restart` 훅과 하드닝 유닛의 관계

post-renew 훅은 데몬 프로세스 안에서 실행되므로 유닛의 권한이 훅이 할 수
있는 일의 한계를 정합니다. 위의
[하드닝된 비루트 유닛](#하드닝된-systemd-유닛-예시)에서는 데몬이 Docker
소켓에 접근할 수 없어 `docker-restart` 훅이 실패합니다. 선택지는 두
가지입니다:

- 가능하면 소켓이 필요 없는 리로드를 우선하세요: `--reload-style sighup`,
  `--reload-style systemd`, 또는 Docker 소켓이 필요 없는 사용자 지정
  `--post-renew-command`.
- 컨테이너를 반드시 Docker 소켓으로 재시작해야 한다면 유닛에
  `SupplementaryGroups=docker`를 추가하세요. 트레이드오프를 분명히 해야
  합니다: Docker 소켓 접근은 루트와 동급이므로 비루트 하드닝이
  약해집니다 — 에이전트 프로세스가 침해되면 소켓을 통해 루트로 권한
  상승할 수 있습니다.
