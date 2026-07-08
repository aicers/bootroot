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
bootroot verify --service-name <service> --db-check
bootroot service info --service-name <service>
bootroot monitoring status
```

- `bootroot status`: OpenBao/step-ca/상태 파일 기준의 전체 상태 확인
- `bootroot verify --service-name <service> --db-check`:
  비대화형으로 발급/검증/DB/리스폰더 연동 점검
- `bootroot service info --service-name <service>`:
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
- **호스트 접근:** 로그는 `openbao-audit` Docker 볼륨에 저장됩니다.
  `docker compose exec openbao cat /openbao/audit/audit.log`으로
  확인할 수 있습니다.
- **로테이션:** OpenBao는 감사 로그를 자체적으로 로테이션하지 않습니다.
  외부 로그 로테이션 도구(예: bind-mount의 `logrotate` 또는 볼륨을
  tail하는 사이드카)를 사용하고, 로테이션 후 OpenBao 프로세스에
  `SIGHUP`을 보내 파일 핸들을 다시 열도록 합니다.
- **확인:** `docker compose exec openbao bao audit list`로 감사 장치가
  활성 상태인지 확인합니다.

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
  -> `bootroot verify --service-name <service>`.

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
  두 프로비저닝 경로 — 로컬 `service add`와 `bootroot-remote bootstrap`
  — 모두 기본 제공하는 `state_path` basename을 서비스 이름 기반으로
  설정하므로 서비스별 구성이 fast-poll 상태 파일 충돌 없이 한 디렉터리를
  공유할 수 있으며, bootstrap은 추가로 두 sibling 구성이 여전히 같은
  `state_path`로 해석되면 경고합니다. `docs/ko/remote-bootstrap.md`를
  참고하세요.
- 점검 순서:
  `systemctl status <unit>` -> `journalctl -u <unit> -n 200`
  -> `bootroot verify --service-name <service>`.

### 하드닝된 systemd 유닛 예시

데몬을 비루트 사용자로, 파일시스템 접근을 최소화해 실행하세요.
`ReadWritePaths=`에는 세 위치만 필요합니다: agent 설정 디렉터리
(`agent.toml`과 fast-poll 상태 파일 `bootroot-agent-state-<svc>.json`이
여기에 있음), 인증서 출력 디렉터리, 서비스별 시크릿 디렉터리
(`secret_id`, `eab.json`, `ca-bundle.pem`).

```ini
[Unit]
Description=bootroot-agent certificate daemon
After=network-online.target
Wants=network-online.target

[Service]
# 또는 전용 비루트 계정: User=bootroot-agent
DynamicUser=yes
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

- 서비스에 발급된 파일(`role_id`/`secret_id`/`eab.json` 및 cert/key)은
  유닛의 사용자에게 읽기 가능해야 하며, fast-poll이 갱신하는 파일은
  쓰기도 가능해야 합니다. `DynamicUser=yes`에서는 파일 모드를 넓히기보다
  그룹 권한 부여(예: `--cert-group`과 시크릿 디렉터리의 공유 그룹)를
  권장합니다. 이렇게 적용한 소유권은 회전 후에도 유지됩니다:
  `bootroot rotate approle-secret-id`는 `secret_id`를 기존 파일의
  소유자/그룹을 보존하면서 원자적으로 다시 쓰므로, root로 실행되는
  예약 회전이 non-root 데몬의 자격증명 접근을 차단하지 않습니다.
- post-renew 훅은 이 데몬 프로세스 안에서 실행되므로 유닛의 권한이 훅이
  할 수 있는 일의 한계를 정합니다. `docker-restart`와의 상호작용은
  [컨테이너화된 소비 애플리케이션](#컨테이너화된-소비-애플리케이션)을
  참고하세요.

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
bootroot service add --service-name review \
  --reload-style systemd --reload-target review.service ...

# 직접 실행되는 네이티브 데몬 (pkill -HUP <process-name> 사용)
bootroot service add --service-name review \
  --reload-style sighup --reload-target review ...

# 컨테이너 컨슈머 (`docker restart <container>` 실행)
bootroot service add --service-name aice-web-next \
  --reload-style docker-restart --reload-target aice-web-next ...
```

명시적으로 옵트아웃하려면 `--reload-style none`을 사용하거나, 임의의
명령에는 저수준 `--post-renew-command` / `--post-renew-arg` /
`--post-renew-timeout-secs` / `--post-renew-on-failure` 플래그를
사용하세요.

### 기존 서비스에 훅 재구성

서비스가 `--reload-style` 없이 등록되었더라도 더 이상 제거 후 재등록할
필요가 없습니다: `bootroot service update`가 동일한 훅 플래그를 받아
관리되는 `agent.toml` 프로필 블록을 그 자리에서 다시 렌더링합니다. 이것이
`service add`, `rotate ca-key`, `rotate force-reissue`의 CLI 안내가
운영자에게 가리키는 표준 한 줄 복구 명령입니다.

```bash
bootroot service update --service-name review \
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
bootroot service update --service-name edge-proxy --secret-id-ttl 12h
bootroot service update --service-name edge-proxy --no-wrap
```

이 명령은 `state.json`만 수정합니다. 갱신된 정책을 실제 `secret_id`에
적용하려면 이후 `rotate approle-secret-id`를 실행합니다:

```bash
bootroot rotate approle-secret-id --service-name edge-proxy
```

`"inherit"`를 사용하면 서비스별 오버라이드를 지우고 OpenBao의 AppRole에
설정된 역할 수준 기본값으로 되돌립니다:

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl inherit
bootroot service update --service-name edge-proxy --secret-id-wrap-ttl inherit
```

## 원격 bootstrap 및 secret_id handoff 운영

`--delivery-mode remote-bootstrap`으로 추가한 대상의 운영 모델은 일회성
bootstrap이며, 이후 실행 중인 에이전트는 스스로 자립합니다:

1. `bootroot service add` 이후 서비스 머신에서 `bootroot-remote bootstrap`을
   1회 실행해 첫 `bootroot-agent` 실행 전에 trust 설정과 CA 번들을 포함한
   초기 설정 번들을 반영합니다.
2. 이후 실행 중인 `bootroot-agent`의 fast-poll 루프가 호스트별 운영자 조치
   없이 스스로 최신 상태를 유지합니다: `bootroot/services/<service>/secret_id`
   에서 자신의 `secret_id`를 갱신하고(`secret_id_ttl`을 넘겨서도 유지), control
   node에서 `bootroot rotate approle-secret-id`나 CA/trust 회전이 일어나면
   `bootroot/services/<service>/trust`에서 `agent.toml`의 `[trust]` 핀과
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
(`bootroot/services/<service>/secret_id`)에 기록됩니다. *실행 중인* 원격
`bootroot-agent`는 운영자 조치가 필요 없습니다: fast-poll 루프가 아직 유효한
자격증명으로 그 경로를 읽어 회전된 `secret_id`를 에이전트의 로컬 파일에
원자적으로 기록하고, 다음 재로그인 시 AppRole로 재인증합니다 — 그래서 루프는
수동 작업 없이 `secret_id_ttl`을 넘겨서도 유지됩니다. 같은 루프가
`bootroot/services/<service>/trust`를 읽어 `agent.toml`의 `[trust]` 핀과
`ca-bundle.pem`을 다시 렌더링하므로 CA/trust 회전도 동일한 방식으로
전파됩니다.

`bootroot-remote apply-secret-id`는 정상 상태가 아니라 **복구** 경로입니다:
`secret_id_ttl`을 넘겨 오프라인 상태였던(자격증명이 이미 만료되어 스스로
갱신할 수 없는) 에이전트에 새 `secret_id`를 전달합니다:

```bash
bootroot-remote apply-secret-id --openbao-url https://<ip>:8200 \
  --service-name <svc> --role-id-path <dir>/role_id \
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
    `ca-bundle.pem`을 로컬에 기록하고, 서비스별 OpenBao Agent가 계속
    동기화합니다.
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
bootroot rotate force-reissue --service-name edge-proxy --yes
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
bootroot service add --service-name web-app \
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
