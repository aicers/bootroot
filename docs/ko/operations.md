# 운영

이 섹션은 운영 체크리스트와 장애 대응 절차에 집중합니다. 설치/설정은
**설치**와 **설정** 섹션을 참고하세요.
CLI 명령 자체는 [CLI 문서](cli.md)를 참고하세요.

CI/테스트 운영 기준은 [CI/E2E](e2e-ci.md)를 참고하세요.

## 자동화 경계(필독)

bootroot 자동화 범위:

- 설정/산출물 생성 및 갱신(`agent.toml`, `agent.hcl`, `agent.toml.ctmpl`,
  `token`, bootstrap 관련 파일)
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

- 서비스 본체와 필요한 에이전트/사이드카가 모두 상시 실행 상태인지 확인합니다.
- `restart: always` 또는 `restart: unless-stopped` 정책을 명시합니다.
- 호스트 재부팅 후 자동 기동되도록 Docker/Compose 서비스 자체를
  systemd 등으로 관리합니다.
- 기본 점검 순서:
  `docker compose ps` -> `docker compose logs --tail=200 <service>`
  -> `bootroot verify --service-name <service>`.

## systemd 운영 절차(지원)

- `bootroot-agent`를 long-running 서비스로 등록하고 `Restart=on-failure`,
  `WantedBy=multi-user.target`를 적용합니다.
- OpenBao Agent를 systemd로 운영한다면 서비스별로 분리하고
  `After=network-online.target` 같은 의존성 순서를 명시합니다.
- 초기 설정 시 서비스별로 `bootroot-remote bootstrap`을 1회 실행하고,
  secret_id 회전 이후에는 `bootroot-remote apply-secret-id`를 실행합니다.
- 점검 순서:
  `systemctl status <unit>` -> `journalctl -u <unit> -n 200`
  -> `bootroot verify --service-name <service>`.

## 회전 스케줄링

`bootroot rotate ...`는 크론/systemd 타이머로 주기 실행합니다. 토큰 등
민감값은 환경 파일이나 안전한 저장소로 관리하세요.
day-2 자동화에서는 root token 대신 AppRole 런타임 인증
(`--auth-mode approle`)을 사용하세요. root token은 부트스트랩/비상
절차용으로만 유지하는 것을 권장합니다.
`bootroot`는 root token 영구 저장소를 기본 제공하지 않습니다.

예시(크론):

```cron
0 3 * * 0 OPENBAO_APPROLE_ROLE_ID=... OPENBAO_APPROLE_SECRET_ID=... \
  bootroot rotate --auth-mode approle stepca-password --yes
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

**서비스별 재정의:**

- `bootroot service add --secret-id-ttl 48h`는 발급 시 TTL을 설정합니다.
- `bootroot service update --secret-id-ttl 48h`는 저장된 정책을
  변경합니다(이후 `bootroot rotate approle-secret-id` 실행 필요).
- `--secret-id-ttl inherit`를 사용하면 서비스별 재정의를 지우고 역할
  수준 기본값으로 복원합니다.

`service add` 시 `--secret-id-ttl`을 생략하면 `bootroot init` 시
설정된 역할 수준 TTL을 상속합니다.

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
bootstrap + 명시적 secret_id handoff입니다.

1. `bootroot service add` 이후 서비스 머신에서 `bootroot-remote bootstrap`을
   1회 실행해 첫 `bootroot-agent` 실행 전에 trust 설정과 CA 번들을 포함한
   초기 설정 번들을 반영합니다.
2. control node에서 `bootroot rotate approle-secret-id` 실행 후, 서비스
   머신에서 `bootroot-remote apply-secret-id`를 실행해 새 secret_id를
   전달합니다.

최소 환경/설정 체크리스트:

- OpenBao 엔드포인트, KV 마운트
- 서비스 이름, AppRole 파일 경로(`role_id`, `secret_id`)
- EAB 파일 경로, `agent.toml` 경로
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

### OpenBao Agent 회전 전파

`local-file` 서비스의 경우, `bootroot rotate approle-secret-id`가 새
`secret_id`를 디스크에 원자적으로 기록하고 서비스별 OpenBao Agent를
리로드합니다. 데몬 모드 배치에서는 에이전트가 `SIGHUP`을 받아 재시작 없이
자격증명을 다시 읽습니다. Docker 배치에서는 에이전트 컨테이너가
재시작됩니다(`docker restart`).

`remote-bootstrap` 서비스의 경우, 회전된 `secret_id`는 서비스별 KV 경로
(`bootroot/services/<service>/secret_id`)에 기록됩니다. 운영자가 서비스
머신에서 `bootroot-remote apply-secret-id`를 실행해야 합니다. 서비스의
OpenBao Agent는 로컬 `secret_id` 파일을 읽고 다음 토큰 갱신 주기에
재인증합니다.

참고: `bootroot-agent` 자체는 `remote-bootstrap` 흐름에서 AppRole로
직접 재인증하지 않습니다. OpenBao Agent가 유지하는 토큰 파일을 소비합니다.

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
3. 원격 서비스마다 `bootroot/services/<name>/trust`에 trust 페이로드를
   기록합니다.
4. 로컬 서비스마다 에이전트 설정의 `[trust]` 섹션을 갱신하고
   `ca-bundle.pem`을 디스크에 기록합니다.

`trust-sync` 이후:

- `local-file`: 로컬 서비스 호스트에 갱신된 trust 설정과 번들이 이미 기록됩니다.
- `remote-bootstrap`: 서비스 호스트에서 `bootroot-remote bootstrap`을 다시
  실행해 갱신된 trust payload와 CA 번들을 반영합니다.

## 강제 재발급

서비스의 인증서/키를 삭제하고 bootroot-agent가 재발급하도록 하려면:

```bash
bootroot rotate force-reissue --service-name edge-proxy --yes
```

로컬 서비스(daemon/docker)의 경우 파일 삭제 후 bootroot-agent에 시그널을
보냅니다. 원격 서비스의 경우 서비스 머신에서 `bootroot-remote bootstrap`을
실행하라는 안내를 출력합니다.

## 기존 도커 배포 서비스를 장기 실행 사이드카로 마이그레이션

이슈 #552 수정 전에 `bootroot service add --deploy-type docker`가 출력하던
사이드카 스니펫은 bootroot-agent를 일회성 컨테이너
(`docker run --rm ... bootroot-agent --config /app/agent.toml --oneshot`)로
실행했습니다. 이 컨테이너는 초기 발급 직후 종료되므로, 해당 설정으로
등록된 서비스는 `bootroot rotate ca-key` Phase 5에서 `docker restart`할
컨테이너가 존재하지 않아 `No such container: <container_name>` 오류로
실패합니다.

`state.json`에 기록된 `--container-name`을 유지한 채, 사이드카를 장기 실행
데몬으로 재생성하세요:

```bash
# 과거 일회성 사이드카가 남아 있다면 먼저 제거합니다.
docker rm -f <container_name> 2>/dev/null || true

# state.json 변경 없이 현재 권장 스니펫만 출력합니다.
bootroot service add --print-only \
  --deploy-type docker \
  --service-name <service> \
  --container-name <container_name> \
  ... (기존 등록과 동일한 나머지 플래그) ...
```

출력된 `docker run -d --restart unless-stopped ...` 명령을 실행하면 호스트
재부팅 후에도 컨테이너가 `Up` 상태로 유지되고, `bootroot rotate ca-key`
Phase 5가 호출하는 `docker restart <container_name>`이 의미 있는 시그널-
갱신 동작이 됩니다.

마이그레이션 없이 회전을 먼저 실행하면, Phase 5가 사라진 컨테이너 이름을
표시하고 위 절차를 안내하는 전용 오류 메시지로 즉시 중단됩니다(이전의
`exit status: 1`과 달리 원인이 명확히 드러납니다).
