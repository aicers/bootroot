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

## 원격 bootstrap 및 secret_id handoff 운영

`--delivery-mode remote-bootstrap`으로 추가한 대상의 운영 모델은 일회성
bootstrap + 명시적 secret_id handoff입니다.

1. `bootroot service add` 이후 서비스 머신에서 `bootroot-remote bootstrap`을
   1회 실행해 초기 설정 번들을 반영합니다.
2. control node에서 `bootroot rotate approle-secret-id` 실행 후, 서비스
   머신에서 `bootroot-remote apply-secret-id`를 실행해 새 secret_id를
   전달합니다.

최소 환경/설정 체크리스트:

- OpenBao 엔드포인트, KV 마운트
- 서비스 이름, AppRole 파일 경로(`role_id`, `secret_id`)
- EAB 파일 경로, `agent.toml` 경로
- 프로필 식별/경로 입력(hostname, instance_id, cert/key 경로)
- trust 데이터에 `ca_bundle_pem`이 포함된 경우 CA 번들 경로

보안 참고:

- 시크릿 디렉터리 `0700`, 파일 `0600`
- 서비스 계정 권한을 서비스별 경로로 최소화
- `bootroot init --summary-json` 산출물은 `root_token`을 포함할 수 있으므로
  민감 아티팩트로 취급하고 접근/보관 기간을 제한하기

## OpenBao 재기동/복구 체크리스트

- OpenBao가 `sealed` 상태면 먼저 unseal keys로 언실을 완료합니다.
- 언실 완료 후 운영 명령에 맞는 런타임 인증을 주입합니다.
  - day-2 `service add`/`rotate`: AppRole 우선(`--auth-mode approle`)
  - 부트스트랩/비상 관리자 작업: root token(`--auth-mode root`)
- 언실(unseal)과 런타임 인증 주입은 별도 단계입니다. 언실이 끝났다고
  OpenBao 인증 요구가 사라지지는 않습니다.

## CA 번들(trust) 운영

이 섹션은 `trust.ca_bundle_path`, `trust.trusted_ca_sha256`,
`trust.verify_certificates` 3개 값의 운영 기준을 설명합니다.

- `trust.ca_bundle_path`와 `trust.trusted_ca_sha256`를 구성하면
  bootroot-agent는 발급 응답에서 리프 인증서와 체인을 분리합니다.
  리프 인증서/키는 서비스 경로에 저장하고, 체인(중간/루트)은
  `trust.ca_bundle_path`에 저장합니다.
- `trust.trusted_ca_sha256`가 설정되어 있으면 체인 지문 검증을 통과한 경우에만
  번들을 저장합니다. 지문이 불일치하면 발급이 실패합니다.
- 응답에 체인이 없으면 CA 번들은 갱신하지 않으며 로그에 경고를 남깁니다.
- `trust.verify_certificates = true`이면 bootroot-agent가 ACME 서버(step-ca)의
  TLS 인증서를 검증합니다. `ca_bundle_path`가 있으면 그 번들을 사용하고,
  없으면 시스템 CA 저장소를 사용합니다.
- CLI 오버라이드:
  `bootroot-agent --verify-certificates`(해당 실행에서 검증 강제) 또는
  `bootroot-agent --insecure`(해당 실행에서만 검증 비활성화).
- 일반 모드(`--insecure` 없이)에서 첫 발급이 성공하면, bootroot-agent는
  `agent.toml`의 `trust.verify_certificates` 값을 `true`로 자동 기록해
  이후 실행부터 검증 모드로 전환합니다.
- 이 자동 전환 과정에서 파일 쓰기 또는 재로드 검증이 실패하면
  bootroot-agent는 non-zero로 종료합니다.

권한/소유권:

- CA 번들을 **읽는 서비스**가 파일을 읽을 수 있어야 합니다.
- 가장 단순한 방법은 bootroot-agent와 서비스가 **같은 사용자/그룹**으로
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

## 강제 재발급

서비스의 인증서/키를 삭제하고 bootroot-agent가 재발급하도록 하려면:

```bash
bootroot rotate force-reissue --service-name edge-proxy --yes
```

로컬 서비스(daemon/docker)의 경우 파일 삭제 후 bootroot-agent에 시그널을
보냅니다. 원격 서비스의 경우 서비스 머신에서 `bootroot-remote bootstrap`을
실행하라는 안내를 출력합니다.
