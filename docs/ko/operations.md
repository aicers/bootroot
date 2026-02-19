# 운영

이 섹션은 운영 체크리스트와 장애 대응 절차에 집중합니다. 설치/설정은
**설치**와 **설정** 섹션을 참고하세요.
CLI 명령 자체는 [CLI 문서](cli.md)를 참고하세요.

CI/테스트 운영 기준은 [CI/E2E](e2e-ci.md)를 참고하세요.

## 자동화 경계(필독)

bootroot 자동화 범위:

- 설정/산출물 생성 및 갱신(`agent.toml`, `agent.hcl`, `agent.toml.ctmpl`,
  `token`, sync 관련 파일)
- 서비스 추가 시 전달 모드별 상태 기록과 동기화 데이터 준비
- rotate/verify/status 등 운영 명령 실행 흐름 제공

운영자 책임 범위:

- 바이너리 설치/업데이트(`bootroot`, `bootroot-agent`, `bootroot-remote`,
  OpenBao Agent)
- 프로세스 상시 실행 보장(시작/재시작/부팅 시 자동 시작)
- 런타임 통합(`docker compose` 또는 `systemd`)

정책 요약:

- Compose 경로는 권장 운영 경로입니다.
- systemd 경로도 지원하지만, 동일 신뢰성 요건(상시 실행/재시작/의존성)을
  운영자가 직접 충족해야 합니다.
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
  서비스별 전달 모드/항목별 sync-status 등 현재 상태 확인
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
- `bootroot-remote`는 서비스별 timer/cron으로 주기 실행하고, 중복 실행 방지
  잠금(`flock`)을 적용합니다.
- 점검 순서:
  `systemctl status <unit>` -> `journalctl -u <unit> -n 200`
  -> `bootroot verify --service-name <service>`.

## 회전 스케줄링

`bootroot rotate ...`는 크론/systemd 타이머로 주기 실행합니다. 토큰 등
민감값은 환경 파일이나 안전한 저장소로 관리하세요.
`bootroot rotate` 계열 명령은 OpenBao root token이 필요하며,
`--root-token` 또는 `OPENBAO_ROOT_TOKEN`으로 전달할 수 있습니다
(없으면 프롬프트 입력).

예시(크론):

```cron
0 3 * * 0 OPENBAO_ROOT_TOKEN=... bootroot rotate stepca-password --yes
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

## 원격 sync 주기 실행 운영

`--delivery-mode remote-bootstrap`으로 추가한 대상은
`bootroot-remote sync`를 주기 실행해야 합니다.
다음 템플릿 파일을 제공합니다.

- `scripts/bootroot-remote-sync.service`
- `scripts/bootroot-remote-sync.timer`
- `scripts/bootroot-remote-sync.cron`

권장 패턴:

- 서비스별 주기 실행 작업 1개
- 서비스별 `--summary-json` 경로 분리
- role/secret/token/config 경로를 서비스 단위로 분리
- 중복 실행 방지 잠금 적용(`flock` 등)

최소 환경/설정 체크리스트:

- OpenBao 엔드포인트, KV 마운트
- 서비스 이름, AppRole 파일 경로(`role_id`, `secret_id`)
- EAB 파일 경로, `agent.toml` 경로
- 프로필 식별/경로 입력(hostname, instance_id, cert/key 경로)
- trust sync 사용 시 CA 번들 경로

장애 처리 가이드:

- `bootroot-remote sync`의 retry/backoff/jitter 사용
- `failed`/`expired` 상태가 반복되면 알림 연계
- pull summary JSON과 `bootroot service sync-status`를 함께 확인

systemd timer 권장 예시(중복 실행 방지):

```ini
[Service]
Type=oneshot
ExecStart=/usr/bin/flock -n /var/lock/bootroot-remote-<service>.lock \
  /usr/local/bin/bootroot-remote sync ...
```

수동 반영(예외 상황):

- `bootroot-remote sync`가 만든 summary JSON을 수동 반영해야 할 때만
  아래 명령을 사용합니다.

```bash
bootroot service sync-status \
  --service-name <service> \
  --summary-json <service>-remote-summary.json
```

보안 참고:

- 시크릿 디렉터리 `0700`, 파일 `0600`
- summary JSON은 상태/오류 요약 중심이지만, 운영 로그에는 필요한 범위만 남기고
  장기 보관 정책을 분리하기
- 서비스 계정 권한을 서비스별 경로로 최소화

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
