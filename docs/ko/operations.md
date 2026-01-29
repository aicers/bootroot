# 운영

이 섹션은 운영 체크리스트에 집중합니다. 설치/설정은 **설치**와 **설정**
섹션을 참고하세요.
CLI를 사용하는 경우 [CLI 문서](cli.md)를 참고하세요. 이 문서는 **수동 운영**
절차를 기준으로 설명합니다.

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

## 회전 스케줄링

`bootroot rotate ...`는 크론/systemd 타이머로 주기 실행합니다. 토큰 등
민감값은 환경 파일이나 안전한 저장소로 관리하세요.

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

## CA 번들(trust) 운영

`trust` 설정을 켜면 bootroot-agent는 ACME 응답에서 **리프와 체인을 분리**해
리프 인증서/키를 저장하고, 체인(중간/루트)을 `ca_bundle_path`에 저장합니다.
이 번들은 mTLS에서 상대 인증서 검증에 사용됩니다.

- `trust.ca_bundle_path`는 **CA 번들 파일 경로**입니다.
- `trust.trusted_ca_sha256`를 지정하면 응답의 체인이 **지문 검증을 통과해야**
  저장됩니다. 불일치 시 발급이 실패합니다.
- 체인이 없는 응답이라면 CA 번들을 저장하지 않습니다(로그에 남습니다).
- `trust.verify_certificates = true`이면 bootroot-agent가 ACME 서버 TLS
  인증서를 검증합니다. `ca_bundle_path`가 있으면 그 번들을 사용하고,
  없으면 시스템 CA 저장소를 사용합니다.
- CLI 오버라이드: `bootroot-agent --verify-certificates` 또는 `--insecure`.

권한/소유권:

- CA 번들을 **읽는 서비스**가 파일을 읽을 수 있어야 합니다.
- 가장 단순한 방법은 bootroot-agent와 서비스가 **같은 사용자/그룹**으로
  실행되도록 맞추는 것입니다.
