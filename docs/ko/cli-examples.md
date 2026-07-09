# CLI 예제

이 섹션은 **실전과 유사한 흐름**을 기준으로 `bootroot` CLI를 사용하는
전체 과정을 예제로 보여줍니다. 출력은 **CLI 결과를 최대한 생략 없이**
담았으며, 환경에 따라 일부 값은 다를 수 있습니다.

## 사전 준비

- Docker/Docker Compose 설치
- 80/443/8200/9000/5433/8080 포트 사용 가능 (호스트 측 `PostgreSQL`은
  기본값 5433을 사용합니다. `POSTGRES_HOST_PORT` 또는
  `bootroot infra install --postgres-host-port <N>`로 재정의 가능)

Docker 데몬은 **재부팅 시 자동 시작**되도록 설정되어 있어야 합니다.
bootroot가 제공하는 컨테이너들은 `restart` 정책으로 자동 재기동되지만,
Docker 데몬 자체는 OS에서 systemctl 등으로 별도 관리해야 합니다.

> 참고: 아래 예제는 **step-ca가 실행되는 동일 머신**에서
> OpenBao/PostgreSQL/HTTP-01 리스폰더를 함께 기동하는 구성을 전제로 합니다.

## 1) infra install

```bash
bootroot infra install
```

새로 클론한 환경에서 가장 먼저 실행하는 명령입니다. 임의의 PostgreSQL
비밀번호가 포함된 `.env`를 생성하고, `secrets/` 및 `certs/` 디렉터리를
만들고, 이미지 pull/build 후 Docker Compose 서비스를 기동합니다.
수동 환경 변수 설정이나 이미지 준비가 필요하지 않습니다.

예시 출력:

```text
bootroot 인프라 기동: 준비 상태 요약
- openbao: running (health: healthy)
- postgres: running (health: healthy)
- bootroot-http01: running (health: healthy)
- step-ca: 검사 생략 (init에서 부트스트랩 예정)
bootroot infra install: 완료
```

이미 구성된 환경을 다시 시작하려면 `bootroot infra up`을 사용하세요.

## 2) init

> 최소 입력 요약:
>
> - OpenBao가 **미초기화**라면 초기화를 먼저 수행해야 하며,
>   초기화 후 생성된 `root token`/`unseal keys`를 사용
> - OpenBao가 **초기화되었지만 언실되지 않았다면** `unseal keys` 필요
> - `bootroot infra install` 이후라면 DB 자격증명이 `.env`에서 자동으로
>   제공되므로 `--enable db-provision`으로 PostgreSQL 역할/DB를
>   자동 프로비저닝할 수 있습니다(수동 `--db-dsn` 불필요)
> - step-ca 비밀번호는 `--enable auto-generate`로 자동 생성 가능
> - `--responder-url`을 주면 responder 검증을 수행 (없으면 스킵)
> - step-ca 부트스트랩(`step ca init`)은 `init` 내부에서 자동 실행

```bash
bootroot init --enable auto-generate,db-provision \
  --summary-json ./tmp/init-summary.json \
  --responder-url "http://localhost:8080"
```

예시 대화/출력(전체):

```text
OpenBao root token: ********
OpenBao unseal key (comma-separated): key-1,key-2,key-3
Overwrite password.txt? [y/N]: y
Overwrite ca.json? [y/N]: y
Proceed with init? [y/N]: y

bootroot init: 요약
- OpenBao URL: http://localhost:8200
- KV 마운트: secret
- 시크릿 디렉터리: secrets
- OpenBao 초기화: 완료 (shares=5, threshold=3)
- 루트 토큰: ********
- 언실 키 1: ********
- 언실 키 2: ********
- 언실 키 3: ********
- step-ca 비밀번호: ********
- DB DSN: ********
- DB 프로비저닝: 완료
- responder HMAC: ********
- EAB: 미설정
- step-ca 초기화: 완료
- responder 점검: ok
- DB 호스트 해석: localhost -> postgres
- OpenBao KV 경로:
  - bootroot/stepca/password
  - bootroot/stepca/db
  - bootroot/http01/hmac
  - bootroot/ca
  - bootroot/agent/eab
- summary json: ./tmp/init-summary.json
자동 언실을 위해 언실 키를 파일에 저장할까요? [y/N]: y
다음 단계:
  - AppRole/secret_id를 서비스에 연결하세요.
  - OpenBao Agent/bootroot-agent 실행을 준비하세요.
```

자동화에서는 사람용 요약 텍스트를 파싱하지 말고
`./tmp/init-summary.json`에서 root token 같은 민감 필드를 읽으세요.

## 3) service add

`bootroot service add`의 `--delivery-mode`는 서비스 설정 반영 경로를 고르는
옵션입니다.

- 기본값: `local-file`
- `local-file`: 서비스가 step-ca/OpenBao/responder와 **같은 머신**에 추가될 때 사용
- `remote-bootstrap`: 서비스가 step-ca/OpenBao/responder와 **다른 머신**에
  추가될 때 사용
- `--dry-run`, `--print-only`: 둘 다 프리뷰 모드로 동작하며 파일/state를
  변경하지 않습니다.
- 프리뷰에서 trust 스니펫을 보려면 `--root-token`을 함께 지정해야 합니다.
- `--root-token` 없이 프리뷰를 실행하면 trust 스니펫을 출력하지 못한 이유가
  함께 출력됩니다.

아래 3-1/3-2는 기본값(`local-file`) 예제이고, 3-3은
`remote-bootstrap` 예제입니다.

> 참고: 아래 출력의 `secrets/...` 경로는 기본 `--secrets-dir secrets` 기준입니다.
> 운영 환경에서 시크릿 루트가 다르면(예: `/etc/bootroot/secrets`) 같은 상대
> 구조로 치환해서 읽으면 됩니다.

### 3-1) local-file (기본값)

```bash
bootroot service add \
  --service-name edge-proxy \
  --hostname edge-node-01 \
  --domain trusted.domain \
  --agent-config /etc/bootroot/agent.toml \
  --cert-path /etc/bootroot/certs/edge-proxy.crt \
  --key-path /etc/bootroot/certs/edge-proxy.key \
  --instance-id 001 \
  --root-token <OPENBAO_ROOT_TOKEN>
```

예시 대화/출력(요약):

```text
OpenBao root token: ********

bootroot 서비스 추가: 요약
- 서비스 이름: edge-proxy
- 호스트명: edge-node-01
- 도메인: trusted.domain
- 전달 모드: local-file
- 정책: bootroot-service-edge-proxy
- AppRole: bootroot-service-edge-proxy
- role_id: ********
- secret_id 경로: secrets/services/edge-proxy/secret_id
- OpenBao 경로: bootroot/services/edge-proxy
Bootroot 자동 반영 항목:
- 자동 반영 bootroot-agent 설정: /etc/bootroot/agent.toml
- 자동 프로비저닝 EAB 파일 (EAB가 설정된 경우에만 존재; --eab-file로
  경로 전달): secrets/services/edge-proxy/eab.json
다음 단계:
운영자 실행 항목 (필수):
  - /etc/bootroot/agent.toml에 프로필(instance_id=001,
    hostname=edge-node-01, domain=trusted.domain,
    cert=/etc/bootroot/certs/edge-proxy.crt,
    key=/etc/bootroot/certs/edge-proxy.key)을 추가하고
    bootroot-agent를 리로드하세요.
daemon 프로필 스니펫:
[[profiles]]
service_name = "edge-proxy"
...
daemon 실행 명령 (systemd ExecStart 또는 셸; EAB 회전이 적용되려면
--eab-file이 필요합니다):
bootroot-agent --config /etc/bootroot/agent.toml \
  --eab-file secrets/services/edge-proxy/eab.json
```

생성된 `agent.toml`은 바로 실행 가능한 완전한 설정입니다: managed 프로필,
`[trust]` 섹션, 최상위 `domain`(`--domain`에서 가져옴),
`[acme].http_responder_hmac`(OpenBao에 저장된 리스폰더 HMAC에서 가져옴),
그리고 에이전트의 fast-poll 자체 인증 루프를 활성화하는 `[openbao]`
섹션(서비스별로 키가 부여된 절대 경로 `state_path`가 `agent.toml` 옆에
프로비저닝됨)을 포함합니다. HTTP-01 검증 FQDN도 `bootroot-http01`
컨테이너에 DNS 별칭으로 자동 등록됩니다. `bootroot-agent` 실행 전에 수동
편집이 필요하지 않으며, 출력된 실행 명령으로 호스트 데몬으로 실행하세요
(`--eab-file`을 유지해야 합니다).

### 3-2) local-file: 컨테이너화된 소비 애플리케이션

bootroot-agent 자체는 여전히 호스트 데몬으로 실행됩니다. 컨테이너로
동작하는 애플리케이션이라면 `--cert-path`/`--key-path`를 컨테이너가
bind-mount하는 호스트 디렉터리로 지정하고, 명시적 컨테이너 이름과 함께
`docker-restart` post-renew 훅을 설정하세요:

```bash
bootroot service add \
  --service-name web-app \
  --hostname web-01 \
  --domain trusted.domain \
  --agent-config /srv/bootroot/agent.toml \
  --cert-path /opt/web-app-mtls/web-app.crt \
  --key-path /opt/web-app-mtls/web-app.key \
  --instance-id 001 \
  --reload-style docker-restart \
  --reload-target web-app \
  --root-token <OPENBAO_ROOT_TOKEN>
```

bind-mount 패턴과 하드닝 유닛/Docker 소켓 트레이드오프는
[운영 > 컨테이너화된 소비 애플리케이션](operations.md)을 참고하세요.

### 3-3) remote-bootstrap 전달 모드 + 일회성 bootstrap

전송 옵션, `secret_id` 위생, 아티팩트 스키마 참조를 포함한 전체 운영자
가이드는 [원격 부트스트랩 운영자 가이드](remote-bootstrap.md)를 참고하세요.

제어 노드 온보딩(아티팩트 생성):

```bash
bootroot service add \
  --service-name edge-remote \
  --delivery-mode remote-bootstrap \
  --hostname edge-node-02 \
  --domain trusted.domain \
  --agent-config /srv/bootroot/agent.toml \
  --cert-path /srv/bootroot/certs/edge-remote.crt \
  --key-path /srv/bootroot/certs/edge-remote.key \
  --instance-id 101 \
  --root-token <OPENBAO_ROOT_TOKEN>
```

원격 노드 일회성 bootstrap (권장 `--artifact` 호출 방식):

```bash
bootroot-remote bootstrap \
  --artifact /srv/bootroot/secrets/services/edge-remote/bootstrap.json \
  --output json
```

래핑이 활성(기본값)이면 아티팩트에 `wrap_token`이 포함되며,
`bootroot-remote`가 런타임에 이를 언래핑하여 `secret_id`를 얻습니다.
민감한 토큰이 셸 명령줄과 `ps` 출력에 노출되지 않습니다.
아래의 개별 CLI 플래그 방식은 래핑을 비활성화(`--no-wrap`)했을 때
사용하는 대체 호출 형태로, 언래핑된 `secret_id`와 연결 필드를
아티팩트에서 읽는 대신 직접 전달합니다:

```bash
bootroot-remote bootstrap \
  --openbao-url http://127.0.0.1:8200 \
  --kv-mount secret \
  --service-name edge-remote \
  --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id \
  --secret-id-path /srv/bootroot/secrets/services/edge-remote/secret_id \
  --eab-file-path /srv/bootroot/secrets/services/edge-remote/eab.json \
  --agent-config-path /srv/bootroot/agent.toml \
  --agent-email admin@example.com \
  --agent-server https://stepca.internal:9000/acme/acme/directory \
  --agent-domain trusted.domain \
  --agent-responder-url http://responder.internal:8080 \
  --profile-hostname edge-node-02 \
  --profile-instance-id 101 \
  --profile-cert-path /srv/bootroot/certs/edge-remote.crt \
  --profile-key-path /srv/bootroot/certs/edge-remote.key \
  --ca-bundle-path /srv/bootroot/certs/ca-bundle.pem \
  --summary-json /srv/bootroot/tmp/edge-remote-summary.json \
  --output json
```

`bootroot-remote bootstrap`은 서비스 설정 번들(`secret_id`, `eab`,
`responder_hmac`, `trust`)을 1회 pull+apply합니다.
`bootroot service add`가 출력하는 `원격 실행 명령 템플릿`은 `--artifact`
플래그를 사용하므로, `--agent-server`와 `--agent-responder-url` 값은
명령줄이 아닌 아티팩트에서 읽힙니다. 서비스 머신이 기본 localhost 엔드포인트에
접근할 수 없는 경우, 아티팩트 전송 전에 `bootstrap.json`을 편집하여 원격 접근
가능 값(예: `stepca.internal`, `responder.internal`)으로 교체하세요.

### 3-4) 갱신 후 훅 (리로드 스타일 프리셋)

`--reload-style`과 `--reload-target`을 사용하면
인증서 갱신 후 서비스를 리로드하는 post-renew 훅을
설정할 수 있습니다:

```bash
bootroot service add \
  --service-name edge-proxy \
  --hostname edge-node-01 \
  --domain trusted.domain \
  --agent-config /etc/bootroot/agent.toml \
  --cert-path /etc/bootroot/certs/edge-proxy.crt \
  --key-path /etc/bootroot/certs/edge-proxy.key \
  --instance-id 001 \
  --reload-style systemd \
  --reload-target nginx \
  --root-token <OPENBAO_ROOT_TOKEN>
```

이 명령은 생성된 `agent.toml` 프로필에
`[profiles.hooks.post_renew]` 항목을 추가하여
갱신 성공 시마다 `systemctl reload nginx`를
실행합니다. 다른 프리셋 스타일로는
`sighup`(`pkill`로 `SIGHUP` 전송),
`docker-restart`(`docker restart` 실행),
`none`(훅 없음)이 있습니다. 세부 제어가 필요하면
저수준 플래그 `--post-renew-command`,
`--post-renew-arg`, `--post-renew-timeout-secs`,
`--post-renew-on-failure`를 사용하세요.

control node에서 secret_id 회전 후에는 *실행 중인* 원격 `bootroot-agent`가
fast-poll 루프로 새 secret_id를 직접 받아오므로 수동 전달이 필요하지 않습니다.
아래 명령은 `secret_id_ttl`이 지나도록 오프라인이어서 자격 증명이 이미 만료된
에이전트를 위한 **복구** 경로일 뿐입니다:

```bash
bootroot-remote apply-secret-id \
  --openbao-url http://127.0.0.1:8200 \
  --kv-mount secret \
  --service-name edge-remote \
  --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id \
  --secret-id-path /srv/bootroot/secrets/services/edge-remote/secret_id
```

### 3-5) service update (정책 변경)

`service add`를 다시 실행하지 않고 서비스별 `secret_id` 정책을 변경하려면:

```bash
bootroot service update --service-name edge-proxy --secret-id-ttl 12h
```

서비스의 응답 래핑을 비활성화하려면:

```bash
bootroot service update --service-name edge-proxy --no-wrap
```

기본 래핑 동작을 복원하려면:

```bash
bootroot service update --service-name edge-proxy --secret-id-wrap-ttl inherit
```

정책 변경 후 다음 회전에 적용:

```bash
bootroot rotate approle-secret-id --service-name edge-proxy
```

## 4) HTTP-01 검증을 위한 DNS 해석

`bootroot service add`는 서비스의 검증 FQDN
(`<instance_id>.<service_name>.<hostname>.<domain>`)을 `bootroot-http01`
컨테이너에 Docker 네트워크 별칭으로 자동 등록합니다. 따라서 step-ca가 별도
설정 없이 해당 FQDN을 리스폰더로 해석할 수 있습니다.

`bootroot-http01`이 재시작된 경우(예: `docker compose down` / `up`),
`bootroot infra up`이 `state.json`에서 별칭을 자동으로 재적용합니다.

Compose 이외의 환경이나 수동 해석이 필요한 경우 step-ca 컨테이너의
`/etc/hosts`에 항목을 추가하세요:

```bash
RESPONDER_IP="$(docker inspect -f \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  bootroot-http01)"
docker exec bootroot-ca sh -c \
  "printf '%s %s\n' \"$RESPONDER_IP\" \
  '001.edge-proxy.edge-node-01.trusted.domain' >> /etc/hosts"
```

## 5) service verify

```bash
bootroot verify --service-name edge-proxy
```

DB 연결/인증까지 함께 검증하려면:

```bash
bootroot verify --service-name edge-proxy --db-check
```

예시 대화/출력(전체):

```text
bootroot 검증: 요약
- 서비스 이름: edge-proxy
- 결과: ok
```

`bootroot verify`는 **실제 발급이 가능한지**를 one-shot으로 확인합니다.
검증 이후에도 주기적 갱신을 원하면 bootroot-agent를 **상시 모드**
로 실행해야 합니다(oneshot 없이 실행).

## 6) 서비스 구동(상시 모드)

여기서 “상시 모드”는 one-shot 검증이 아니라 **지속 실행**으로
인증서를 주기적으로 갱신하는 운용 모드를 뜻합니다.

bootroot-agent는 **호스트 데몬**으로 실행합니다 — 서비스별 OpenBao
Agent도, Docker 사이드카도 없습니다. **서로 다른 서비스마다**
`bootroot-agent` 프로세스 하나와 agent 구성 하나를 실행하세요.
`[openbao]` 섹션은 AppRole 자격증명을 하나만 담으므로 서로 다른 서비스가
하나의 `agent.toml`을 공유할 수 없습니다. 하나의 구성에 여러
`[[profiles]]`를 두는 것은 같은 서비스의 인스턴스에 대해서만 지원되며,
이런 인스턴스를 추가할 때 `agent.toml`을 갱신하고 데몬을 리로드하세요.
프로세스 종료 시 자동 재기동되도록 systemd에서
`Restart=always`(또는 `on-failure`)를 설정하는 것을 권장합니다
([운영 > 하드닝된 systemd 유닛 예시](operations.md) 참고).

`service add`가 출력한 실행 명령을 사용하세요 — EAB 회전이 적용되려면
`--eab-file`이 필수입니다:

```bash
bootroot-agent --config /etc/bootroot/agent.toml \
  --eab-file /path/to/secrets/services/edge-proxy/eab.json
```

예시 출력:

```text
Loaded 1 profile(s).
Issuing certificate for 001.edge-proxy.edge-node-01.trusted.domain
Certificate issued successfully.
```

컨테이너로 동작하는 애플리케이션의 경우에도 같은 호스트 데몬이 컨테이너가
bind-mount하는 호스트 디렉터리에 cert/key를 기록하고, `docker-restart`
post-renew 훅이 갱신 때마다 컨테이너를 재시작합니다(3-2절 참고).

예시 출력:

```text
Loaded 1 profile(s).
Issuing certificate for 001.web-app.web-01.trusted.domain
Certificate issued successfully.
```

## 7) 시크릿 회전(예시)

bootroot의 `rotate`는 **시크릿 회전**(step-ca 비밀번호, DB, HMAC, AppRole)을
수행합니다. **인증서 갱신**은 `bootroot-agent`가 처리합니다. EAB 자격증명은
bootroot가 회전하지 않습니다. 번들된 OSS step-ca는 EAB를 지원하지 않으며,
EAB를 지원하는 CA를 사용할 때는 운영자가 OpenBao KV에 직접 새 자격증명을
기록합니다.

모든 시크릿을 갱신하는 예:

```bash
bootroot rotate stepca-password
bootroot rotate db \
  --db-admin-dsn "postgresql://admin:***@127.0.0.1:5433/postgres"
bootroot rotate responder-hmac
bootroot rotate openbao-recovery --rotate-root-token

# 등록된 모든 서비스의 secret_id를 한 번의 호출로 회전
# (서비스별 대상 지정은 --service-name으로 계속 가능)
bootroot rotate approle-secret-id --all-services

# 인프라 OpenBao Agent가 사용하는 인프라 AppRole secret_id 회전
# (위에서 사용한 runtime-rotate 자격증명이 아니라
# bootroot-infra-rotate-role 자격증명 필요)
bootroot rotate \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  --yes \
  approle-secret-id --infra stepca
bootroot rotate \
  --auth-mode approle \
  --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
  --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
  --yes \
  approle-secret-id --infra responder

# CA trust 데이터를 OpenBao와 모든 서비스에 동기화
bootroot rotate trust-sync

# 특정 서비스의 인증서 강제 재발급
bootroot rotate force-reissue --service-name edge-proxy

# remote-bootstrap 서비스를 강제 재발급하고 원격 agent가 반영할 때까지
# 대기(OpenBao reissue KV 경로의 completed_at 폴링).
bootroot rotate force-reissue \
  --service-name edge-remote --wait --wait-timeout 90s
```

OpenBao 복구 자격증명 수동 회전(언실 키 + 루트 토큰):

```bash
bootroot rotate \
  --openbao-url http://localhost:8200 \
  --root-token "$OPENBAO_ROOT_TOKEN" \
  --yes \
  openbao-recovery \
  --rotate-unseal-keys \
  --rotate-root-token \
  --unseal-key-file ./secure/openbao-unseal-keys.txt \
  --output ./secure/openbao-recovery-rotated.json
```

CA 키 회전(중간 CA만):

```bash
bootroot rotate \
  --compose-file docker-compose.yml \
  --openbao-url http://localhost:8200 \
  --auth-mode approle \
  --approle-role-id "$ROTATE_ROLE_ID" \
  --approle-secret-id "$ROTATE_SECRET_ID" \
  --yes \
  ca-key --cleanup
```

CA 키 회전(전체 — 루트 + 중간):

```bash
bootroot rotate \
  --compose-file docker-compose.yml \
  --openbao-url http://localhost:8200 \
  --auth-mode approle \
  --approle-role-id "$ROTATE_ROLE_ID" \
  --approle-secret-id "$ROTATE_SECRET_ID" \
  --yes \
  ca-key --full --cleanup
```

CA 키 회전 후 모든 서비스에 대해 인증서 강제 재발급:

```bash
bootroot rotate force-reissue --service-name edge-proxy
bootroot rotate force-reissue --service-name web-app
```

주기 실행(예: cron, 모든 회전 스텝을 한 번에 실행하는 스크립트):

```bash
#!/usr/bin/env bash
set -euo pipefail

bootroot rotate stepca-password --yes
bootroot rotate db --yes \
  --db-admin-dsn "postgresql://admin:***@127.0.0.1:5433/postgres"
bootroot rotate responder-hmac --yes
```

```crontab
# 매일 새벽 3시
0 3 * * * /usr/local/bin/bootroot-rotate-all.sh
```

> 실제 운영 정책에 맞춰 주기/대상을 조정하세요.

## 8) 모니터링(예시)

LAN 전용으로 모니터링 기동:

```bash
bootroot monitoring up --profile lan --grafana-admin-password admin
```

공개 프로필로 모니터링 기동:

```bash
bootroot monitoring up --profile public --grafana-admin-password admin
```

상태 확인:

```bash
bootroot monitoring status
```

접속 URL:

- `lan`: `http://<LAN-IP>:3000` (기본값이면 `http://127.0.0.1:3000`)
- `public`: `http://<공인-IP>:3000`

Grafana 관리자 비밀번호 초기화 후 재기동:

```bash
bootroot monitoring down --reset-grafana-admin-password
bootroot monitoring up --profile lan --grafana-admin-password newpass
```
