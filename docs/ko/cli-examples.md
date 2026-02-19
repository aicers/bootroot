# CLI 예제

이 섹션은 **실전과 유사한 흐름**을 기준으로 `bootroot` CLI를 사용하는
전체 과정을 예제로 보여줍니다. 출력은 **CLI 결과를 최대한 생략 없이**
담았으며, 환경에 따라 일부 값은 다를 수 있습니다.

## 사전 준비

- Docker/Docker Compose 설치
- 80/443/8200/9000/5432/8080 포트 사용 가능
- step-ca/bootroot-http01 이미지가 로컬에 없으면 먼저 pull/build

이미지 준비 예시:

```bash
docker compose pull openbao postgres
docker compose build step-ca bootroot-http01
```

Docker 데몬은 **재부팅 시 자동 시작**되도록 설정되어 있어야 합니다.
bootroot가 제공하는 컨테이너들은 `restart` 정책으로 자동 재기동되지만,
Docker 데몬 자체는 OS에서 systemctl 등으로 별도 관리해야 합니다.

> 참고: 아래 예제는 **step-ca가 실행되는 동일 머신**에서
> OpenBao/PostgreSQL/HTTP-01 리스폰더를 함께 기동하는 구성을 전제로 합니다.

## 1) infra up

```bash
bootroot infra up
```

> 로컬 이미지가 없으면 pull 경고가 뜰 수 있으므로,
> 사전 준비 단계에서 pull/build를 해 두면 출력이 깔끔합니다.

예시 출력:

```text
bootroot 인프라 기동: 준비 상태 요약
- openbao: running (health: healthy)
- postgres: running (health: healthy)
- step-ca: running (health: healthy)
- bootroot-http01: running (health: healthy)
bootroot 인프라 기동: 완료
```

## 2) init

> 최소 입력 요약:
>
> - OpenBao가 **미초기화**라면 초기화를 먼저 수행해야 하며,
>   초기화 후 생성된 `root token`/`unseal keys`를 사용
> - OpenBao가 **초기화되었지만 언실되지 않았다면** `unseal keys` 필요
> - DB DSN은 반드시 필요 (`--db-dsn` 또는 DB 프로비저닝 옵션)
> - step-ca 비밀번호는 `--auto-generate`로 자동 생성 가능
> - `--responder-url`을 주면 responder 검증을 수행 (없으면 스킵)

```bash
bootroot init --auto-generate \
  --summary-json ./tmp/init-summary.json \
  --db-dsn "postgresql://step:step-pass@postgres:5432/stepca?sslmode=disable" \
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
- responder HMAC: ********
- EAB: 미설정
- step-ca 초기화: 완료
- responder 점검: ok
- DB 점검: 생략
- DB 호스트 해석: localhost -> postgres
- OpenBao KV 경로:
  - bootroot/stepca/password
  - bootroot/stepca/db
  - bootroot/http01/hmac
  - bootroot/ca
  - bootroot/agent/eab
- summary json: ./tmp/init-summary.json
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

### 3-1) local-file (기본값): daemon 서비스 추가

```bash
bootroot service add \
  --service-name edge-proxy \
  --deploy-type daemon \
  --hostname edge-node-01 \
  --domain trusted.domain \
  --agent-config /etc/bootroot/agent.toml \
  --cert-path /etc/bootroot/certs/edge-proxy.crt \
  --key-path /etc/bootroot/certs/edge-proxy.key \
  --instance-id 001 \
  --root-token <OPENBAO_ROOT_TOKEN>
```

예시 대화/출력(전체):

```text
OpenBao root token: ********

bootroot 서비스 추가: 계획
- 서비스 이름: edge-proxy
- 배포 타입: daemon
- 호스트명: edge-node-01
- 도메인: trusted.domain
- instance_id: 001
- 에이전트 설정: /etc/bootroot/agent.toml
- cert 경로: /etc/bootroot/certs/edge-proxy.crt
- key 경로: /etc/bootroot/certs/edge-proxy.key
다음 단계:
  - AppRole: bootroot-service-edge-proxy
  - secret_id 경로: secrets/services/edge-proxy/secret_id
  - OpenBao 경로: bootroot/services/edge-proxy
  - OpenBao Agent (서비스별 인스턴스):
    - config: secrets/openbao/services/edge-proxy/agent.hcl
    - role_id file: secrets/services/edge-proxy/role_id
    - secret_id file: secrets/services/edge-proxy/secret_id
    - ensure secrets/services/edge-proxy is 0700 and
      role_id/secret_id files are 0600
    - run the app-specific OpenBao Agent on the host with
      secrets/openbao/services/edge-proxy/agent.hcl
  - /etc/bootroot/agent.toml에 프로필(instance_id=001,
    hostname=edge-node-01, domain=trusted.domain,
    cert=/etc/bootroot/certs/edge-proxy.crt,
    key=/etc/bootroot/certs/edge-proxy.key)을 추가하고
    bootroot-agent를 리로드하세요.
```

최신 CLI 출력에는 위 정보와 함께
`Bootroot 자동 반영 항목`/`운영자 실행 항목 (필수/권장/선택)` 라벨이 표시되어
자동 처리 범위와 운영자 작업 범위를 명확히 구분해 줍니다.

예시(라벨 중심):

```text
Bootroot 자동 반영 항목:
- 자동 반영 bootroot-agent 설정: ...
- 자동 반영 OpenBao Agent 설정: ...

운영자 실행 항목 (필수):
- OpenBao Agent 실행
- bootroot-agent 실행/리로드

운영자 실행 항목 (선택):
- trust 자동 반영값 대신 수동 trust 고정/오버라이드 적용
```

### 3-2) local-file (기본값): docker 서비스 추가

```bash
bootroot service add \
  --service-name web-app \
  --deploy-type docker \
  --hostname web-01 \
  --domain trusted.domain \
  --agent-config /srv/bootroot/agent.toml \
  --cert-path /srv/bootroot/certs/web-app.crt \
  --key-path /srv/bootroot/certs/web-app.key \
  --instance-id 001 \
  --container-name web-app \
  --root-token <OPENBAO_ROOT_TOKEN>
```

예시 대화/출력(전체):

```text
OpenBao root token: ********

다음 단계:
  - web-app 사이드카(container=web-app, instance_id=001,
    hostname=web-01, domain=trusted.domain)를
    /srv/bootroot/agent.toml로 실행하고 AppRole bootroot-service-web-app,
    secret_id 파일 secrets/services/web-app/secret_id를 사용하세요.
```

### 3-3) remote-bootstrap 전달 모드 + 원격 sync

제어 노드 온보딩(아티팩트 생성):

```bash
bootroot service add \
  --service-name edge-remote \
  --deploy-type daemon \
  --delivery-mode remote-bootstrap \
  --hostname edge-node-02 \
  --domain trusted.domain \
  --agent-config /srv/bootroot/agent.toml \
  --cert-path /srv/bootroot/certs/edge-remote.crt \
  --key-path /srv/bootroot/certs/edge-remote.key \
  --instance-id 101 \
  --root-token <OPENBAO_ROOT_TOKEN>
```

원격 노드 수렴:

```bash
bootroot-remote sync \
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

`bootroot-remote sync`는 pull과 ack를 함께 수행하며, summary를
`bootroot service sync-status`에 반영해 `secret_id`, `eab`,
`responder_hmac`, `trust_sync` 상태를 갱신합니다.
`state.json` 경로가 기본값이 아닌 경우에만 `--state-file <path>`를 추가하세요.
또한 실제 운영에서는 `bootroot service add` 요약 출력의
`원격 실행 명령`을 그대로 사용하는 것을 권장합니다.

추가 입력 정리:

- sync는 pull 입력(`--openbao-url`, `--kv-mount`, `--service-name`,
  `--role-id-path`, `--secret-id-path`, `--eab-file-path`,
  `--agent-config-path`, baseline/profile 입력, `--ca-bundle-path`)을
  그대로 받습니다.
- `--summary-json`은 sync에서 필수입니다.
- ack 연동용으로 `--bootroot-bin`(기본 `bootroot`), `--state-file`(선택)을
  받을 수 있습니다.
- pull 단계 출력 형식 제어용 `--output text|json`을 받을 수 있습니다.

## 4) DNS/hosts 준비 (CLI 예제 실행용)

이 CLI 예제를 실행하려면 step-ca가 `HTTP-01` 검증 대상 FQDN을
리스폰더 컨테이너로 해석할 수 있어야 합니다. DNS가 아직 준비되지 않은
환경에서는 step-ca 컨테이너의 `/etc/hosts`에 매핑을 추가해
**검증용 도메인 -> responder 컨테이너 IP**로 연결할 수 있습니다.
검증 FQDN은 `<instance_id>.<service_name>.<hostname>.<domain>` 형식입니다.

```bash
RESPONDER_IP="$(docker inspect -f \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  bootroot-http01)"
docker exec bootroot-ca sh -c \
  "printf '%s %s\n' \"$RESPONDER_IP\" \
  '001.edge-proxy.edge-node-01.trusted.domain' >> /etc/hosts"
```

추가된 서비스가 더 있다면, 각 서비스의 FQDN에 대해 동일한 명령을 반복하세요.

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

daemon 서비스:

- bootroot-agent: 데몬 모드
- OpenBao Agent: 서비스별 daemon

bootroot-agent는 **서비스별이 아니라 머신별로 1개**를 데몬으로 실행합니다.
프로필을 추가할 때마다 `agent.toml`을 갱신하고, 데몬을 리로드하세요.
프로세스 종료 시 자동 재기동되도록 systemd에서
`Restart=always`(또는 `on-failure`)를 설정하는 것을 권장합니다.

```bash
openbao agent -config /etc/bootroot/secrets/openbao/services/edge-proxy/agent.hcl
```

```bash
bootroot-agent --config /etc/bootroot/agent.toml
```

예시 출력:

```text
Loaded 1 profile(s).
Issuing certificate for 001.edge-proxy.edge-node-01.trusted.domain
Certificate issued successfully.
```

docker 서비스:

- OpenBao Agent: 사이드카(서비스별 docker 컨테이너)
- bootroot-agent: 사이드카(서비스별 docker 컨테이너)

Docker 서비스도 호스트 통합 bootroot-agent daemon을 사용할 수는 있지만,
지원은 하되 권장하지 않습니다. 격리와 라이프사이클 정합성을 위해 사이드카
패턴을 권장합니다.

```bash
AGENT_HCL=/srv/bootroot/secrets/openbao/services/web-app/agent.hcl
docker run --rm \
  --name openbao-agent-web-app \
  -v "$AGENT_HCL":/app/agent.hcl:ro \
  -v /srv/bootroot/secrets:/app/secrets \
  openbao/bao:latest \
  agent -config /app/agent.hcl
```

```bash
docker run --rm \
  --name web-app \
  -v /srv/bootroot/agent.toml:/app/agent.toml:ro \
  -v /srv/bootroot/certs:/app/certs \
  <bootroot-agent-image> \
  bootroot-agent --config /app/agent.toml
```

예시 출력:

```text
Loaded 1 profile(s).
Issuing certificate for 001.web-app.web-01.trusted.domain
Certificate issued successfully.
```

## 7) 시크릿 회전(예시)

bootroot의 `rotate`는 **시크릿 회전**(step-ca 비밀번호, EAB, DB, HMAC, AppRole)을
수행합니다. **인증서 갱신**은 `bootroot-agent`가 처리합니다.

모든 시크릿을 갱신하는 예:

```bash
bootroot rotate stepca-password
bootroot rotate eab
bootroot rotate db \
  --db-admin-dsn "postgresql://admin:***@127.0.0.1:5432/postgres"
bootroot rotate responder-hmac
bootroot rotate approle-secret-id --service-name edge-proxy
bootroot rotate approle-secret-id --service-name web-app
```

주기 실행(예: cron, 모든 회전 스텝을 한 번에 실행하는 스크립트):

```bash
#!/usr/bin/env bash
set -euo pipefail

bootroot rotate stepca-password --yes
bootroot rotate eab --yes
bootroot rotate db --yes \
  --db-admin-dsn "postgresql://admin:***@127.0.0.1:5432/postgres"
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
