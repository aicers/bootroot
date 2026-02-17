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
    role_id: secrets/services/<service>/role_id
    secret_id: secrets/services/<service>/secret_id
다음 단계:
  - AppRole/secret_id를 서비스에 연결하세요.
  - OpenBao Agent/bootroot-agent 실행을 준비하세요.
```

## 3) service add

### 3-1) daemon 서비스 추가

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
    - config: secrets/openbao-agent/apps/edge-proxy.hcl
    - role_id file: secrets/services/edge-proxy/role_id
    - secret_id file: secrets/services/edge-proxy/secret_id
    - ensure secrets/services/edge-proxy is 0700 and
      role_id/secret_id files are 0600
    - run the app-specific OpenBao Agent on the host with
      secrets/openbao-agent/apps/edge-proxy.hcl
  - /etc/bootroot/agent.toml에 프로필(instance_id=001,
    hostname=edge-node-01, domain=trusted.domain,
    cert=/etc/bootroot/certs/edge-proxy.crt,
    key=/etc/bootroot/certs/edge-proxy.key)을 추가하고
    bootroot-agent를 리로드하세요.
```

### 3-2) docker 서비스 추가

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

## 4) 로컬 검증을 위한 DNS/hosts 준비

로컬 환경에서는 step-ca가 `HTTP-01` 검증 대상 FQDN을
리스폰더 컨테이너로 해석할 수 있어야 합니다. 간단히는
step-ca 컨테이너의 `/etc/hosts`에 매핑을 추가합니다.
이 매핑은 **검증용 도메인 → responder 컨테이너 IP**로
강제 연결되도록 만들어, 실제 DNS가 없는 로컬 환경에서도
HTTP-01 검증이 통과되게 합니다.
검증 FQDN은 `<instance_id>.<service_name>.<hostname>.<domain>` 형식입니다.

```bash
RESPONDER_IP="$(docker inspect -f \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  bootroot-http01)"
docker exec bootroot-ca sh -c \
  "printf '%s %s\n' \"$RESPONDER_IP\" \
  '001.edge-proxy.edge-node-01.trusted.domain' >> /etc/hosts"
```

추가된 서비스이 더 있다면, 각 서비스의 FQDN에 대해 동일한 명령을 반복하세요.

> 운영 환경에서는 DNS로 동일한 이름 해석이 되도록 구성하세요.

## 5) app verify

```bash
bootroot verify --service-name edge-proxy
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
openbao agent -config /etc/bootroot/openbao/services/edge-proxy/agent.hcl
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
docker run --rm \
  --name openbao-agent-web-app \
  -v /srv/bootroot/openbao/services/web-app/agent.hcl:/app/agent.hcl:ro \
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
bootroot rotate db --yes
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
