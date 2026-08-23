# 설치

이 섹션은 step-ca, PostgreSQL, OpenBao Agent, bootroot-agent, HTTP-01
리스폰더의 설치/배치 원리를 설명합니다.
실제 운영에서는 보통 `bootroot` CLI 자동화를 사용하지만, 이 문서는
**운영자 이해도를 높이기 위해 CLI 자동화를 배제한 수동 관점**으로
구성되어 있습니다.
즉, "CLI가 내부에서 어떤 구성을 만들어 주는지"를 사람이 직접 따라가며
이해할 수 있게 설명합니다.

실제 명령/자동화 흐름은 [CLI](cli.md), [CLI 예제](cli-examples.md)를
함께 참고하세요.

운영자 책임(요약):

- 상시 실행/재시작/의존성 보장은 운영자 책임입니다.
- bootroot는 설정/산출물 생성을 자동화하지만, 바이너리 설치와 프로세스
  생명주기 관리는 운영자가 수행해야 합니다.

## step-ca

### Docker(기본)

이 repo는 공식 사전 빌드 step-ca 이미지(`smallstep/step-ca:0.30.2`)를
실행하는 compose 구성을 제공합니다. 이 이미지는 PostgreSQL 지원을 기본
포함합니다. compose 구성은 step-ca를 빌드하지 않으며, 고정된 공식
이미지를 내려받습니다. 로컬/실험 용도에 가장 간단한 경로입니다.

step-ca를 기동하는 권장 방법은 아래의 `bootroot infra install`이며 전체
스택을 처리합니다. 이 서비스 하나만 직접 기동하려면:

```bash
docker compose up -d step-ca
```

#### step-ca 초기화(최초 1회)

최초 설치 시 권장하는 방법은 다음과 같습니다:

```bash
bootroot infra install
```

이 명령은 임의의 PostgreSQL 비밀번호가 포함된 `.env`를 생성하고,
`secrets/` 및 `certs/` 디렉터리를 만들고, Docker Compose 서비스를
기동합니다(로컬 responder 이미지는 빌드하고 나머지는 내려받음). 수동 파일
생성이나 편집이 필요하지 않습니다.

이미 구성된 환경을 나중에 다시 시작하려면:

```bash
bootroot infra up
```

`bootroot infra install` 이후 `bootroot init`은 step-ca 부트스트랩을
자동으로 처리합니다(수동 `step ca init` 실행이 필요 없습니다).

**수동 대안** (완전한 제어가 필요한 고급 사용자용):

`bootroot infra install`을 사용하지 않는 경우, 수동으로 초기화할 수
있습니다:

```bash
mkdir -p secrets
printf "%s" "<your-password>" > secrets/password.txt

# ./secrets 디렉터리 소유자로 컨테이너에서 init 실행(예시)
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v $(pwd)/secrets:/home/step smallstep/step-ca:0.30.2 \
  step ca init \
  --name "Bootroot CA" \
  --provisioner "admin" \
  --dns "localhost,bootroot-ca" \
  --address ":9000" \
  --password-file /home/step/password.txt \
  --provisioner-password-file /home/step/password.txt \
  --acme
```

컨테이너는 `root`가 아니라 `secrets/` 디렉터리 소유자로 실행하세요.
`--user $(id -u):$(id -g)`는 여러분 자신의 uid/gid를 사용하며, 위의
`mkdir`로 `secrets/`를 직접 소유하게 되므로 올바른 값입니다. Bootroot가
`secrets/`에 대해 실행하는 모든 것 — `password.txt`와 `config/ca.json`을
렌더링하는 OpenBao Agent 사이드카, 그리고 모든 `step` 헬퍼 컨테이너 —
은 그 디렉터리 소유자로 실행됩니다. 따라서 `root`로 생성된 자료는
나머지 트리와 어긋나게 됩니다. Bootroot는 이제 다음 실행 시 이런 어긋남을
복구하지만, 수동 경로에서 애초에 문제를 만들지 않는 것이 좋습니다.

`<your-password>`는 CA 키를 보호(암호화)하는 비밀번호입니다. 운영에서는
충분히 강한 비밀번호로 설정하고, 해당 파일은 외부에 노출되지 않도록
보호하세요. 운영에서는 OpenBao 같은 **시크릿 매니저(Secret Manager)** 를
통해 이 비밀번호를 주입하는 방식을 권장합니다.

초기화가 끝나면 다음 파일들이 생성됩니다(대표 예시):

- `secrets/config/ca.json`
- `secrets/certs/root_ca.crt`
- `secrets/certs/intermediate_ca.crt`
- `secrets/secrets/root_ca_key`
- `secrets/secrets/intermediate_ca_key`

`bootroot init`는 CA 지문을 OpenBao에 저장하므로,
`secrets/certs/root_ca.crt`와 `secrets/certs/intermediate_ca.crt`가
존재해야 합니다. 이 파일이 없으면 `bootroot init`가 실패합니다.

이 문서의 예시는 `-v $(pwd)/secrets:/home/step`로 마운트하기 때문에,
생성된 파일이 컨테이너의 `/home/step`에 만들어지고, 호스트에서는
`./secrets/` 디렉터리로 저장됩니다. 즉, 별도의 위치로 옮기지 말고
`./secrets/` 아래에 그대로 두어야 `secrets/config/ca.json` 경로와
맞춰서 정상 동작합니다.

Bootroot의 기본 배포에서는 step-ca가 HTTPS 엔드포인트에서 CA 인증서를
직접 제시할 수 있습니다. Bootroot는 `bootroot init` 시점에 CA 번들과
대응하는 SHA-256 지문을 OpenBao에 저장하므로, 이후 bootroot-agent는 이
관리되는 신뢰 정보를 사용해 step-ca 엔드포인트를 검증할 수 있습니다.

수동 경로를 사용하는 경우, `secrets/config/ca.json`을 현재 환경에 맞게
갱신해야 합니다:

1. `secrets/config/ca.json`의 `db.type`을 `postgresql`로 설정
2. `db.dataSource`를 실제 DSN으로 교체
3. 변경 후 `step-ca` 컨테이너(또는 서비스) 재시작

재시작 방법:

- Docker Compose:

  ```bash
  docker compose restart step-ca
  ```

- systemd(베어메탈):

  ```bash
  sudo systemctl restart step-ca
  ```

`db.dataSource`는 PostgreSQL 접속 문자열입니다. DSN은 **Data Source Name**
의 약어이며, 데이터베이스 연결 정보를 의미합니다. 형식은 다음과 같습니다.

```text
postgresql://<user>:<password>@<host>:<port>/<db>?sslmode=<mode>
```

예시:

- Docker Compose:
  `postgresql://step:step-pass@postgres:5432/stepca?sslmode=disable`
- 운영(SSL 강제):
  `postgresql://step:<secret>@db.internal:5432/stepca?sslmode=require`

`sslmode=disable` 예시는 step-ca와 PostgreSQL이 같은 머신, 같은 로컬 신뢰
경계 안에 있는 기본 토폴로지 전용입니다. PostgreSQL을 다른 머신이나 다른
네트워크 신뢰 경계로 분리하는 경우에는 이 로컬 예시를 그대로 재사용하지 말고
PostgreSQL TLS와 적절한 `sslmode`를 사용해야 합니다.

**중요**: step-ca가 컨테이너에서 실행 중이면 `db.dataSource`의 호스트는
**컨테이너 내부 기준**입니다. 최종적으로는 Compose 서비스 이름(예:
`postgres`)을 사용해야 합니다.

`bootroot init`의 `--db-dsn`/`--db-admin-dsn` 입력에서는
`localhost`/`127.0.0.1`/`::1`도 허용되며, 내부적으로 `postgres`로
정규화됩니다. 반면 `db.internal` 같은 원격 호스트는 init에서 실패합니다.

`<secret>` 자리는 실제 운영 비밀번호를 넣어야 합니다.

`step-pass`는 이 repo의 **개발용 기본 비밀번호**입니다. `.env`의
`POSTGRES_PASSWORD`와 맞춰져야 하므로, 로컬/Compose 예시에서 동일하게
사용했습니다. 운영에서는 반드시 강한 비밀번호로 변경하세요. 운영에서는
이 DB 비밀번호도 OpenBao 같은 **시크릿 매니저(Secret Manager)** 를 통해
주입하는 방식을 권장합니다.

참고: DB 비밀번호 자동 생성은 `bootroot init`에서
`--enable db-provision,auto-generate`를 함께 사용할 때만 적용됩니다.
`--db-dsn` 경로에서는 DSN에 포함된 비밀번호를 그대로 사용합니다.

`.env` 예시(`bootroot infra install`이 자동 생성하며, 수동 대안
경로에서만 직접 생성이 필요합니다):

```text
POSTGRES_USER=step
POSTGRES_PASSWORD=<random-32-byte-hex>
POSTGRES_DB=stepca
GRAFANA_ADMIN_PASSWORD=admin
BOOTROOT_INSTANCE=bootroot
```

`BOOTROOT_INSTANCE`는 설치본의 정체성이며, 이후 모든 명령이 대상으로
삼는 Docker Compose 프로젝트입니다. `bootroot infra install
--instance-name <name>`으로 설정하고, 다른 모든 명령은 여기서 다시
읽습니다. 자세한 내용은 [CLI](cli.md)의 "인스턴스 정체성과 Compose
프로젝트" 절을 참고하세요.

`sslmode`는 환경 정책에 맞게 `disable`, `require`, `verify-full` 중에서
선택합니다. 운영에서는 `require` 또는 `verify-full`을 권장합니다.

`require`와 `verify-full`의 차이는 다음과 같습니다.

- `require`: TLS는 사용하지만 **서버 인증서의 호스트명 검증은 생략**합니다.
  내부 네트워크이거나 별도 인증서 검증 체계가 없는 경우에 사용합니다.
- `verify-full`: TLS 사용 + **서버 인증서 체인과 호스트명**을 모두 검증합니다.
  운영 환경에서 가장 안전하며, DB 서버의 인증서가 올바르게 설정되어 있어야
  합니다.

선택 기준:

- 운영/보안 우선: `verify-full`
- 내부망 테스트/임시 환경: `require`

`bootroot infra install` 후 `bootroot init --enable db-provision`을 실행하면
DB DSN이 `secrets/config/ca.json`에 자동으로 기록됩니다.

### 단일 호스트 가드레일

비TLS 로컬 모델(`sslmode=disable`)을 사용할 때 bootroot는 단일 호스트
가드레일을 강제합니다.

- DSN의 PostgreSQL 호스트는 로컬 값만 허용됩니다
  (`postgres`, `localhost`, `127.0.0.1`, `::1`).
- init summary에는 DB host 해석 결과가 함께 출력됩니다
  (예: `localhost -> postgres`).
- Compose의 PostgreSQL 포트 publish는 localhost 바인딩만 허용됩니다
  (예: `127.0.0.1:5433:5432` — 기본 publish 포트.
  `POSTGRES_HOST_PORT`로 재정의 가능).
  `0.0.0.0` 바인딩 또는 `5433:5432` 형태는 허용되지 않습니다.

다른 핵심 서비스도 마찬가지입니다. `docker-compose.yml`과
`docker-compose.deploy.yml`은
`127.0.0.1:${OPENBAO_HOST_PORT:-8200}:8200`,
`127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000`,
`127.0.0.1:${HTTP01_ADMIN_HOST_PORT:-8080}:8080`으로 게시합니다.
설정 가능한 것은 호스트 측 포트 번호뿐이며, `<compose-dir>/.env`나
프로세스 환경 변수에 값을 지정하거나 `bootroot infra install`에
`--openbao-host-port` / `--stepca-host-port` /
`--http01-admin-host-port`를 전달하면 됩니다(이 경우 `.env`에도
자동으로 upsert됩니다). 따라서 "비어 있어야 하는 포트"
목록(8200, 9000, 8080, 5433)은 요구 사항이 아니라 기본값이며, 두 개의
bootroot 인스턴스가 한 호스트를 공유할 수 있습니다. 배포되는 compose
파일이 기록된 `--instance-name`에서 컨테이너 이름을 유도하므로 두 번째
인스턴스에 별도의 compose 파일은 필요하지 않습니다.

### 두 번째 인스턴스를 같은 호스트에 배치하기

"별도의 compose 파일이 필요하지 않다"는 것은 *직접 수정한* compose
파일이 필요 없다는 뜻이며, 두 설치본이 하나의 디렉터리를 공유해도
된다는 뜻이 아닙니다. 각 인스턴스는 배포된 compose 파일 사본을 담은
자체 compose 디렉터리가 필요합니다. 설치본을 구분 짓는 요소가 모두
compose 파일 옆에 놓이기 때문입니다.

- `.env`. Compose 프로젝트와 모든 컨테이너 이름을 결정하는
  `BOOTROOT_INSTANCE`, 해당 인스턴스의 `POSTGRES_PASSWORD`,
  `*_HOST_PORT` 항목이 여기에 기록됩니다.
- `secrets/`. step-ca와 OpenBao Agent 사이드카가 bind-mount하는 CA
  자재, 렌더링된 설정, AppRole 자격 증명이 들어 있습니다.
- `bootroot infra install`과 `bootroot init`이 생성하는 오버라이드
  (`secrets/openbao/`, `secrets/responder/`).

compose 파일은 `./openbao`, `./secrets`,
`./responder.toml.compose`를 자신의 디렉터리 기준으로 해석하므로 두 번째
디렉터리에는 compose 파일과 함께 `openbao/openbao.hcl`과
`responder.toml.compose`도 있어야 합니다. 두 설치본을 한 디렉터리로
향하게 하면 위 항목을 모두 공유하고 같은 Compose 프로젝트에 놓이게
되는데, 이는 인스턴스 정체성이 막으려는 바로 그 장애입니다.

반면 두 번째 디렉터리에 없는 것은 빌드 컨텍스트입니다.
`docker-compose.yml`의 `bootroot-http01`은 소스 트리 전체를 복사하는
`docker/http01-responder/Dockerfile`을 `build.context: .`로 선언하고,
`bootroot infra install`은 기본적으로 `docker compose up --build`를
실행합니다. 체크아웃 밖에서는 이 빌드가 읽을 것이 없으므로 두 번째
인스턴스는 `--no-build`로 설치해 첫 번째 설치가 이미 만들어 둔 이미지를
재사용하세요. `--no-build`는 `--pull never`를 함의하는데, 첫 번째 설치가
`bootroot-http01-responder:latest`를 빌드하고 서드파티 이미지도 이미
받아 두었으므로 조건이 충족됩니다.

이 태그는 고정된 이름이 아니라 `docker-compose.yml`의 기본값입니다. 응답기의
`image:`는 `BOOTROOT_HTTP01_IMAGE`를 읽으므로, 이 변수를 설정한 설치는 그
이름으로 빌드합니다. 빌드를 공유해서는 안 되는 두 설치(E2E 라이프사이클
하네스는 실행마다 태그 하나를 씁니다)가 서로 떨어져 있는 방법이기도 합니다.
두 번째 설치는 첫 번째와 같은 값을 해석해야 하며, 그렇지 않으면
`--no-build`가 이미지를 찾지 못합니다.

최소한의 두 번째 인스턴스 구성은 다음과 같습니다.

```bash
mkdir -p /srv/insight/openbao
cp docker-compose.yml /srv/insight/
cp openbao/openbao.hcl /srv/insight/openbao/
cp responder.toml.compose /srv/insight/
cd /srv/insight
bootroot infra install --instance-name insight --no-build \
  --postgres-host-port 5434 --openbao-host-port 8201 \
  --stepca-host-port 9001 --http01-admin-host-port 8081
bootroot init --secrets-dir secrets --responder-url http://127.0.0.1:8081
```

각 인스턴스의 명령은 반드시 해당 인스턴스의 디렉터리에서 실행하세요.
bootroot는 `state.json`을 프로세스 작업 디렉터리 기준으로 해석합니다
(`state.json`이라는 상대 경로 그대로이며, `bootroot service add`에는
`--state-file` 옵션이 없습니다). 따라서 작업 디렉터리가 어떤 상태
파일에 기록할지, 어떤 Compose 프로젝트를 재구성할지, 어떤 OpenBao에
접속할지를 모두 결정합니다. OpenBao URL도 그 디렉터리의 `state.json`에서
가져오기 때문입니다. 잘못된 디렉터리에서 `bootroot service add`를
실행하면 서비스가 다른 인스턴스에 등록됩니다.

마지막으로, 내보낸 `COMPOSE_PROJECT_NAME`은 기록된
`BOOTROOT_INSTANCE`와 명령줄의 `--instance-name` 모두보다
우선합니다(전체 우선순위는 [CLI](cli.md)의
"인스턴스 정체성과 Compose 프로젝트" 절 참고). 셸에 값이 남아 있으면
현재 서 있는 디렉터리의 인스턴스가 아니라 그 프로젝트를 조용히
대상으로 삼으므로, 같은 호스트의 여러 인스턴스를 다루기 전에 해제하세요.

`--openbao-url`을 기본값으로 두면 `bootroot init`, `bootroot status`,
`bootroot reinit`이 기본값이 아닌 OpenBao 호스트 포트를 자동으로
반영합니다. step-ca와 HTTP-01 클라이언트 URL은 호스트 포트에서
유도되지 않으므로, 해당 서비스가 기본값이 아닌 포트로 동작한다면
`--responder-url`, `--agent-server`, `--agent-responder-url`을 직접
전달해야 합니다. 전체 우선순위는 `docs/ko/cli.md`를 참고하세요.

위 조건을 위반하면 `bootroot init`, `bootroot infra up`,
`bootroot rotate db`는 즉시 실패합니다.

단일 호스트 신뢰 경계를 벗어나는 경우에는 DB 전송을 TLS 기반으로
전환하세요(`sslmode=require` 또는 `sslmode=verify-full`). 다시 말해
`sslmode=disable`은 같은 머신 기본 토폴로지에만 해당하며,
step-ca/PostgreSQL 분리 배치에는 사용하면 안 됩니다.

### 베어메탈

베어메탈은 컨테이너 없이 **호스트 OS에 직접 설치/운영**하는 방식을 뜻합니다.

1. OS 패키지로 step-ca/step-cli 설치
2. 작업 디렉터리 생성(예: `/etc/step-ca`)
3. `step ca init` 수행
4. systemd 등으로 서비스 등록

PostgreSQL을 사용할 때는 `db.type = "postgresql"`이어야 합니다.

호스트에서 PostgreSQL을 직접 사용하는 경우 DSN 예시는 다음과 같습니다.

```text
postgresql://step:step-pass@localhost:5432/stepca?sslmode=disable
```

## PostgreSQL (step-ca 백엔드)

운영 환경에서는 PostgreSQL 사용을 권장합니다. 자세한 설정과 DSN 예시는
`step-ca (Docker)` 및 `step-ca (베어메탈)` 섹션을 참고하세요.

## OpenBao Agent

OpenBao Agent는 OpenBao의 시크릿을 파일로 렌더링합니다. 이는 인프라
구성요소 전용입니다: step-ca와 HTTP-01 리스폰더가 `bootroot init`가 만든
`agent.hcl`을 사용합니다. 서비스는 서비스별 OpenBao Agent를 **실행하지
않습니다** — 각 서비스의 `bootroot-agent`가 스스로 OpenBao에 인증하고
fast-poll 루프로 시크릿을 최신 상태로 유지합니다
([개념 > 시크릿 전달 흐름](concepts.md) 참고).

### Docker

기본 토폴로지에서는 `bootroot init`가 compose override를 통해 두 인프라
에이전트(`openbao-agent-stepca`, `openbao-agent-responder`)를 기동하므로
별도의 수동 단계가 필요 없습니다.

아래의 raw `docker run` 예시는 디버깅이나 compose로 관리되는
에이전트를 사용할 수 없는 환경을 위한 참고용입니다. `<network>`
부분은 실제 docker 네트워크 이름으로 대체하세요. 기본값은
`<project>_default`이며, 여기서 `<project>`는 `bootroot-openbao`의
`com.docker.compose.project` 라벨 값입니다. 다음 명령으로 확인할 수
있습니다.

```bash
docker inspect bootroot-openbao \
  --format '{{index .Config.Labels "com.docker.compose.project"}}'
```

step-ca용 OpenBao Agent(예시):

```bash
docker run --rm \
  --name openbao-agent-stepca \
  --network <network> \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://bootroot-openbao:8200 \
  openbao/openbao:2.5.5 \
  agent -config /openbao/secrets/openbao/stepca/agent.hcl
```

responder용 OpenBao Agent(예시):

```bash
docker run --rm \
  --name openbao-agent-responder \
  --network <network> \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://bootroot-openbao:8200 \
  openbao/openbao:2.5.5 \
  agent -config /openbao/secrets/openbao/responder/agent.hcl
```

위 예시에서 `VAULT_ADDR=http://localhost:8200`를 쓰지 않는 이유:
컨테이너 내부 `localhost`는 OpenBao가 아니라 **해당 Agent 컨테이너 자신**을
가리키기 때문입니다. Docker 네트워크에서는 OpenBao 컨테이너 이름
(`bootroot-openbao`)으로 접근해야 합니다.

참고: OpenBao/PostgreSQL/step-ca/HTTP-01 responder가 한 머신에서 동작하는
bootroot 기본
토폴로지에서는 `bootroot init`가 step-ca/responder용 OpenBao Agent 설정 파일과
compose override를 생성하고, `openbao-agent-stepca`,
`openbao-agent-responder` 컨테이너를 기동합니다.

### 호스트 실행

```bash
openbao agent -config /etc/bootroot/openbao/stepca/agent.hcl
```

권장 배포 정책:

- step-ca/responder:
  OpenBao/PostgreSQL/step-ca/HTTP-01 responder가 한 머신에서 동작하는 bootroot
  기본 토폴로지에서는 구성요소별 전용 OpenBao Agent 컨테이너를 각각
  분리해서 사용합니다. 즉 step-ca에는 `openbao-agent-stepca`,
  responder에는 `openbao-agent-responder`를 붙여 각 구성요소가 필요한
  시크릿만 렌더링하도록 운영합니다.
- 서비스: OpenBao Agent를 사용하지 않습니다. `bootroot-agent` 호스트
  데몬의 fast-poll 루프가 시크릿 전달 메커니즘입니다.

서비스 `bootroot-agent` 흐름의 `role_id`/`secret_id`(그리고 EAB가 설정된
경우 `eab.json`)는 `secrets/services/<registration_id>/` 아래에 있으며, 해당
디렉터리는 `0700`, 파일은 `0600` 권한을 유지해야 합니다.

## 개발/테스트 환경 완전 초기화

로컬 환경이 꼬였거나 시크릿을 완전히 새로 만들고 싶다면 `bootroot clean`
으로 완전히 정리하세요. **모든 기존 키/토큰/인증서가 폐기됩니다.**

```bash
bootroot clean
```

이 명령은 컨테이너를 중지하고, 볼륨을 삭제하고, 생성된 시크릿과 산출물을
제거합니다. 정리 후 최초 설치 흐름을 다시 실행합니다:

```bash
bootroot infra install
bootroot init
```

그 다음 서비스를 기동하고, 서비스를 다시 추가한 뒤 발급을 확인합니다:

```bash
docker compose up -d
bootroot service add \
  --registration-id edge-proxy \
  --service-name edge-proxy --hostname edge-node-01 \
  --domain trusted.domain --instance-id 001 \
  --agent-config "$(pwd)/tmp/agent-edge-proxy.toml" \
  --cert-path "$(pwd)/certs/edge-proxy.crt" \
  --key-path "$(pwd)/certs/edge-proxy.key"
bootroot verify --registration-id edge-proxy \
  --agent-config "$(pwd)/tmp/agent-edge-proxy.toml"
```

`bootroot verify`는 bootroot-agent 바이너리로 1회 발급을 수행합니다.
`result: ok`가 출력되고 `certs/edge-proxy.crt`에 PEM이 생성되면 정상입니다.

리스폰더 HMAC 불일치가 발생하면 OpenBao의 HMAC 시크릿과
리스폰더 설정이 일치하는지 확인하고 리스폰더를 재기동하세요.

**수동 초기화 대안** (`bootroot clean`을 사용하지 않는 경우):

1. 컨테이너/볼륨 정리:

   ```bash
   docker compose down -v --remove-orphans
   ```

2. 기존 시크릿/산출물 삭제(템플릿은 유지):

   ```bash
   rm -rf certs tmp state.json \
     secrets/certs secrets/config secrets/db secrets/openbao \
     secrets/responder secrets/secrets
   rm -f secrets/password.txt
   ```

   `secrets/templates`까지 지웠다면 `git checkout -- secrets/templates`로
   복원하세요.

## bootroot-agent

권장 배포 정책:

- bootroot-agent는 **호스트 데몬**(systemd)으로 실행합니다. 온보딩된
  서비스에 대해 지원되는 유일한 실행 모델이며, bootroot-agent를 Docker
  사이드카로 실행하지 않습니다.
- **서로 다른 서비스마다** `bootroot-agent` 프로세스 하나와 agent 구성
  하나를 사용합니다. `[openbao]` 섹션은 AppRole 자격증명을 하나만 담으므로
  서로 다른 서비스가 하나의 `agent.toml`을 공유할 수 없습니다. 하나의
  구성에 여러 `[[profiles]]`를 두는 것은 같은 서비스의 인스턴스에 대해서만
  지원됩니다([운영 > systemd 운영 절차](operations.md) 참고).
- 인증서를 소비하는 애플리케이션은 컨테이너로 실행해도 됩니다. 호스트
  데몬이 호스트 디렉터리에 인증서를 기록하고 앱 컨테이너가 그 디렉터리를
  bind-mount하며, `--reload-style docker-restart --reload-target
  <container>` 훅으로 리로드합니다
  ([운영 > 컨테이너화된 소비 애플리케이션](operations.md) 참고).

### bootroot 내부 registrar 에이전트

[registrar 엔드포인트](operations.md#registrar-endpoint-linux-only)를 제공하는 **bootroot
호스트** 배포에서는 해당 호스트의 서비스 에이전트와 별개로 **두 번째**
`bootroot-agent` 프로세스를 함께 운영합니다. 이 프로세스가 갱신하는 인증서는
하나뿐입니다. 데몬이 registrar의 `mint`/`deregister` 동사를 실행하기 위해
`OpenBao`에 인증할 때 사용하는 bootroot 내부 자격 증명입니다.

**이 호스트에서는 `bootroot init`을 root로 실행하세요.** 자격 증명을 구성하는
다섯 개 파일(`registrar-internal/key.pem`, `chain.pem`, `acme-account.json`,
`root-fingerprint`, `agent.toml`)은 `0600`에 소유자가 `root`인 상태로 게시되며,
`init`은 그 소유권을 확보하지 못하면 어느 파일도 게시하지 않고 실패합니다.
일반 사용자로 실행한 엔드포인트 활성 `init`은 키를 그 사용자가 읽을 수 있는
상태로 남기는 대신 아무것도 쓰지 않고 실패합니다. 이 동작은 최선 노력(best
effort)이 아니며, 이를 완화하는 플래그나 설정 키도 없습니다.

따라서 이 설치 전체가 root로 운영됩니다. `init`이 이 호스트에 만든 파일은 root의
것이므로, 이 설치를 변경하는 이후의 모든 `bootroot` 명령(`rotate`,
`service add`, `reinit`, `clean`)도 root로 실행해야 합니다. 상태만 보고하는
읽기 전용 명령은 읽을 대상에 접근할 권한만 있으면 됩니다. 이는 registrar
엔드포인트를 제공하는 호스트에 해당하며, 그렇지 않은 호스트는 변경 사항이 없고
root도 필요 없습니다.

배포 자체는 영향을 받지 않습니다. step-ca, HTTP-01 응답기, 두 개의 `OpenBao`
Agent 사이드카는 계속 설치 트리의 소유자로 실행되며, root로 실행한 `init`도
이들이 읽는 대상(설정 파일, `AppRole` 자격 증명, 렌더링 원본 템플릿, 그리고
이들을 담은 디렉터리)을 `root`가 아니라 그 소유자로 게시합니다. 소유자가 바뀌는
것은 위에 나열한 다섯 개 파일뿐이며, 엔드포인트를 활성화하기 위해 기존 설치의
소유권을 다시 지정할 필요는 없습니다.

`bootroot init`은 이 설정 파일과 전용 CA 번들을 작성할 뿐, 프로세스를 시작하거나
감독자(supervisor)를 설치하지 않습니다. 서비스 에이전트와 마찬가지로 운영자가
같은 감독자 아래에서 시작합니다.

```sh
bootroot-agent --config <secrets-directory>/registrar-internal/agent.toml
```

`<secrets-directory>`는 `state.json`에 기록된 `secrets_dir`입니다. 이 경로는
고정이며 설정으로 바꿀 수 없습니다. 회전(rotation)과 복구도 같은 경로를 패턴으로
사용해 프로세스에 신호를 보냅니다.

**이 프로세스도 root로 실행하세요.** 서비스 에이전트와 달리 위 설정 파일, 리프
키, ACME 계정 키를 읽습니다. 셋 모두 `0700` root 소유 디렉터리 안에 `0600`
root 소유로 있으며, 갱신할 때마다 리프를 그 디렉터리에 다시 게시합니다. 서비스
에이전트를 실행하는 일반 사용자로 시작하면 자기 설정 파일조차 열 수 없습니다.

**일상적인 갱신은 이 프로세스를 시작한 뒤에야 시작됩니다.** 그전까지 자격 증명은
`init`이 발급한 상태 그대로이며, 회전이 신호를 보내도 대상 프로세스가 없습니다.
이 경우는 성공으로 처리하므로, 프로세스가 없는 것은 오류가 아니라 조용한 결과입니다.

서비스 에이전트 설정과 다른 점이 두 가지 있습니다.

- `[trust]`가 공유 `secrets/certs/ca-bundle.pem`이 아니라 **전용**
  `registrar-internal/ca-bundle.pem`을 가리킵니다. 덕분에 CA 회전이 서비스가 읽는
  파일을 건드리지 않고 이 신원의 신뢰 범위만 좁힐 수 있습니다.
- `[acme].account_key_path`가 `registrar-internal/acme-account.json`을 가리켜,
  갱신을 거듭해도 하나의 ACME 계정을 유지합니다. 이 키를 설정하지 않은 기존
  설정은 발급마다 새 계정 키를 만드는 기존 동작을 그대로 유지합니다.

registrar 엔드포인트를 사용하지 않는 호스트에는 이 파일들이 없으며, 이 절도
필요하지 않습니다.

자격 증명의 권한 경계, 부여되는 정확한 `OpenBao` 정책, 프로비저닝 순서, 회전
단계, 복구 명령은
[`docs/reference/registrar-internal-credential.md`](https://github.com/aicers/bootroot/blob/main/docs/reference/registrar-internal-credential.md)에
정리되어 있습니다.

### 바이너리

소스에서 빌드:

```bash
cargo build --release
./target/release/bootroot-agent --config agent.toml --oneshot
```

`--oneshot`은 인증서를 **한 번만 발급**하고 종료하는 옵션입니다. 데몬
모드로 주기적 갱신을 하려면 이 옵션을 빼고, `bootroot service add`가
출력한 대로 프로비저닝된 EAB 파일 경로를 함께 전달합니다:

```bash
bootroot-agent --config /etc/bootroot/agent.toml \
  --eab-file /path/to/secrets/services/<svc>/eab.json
```

EAB 회전이 적용되려면 `--eab-file`이 필수입니다 — 없으면 EAB KV 갱신과
`rotate eab-clear`가 해당 에이전트에서 조용히 무시됩니다. 자세한 설정
방법은 **설정** 섹션과 [운영 > systemd 운영 절차](operations.md)의
하드닝된 유닛 예시를 참고하세요.

TLS 검증 오버라이드:

자세한 동작 원리와 권장 운용 순서는 [설정 > 신뢰](configuration.md)를
참고하세요.

- `--insecure`: 해당 실행에서만 ACME 서버 TLS 검증 비활성화
  (비보안 오버라이드). 일반적인 managed onboarding 흐름에서는 첫
  `bootroot-agent` 실행 전에 trust가 준비되므로 처음부터 검증을 켤 수
  있습니다.

#### CA 번들 소비 서비스 권한

mTLS를 사용하는 서비스는 `trust.ca_bundle_path`에 저장되는 CA 번들을 읽을
수 있어야 합니다. 가장 단순한 구성은 bootroot-agent와 해당 서비스를
같은 계정/그룹으로 실행하는 것입니다.

### compose 스택 대상 스모크 테스트

bootroot-agent에는 컨테이너 이미지가 없습니다. 항상 호스트 프로세스로
실행되므로 `docker compose up` 대상이 존재하지 않습니다. compose 스택을
상대로 **1회 발급**(`--oneshot`)을 확인하려면 바이너리를 빌드한 뒤 스택이
호스트에 게시한 포트로 연결합니다:

```bash
cargo build --bin bootroot-agent
./target/debug/bootroot-agent --oneshot --insecure --config agent.toml.compose
```

`agent.toml.compose`는 바로 이 실행 모델(네이티브 바이너리가 `localhost`로
compose 스택에 접속)을 위한 설정입니다. compose 스택의 CA는 자체 서명이고
이 설정에는 trust 번들이 없으므로 `--insecure`가 필요합니다. managed
onboarding 흐름은 trust를 먼저 준비하므로 이 옵션이 필요하지 않습니다.
데모/스모크 경로일 뿐 온보딩 경로가 **아니며**, 운영 서비스는 위에서 설명한
대로 `bootroot service add`가 작성한 설정으로 bootroot-agent 호스트 데몬을
실행합니다.

`scripts/preflight/extra/agent-scenarios.sh`도 동일한 바이너리를 같은 방식으로
실행합니다.

## bootroot-remote (원격 서비스 머신용)

서비스가 step-ca/OpenBao가 동작하는 머신이 아닌 다른 머신에 추가될 때는
해당 서비스 머신에 `bootroot-remote`를 설치해야 합니다.

- 설치: `cargo build --release --bin bootroot-remote`
- 실행: `bootroot-remote bootstrap ...`(첫 agent 실행 전 초기 trust/bootstrap
  반영). 이후 실행 중인 `bootroot-agent`가 fast-poll 루프로 trust와 secret_id
  회전을 가져오므로, `bootroot-remote apply-secret-id ...`는 `secret_id_ttl`을
  넘겨 오프라인 상태였던 에이전트를 위한 복구 경로일 뿐입니다

`remote-bootstrap` 방식의 상세 인자/예시는 [CLI](cli.md)의
`bootroot-remote bootstrap`/`apply-secret-id` 섹션 및
[원격 부트스트랩 운영자 가이드](remote-bootstrap.md)를 참고하세요.

## HTTP-01 리스폰더

### Docker

HTTP-01 챌린지는 별도 리스폰더 이미지가 처리하며,
`docker/http01-responder/Dockerfile`에서 빌드합니다.

```bash
docker compose up --build -d bootroot-http01
```

현재 프로젝트의 기본 `docker-compose.yml`은 HTTP-01 리스폰더에
`restart: always`를 설정합니다.

리스폰더는 `responder.toml.compose`를 읽고 포트 80에서
`/.well-known/acme-challenge/` 요청에 응답합니다. bootroot-agent는
포트 8080의 관리자 API로 토큰을 등록하며, 동일한 HMAC 시크릿을 사용합니다.

#### DNS 별칭(자동)

HTTP-01 검증 시 step-ca 컨테이너가 각 서비스의 챌린지 호스트명을 리스폰더로
해석해야 합니다. `bootroot service add`가 이를 자동으로 처리합니다: 검증 FQDN
(`<instance_id>.<service_name>.<hostname>.<domain>`)을 `bootroot-http01`
컨테이너에 Docker 네트워크 별칭으로 등록합니다. 수동으로
`docker-compose.override.yml`을 작성할 필요가 없습니다.

등록은 best-effort이며 실패해도 서비스 추가 자체는 성공하므로, 요약의
`- 등록된 HTTP-01 DNS 별칭:` 줄이 그 결과를 보고합니다. 개수는 실제로 등록된
별칭 수이고, `0개 (등록을 건너뛰었습니다; 위 경고를 확인하세요)`는 등록된
별칭이 없다는 뜻이며 구체적인 원인은 그 위에 출력된 경고에 나옵니다. 등록을
건너뛰면 별칭이 재적용될 때까지 챌린지 호스트명을 해석할 수 없으므로 이 줄을
반드시 확인하세요.

리스폰더 컨테이너가 재시작된 경우(예: `docker compose down` / `up`),
`bootroot infra up`을 실행하면 `state.json`에 저장된 모든 별칭이 자동으로
재적용됩니다.

### 바이너리(선택)

부득이하게 Docker 밖에서 실행해야 한다면 바이너리를 사용하고
systemd로 관리하세요.

#### 1단계. 리스폰더 바이너리 빌드

```bash
cargo build --release --bin bootroot-http01-responder
sudo install -m 0755 ./target/release/bootroot-http01-responder /usr/local/bin/
```

#### 2단계. 설정 파일 생성

`/etc/bootroot/responder.toml`을 만들고 HMAC 시크릿을 설정합니다.

#### 3단계. systemd 유닛 생성

```ini
[Unit]
Description=Bootroot HTTP-01 Responder
After=network.target

[Service]
ExecStart=/usr/local/bin/bootroot-http01-responder --config /etc/bootroot/responder.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

#### 4단계. 서비스 시작

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bootroot-http01-responder
```

포트 80 바인딩에는 root 권한 또는 `cap_net_bind_service`가 필요합니다.
