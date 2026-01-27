# 설치

이 섹션은 step-ca, PostgreSQL, bootroot-agent, HTTP-01 리스폰더 설치를 다룹니다.
CLI를 사용하는 경우 [CLI 문서](cli.md)를 참고하세요. 이 문서는 **수동 설치**
절차를 기준으로 설명합니다.

## step-ca

### Docker

이 repo는 PostgreSQL 지원 step-ca를 빌드하는 compose 구성을 제공합니다.

```bash
docker compose up --build -d step-ca
```

#### step-ca 초기화(최초 1회)

사전 생성된 개발용 시크릿을 쓰지 않는다면 아래처럼 초기화합니다.

```bash
mkdir -p secrets
printf "%s" "<your-password>" > secrets/password.txt

docker run --user root --rm -v $(pwd)/secrets:/home/step smallstep/step-ca \
  step ca init \
  --name "Bootroot CA" \
  --provisioner "admin" \
  --dns "localhost,bootroot-ca" \
  --address ":9000" \
  --password-file /home/step/password.txt \
  --provisioner-password-file /home/step/password.txt \
  --acme
```

`<your-password>`는 CA 키를 보호(암호화)하는 비밀번호입니다. 운영에서는
충분히 강한 비밀번호로 설정하고, 해당 파일은 외부에 노출되지 않도록
보호하세요. 운영에서는 OpenBao 같은 **시크릿 매니저(Secret Manager)** 를
통해 이 비밀번호를 주입하는 방식을 권장합니다.

초기화가 끝나면 다음 파일들이 생성됩니다(대표 예시):

- `ca.json`
- `root_ca.crt`
- `intermediate_ca.crt`
- `secrets/ca_key`
- `secrets/intermediate_ca_key`

`bootroot init`는 CA 지문을 OpenBao에 저장하므로,
`secrets/certs/root_ca.crt`와 `secrets/certs/intermediate_ca.crt`가
존재해야 합니다. 이 파일이 없으면 `bootroot init`가 실패합니다.

이 문서의 예시는 `-v $(pwd)/secrets:/home/step`로 마운트하기 때문에,
생성된 파일이 컨테이너의 `/home/step`에 만들어지고, 호스트에서는
`./secrets/` 디렉터리로 저장됩니다. 즉, 별도의 위치로 옮기지 말고
`./secrets/` 아래에 그대로 두어야 `secrets/config/ca.json` 경로와
맞춰서 정상 동작합니다.

그다음 `secrets/config/ca.json`을
현재 환경에 맞게 갱신해야 합니다. 예:

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

**중요**: step-ca가 컨테이너에서 실행 중이면 `db.dataSource`의 호스트는
**컨테이너 내부 기준**입니다. 따라서 `127.0.0.1`/`localhost`가 아니라
Compose 서비스 이름(예: `postgres`)을 사용해야 합니다.

`<secret>` 자리는 실제 운영 비밀번호를 넣어야 합니다.

`step-pass`는 이 repo의 **개발용 기본 비밀번호**입니다. `.env`의
`POSTGRES_PASSWORD`와 맞춰져야 하므로, 로컬/Compose 예시에서 동일하게
사용했습니다. 운영에서는 반드시 강한 비밀번호로 변경하세요. 운영에서는
이 DB 비밀번호도 OpenBao 같은 **시크릿 매니저(Secret Manager)** 를 통해
주입하는 방식을 권장합니다.

`.env`에는 다음처럼 입력합니다(예시):

```text
POSTGRES_USER=step
POSTGRES_PASSWORD=step-pass
POSTGRES_DB=stepca
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
```

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

로컬 Compose 환경이라면 `.env` 값을 맞춘 뒤 아래 스크립트를 쓰면 됩니다.
이 스크립트는 `.env`의 `POSTGRES_*` 값을 읽어서 `secrets/config/ca.json`의
`db.type`과 `db.dataSource`를 자동으로 갱신합니다. 즉, 비밀번호나 호스트를
바꿨을 때 수동 편집 없이 동기화할 수 있습니다.

```bash
scripts/update-ca-db-dsn.sh
```

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

OpenBao Agent는 OpenBao의 시크릿을 파일로 렌더링합니다. step-ca/리스폰더는
`bootroot init`가 만든 `agent.hcl`을 사용하고, 앱은 `bootroot app add`
출력에 나온 경로를 사용합니다.

### Docker

step-ca용 OpenBao Agent(예시):

```bash
docker run --rm \
  --name openbao-agent-stepca \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://localhost:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/stepca/agent.hcl
```

responder용 OpenBao Agent(예시):

```bash
docker run --rm \
  --name openbao-agent-responder \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://localhost:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/responder/agent.hcl
```

앱용 OpenBao Agent(예시):

```bash
docker run --rm \
  --name openbao-agent-edge-proxy \
  -v $(pwd)/secrets:/openbao/secrets \
  -e VAULT_ADDR=http://localhost:8200 \
  openbao/openbao:latest \
  agent -config /openbao/secrets/openbao/apps/edge-proxy/agent.hcl
```

### 호스트 실행

```bash
openbao agent -config /etc/bootroot/openbao/apps/<service>/agent.hcl
```

bootroot는 OpenBao Agent를 **호스트 실행하지 않고 Docker로만** 구동하는
방식을 기본으로 합니다. 호스트 실행은 참고용입니다.

`role_id`/`secret_id` 파일은 `secrets/apps/<service>/` 아래에 있으며,
해당 디렉터리는 `0700`, 파일은 `0600` 권한을 유지해야 합니다.

## 개발/테스트 환경 완전 초기화

로컬 환경이 꼬였거나 시크릿을 완전히 새로 만들고 싶다면 아래 절차로
깨끗하게 초기화하세요. **모든 기존 키/토큰/인증서가 폐기됩니다.**

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

3. step-ca 재초기화 및 DB DSN 갱신:

   - `step-ca 초기화(최초 1회)` 절차를 다시 수행합니다.
   - 로컬 Compose라면 `scripts/update-ca-db-dsn.sh`로
     `secrets/config/ca.json`을 갱신합니다.

4. OpenBao 초기화/언실:

   - OpenBao를 초기화해 `root token`/`unseal keys`를 확보합니다.
   - OpenBao를 unseal 합니다.

5. bootroot 초기화:

   ```bash
   bootroot init --auto-generate \
     --db-dsn "postgresql://step:step-pass@postgres:5432/stepca?sslmode=disable"
   ```

6. 서비스 기동 및 발급 확인:

   ```bash
   docker compose up -d
   docker compose run --rm bootroot-agent
   ```

   `certs/bootroot-agent.crt`에 PEM이 생성되면 정상입니다.

리스폰더 HMAC 불일치가 발생하면 OpenBao의 HMAC 시크릿과
리스폰더 설정이 일치하는지 확인하고 리스폰더를 재기동하세요.

## bootroot-agent

### 바이너리

```bash
cargo build --release
./target/release/bootroot-agent --config agent.toml --oneshot
```

`--oneshot`은 인증서를 **한 번만 발급**하고 종료하는 옵션입니다. 데몬
모드로 주기적 갱신을 하려면 이 옵션을 빼고 실행합니다.
자세한 설정 방법은 **설정** 섹션을 참고하세요.

#### CA 번들 소비 서비스 권한

mTLS를 사용하는 서비스는 `trust.ca_bundle_path`에 저장되는 CA 번들을 읽을
수 있어야 합니다. 가장 단순한 구성은 bootroot-agent와 해당 서비스를
같은 사용자/그룹으로 실행하는 것입니다.

### Docker

```bash
docker compose up --build -d bootroot-agent
```

컨테이너는 기본으로 `agent.toml.compose`를 사용합니다.

## HTTP-01 리스폰더

### Docker

HTTP-01 챌린지는 별도 리스폰더 이미지가 처리하며,
`docker/http01-responder/Dockerfile`에서 빌드합니다.

```bash
docker compose up --build -d bootroot-http01
```

리스폰더는 `responder.toml.compose`를 읽고 포트 80에서
`/.well-known/acme-challenge/` 요청에 응답합니다. bootroot-agent는
포트 8080의 관리자 API로 토큰을 등록하며, 동일한 HMAC 시크릿을 사용합니다.

### systemd(베어메탈)

리스폰더를 호스트에서 systemd로 실행할 수도 있습니다.

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
