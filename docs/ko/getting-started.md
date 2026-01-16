# 빠른 시작

이 섹션은 Docker Compose로 첫 인증서를 발급하는 과정을 설명합니다.
CLI를 사용하는 경우 [CLI 문서](cli.md)를 참고하세요. 이 문서는 **수동 실행**
절차를 기준으로 설명합니다.

## 사전 준비

- Docker 및 Docker Compose
- Compose 네트워크 내부에서 리스폰더의 포트 80 접근 가능
- 자동 생성된 DNS SAN이 step-ca에서 **HTTP-01 리스폰더로 해석**되어야 함
  - Compose에서는 `docker-compose.yml`의 `bootroot-http01`이
    `001.bootroot-agent.bootroot-agent.trusted.domain` alias를 제공함
  - `domain` 값을 바꾸면 alias를 함께 바꾸거나 step-ca의 `/etc/hosts`에 매핑 필요
  - 자동 생성 형식:
    `<instance-id>.<service-name>.<hostname>.<domain>`

## 빠른 실행(Compose)

1. 서비스 시작:

   ```bash
   docker compose up --build -d
   ```

2. 에이전트 로그 확인:

   ```bash
   docker logs -f bootroot-agent
   ```

   기대 로그 예시: `Successfully issued certificate!`

3. 발급 파일 확인:

   ```bash
   ls -l certs/
   ```

   기대 파일: `bootroot-agent.crt`, `bootroot-agent.key`

## 내부적으로 일어난 일

- `agent.toml.compose`를 읽음
- step-ca에 ACME 계정 등록
- HTTP-01 토큰을 리스폰더에 등록
- 리스폰더가 포트 80에서 HTTP-01 응답
- 인증서/키를 `certs/`에 저장

## 다음 단계

- 운영 설치는 **설치** 섹션을 참고하세요.
- 설정 확장은 **설정** 섹션을 참고하세요.
- 운영 환경에서는 OpenBao 같은 시크릿 매니저를 통해
  step-ca 키 암호/DB DSN/HMAC/EAB를 주입하는 구성을 권장합니다.
