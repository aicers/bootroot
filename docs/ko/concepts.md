# 개념

이 섹션은 운영에 필요한 최소한의 배경 지식을 제공합니다.

## PKI와 인증서

- **CA(인증기관)** 는 공개키와 신원을 묶어 서명합니다(호스트명 또는 IP).
- **인증서**는 신원 정보(SAN), 유효기간, CA 서명을 포함합니다.
- **개인키**는 반드시 안전하게 보호되어야 합니다.

## SAN (Subject Alternative Name)

인증서의 실제 신원 목록입니다. 예:

- **DNS**: `example.internal`
- **IP**: `192.0.2.10`

## mTLS

서버와 클라이언트 모두 인증서를 제시하는 TLS 방식입니다.
자동 발급/갱신이 가능하면 운영 안정성이 크게 높아집니다.

## CSR (Certificate Signing Request)

CSR은 클라이언트가 생성하는 요청서입니다. 공개키와 SAN 목록이 포함됩니다.
CA가 이를 검증한 뒤 인증서를 발급합니다.

## ACME

ACME(RFC 8555)는 step-ca가 제공하는 자동화 발급 프로토콜입니다. ACME
계정은 CA와 통신하기 위해 만드는 등록 정보로, 계정 키와 연락처(이메일)
등이 포함됩니다. 이 계정으로 인증서 발급/갱신 요청을 수행합니다.
bootroot-agent는 최초 접속 시 이 계정을 자동으로 생성/등록합니다.

ACME 흐름에서 자주 등장하는 개념은 다음과 같습니다.

- **Account**: ACME 서버에 등록되는 계정입니다. 계정 키와 연락처가
  묶이며, 이후 모든 주문은 이 계정으로 서명됩니다.
- **Order**: 인증서 발급 요청입니다. 어떤 도메인/SAN을 포함할지와
  이후 진행할 인증 절차(Authorization)를 포함합니다.
- **Authorization**: 특정 식별자(도메인 등)에 대한 소유 증명 단계입니다.
  하나의 Order는 여러 Authorization을 포함할 수 있습니다.
- **Challenge**: Authorization을 통과하기 위한 실제 검증 방법입니다.
  HTTP-01, DNS-01, TLS-ALPN-01 등이 있으며, 이 프로젝트는 HTTP-01을 사용합니다.
- **Finalize**: 모든 Authorization이 통과되면 CSR을 제출하고
  인증서를 발급받는 단계입니다.
- **Certificate**: 최종 발급된 인증서입니다. ACME 서버에서 다운로드합니다.

## HTTP-01 챌린지

HTTP-01은 **도메인 소유 확인 절차**입니다. CA가 **토큰**을 발급하고,
해당 도메인으로 HTTP 요청을 보내 응답을 검증합니다.

흐름:

1. step-ca가 Authorization 응답에 HTTP-01 토큰을 포함해 bootroot-agent에
   반환합니다.
2. bootroot-agent가 이 토큰을 받아 **HTTP-01 리스폰더** 관리자 API(포트 8080)로
   등록합니다.
3. step-ca가 **HTTP-01 리스폰더**에
   `http://<domain>/.well-known/acme-challenge/<token>` 요청을 보내 검증합니다.
4. **HTTP-01 리스폰더**가 올바른 key authorization을 응답하면 CA는
   **도메인 소유 검증(Authorization)** 을 통과로 처리합니다.

## EAB (External Account Binding)

등록 제한이 필요한 CA에서 사용하는 방식입니다. `kid`와 `hmac`를
제공해야 계정 등록이 허용됩니다.

- `kid`(key ID): CA가 발급하는 EAB 키의 식별자입니다.
- `hmac`: 외부 계정 바인딩에 사용하는 공유 HMAC 키입니다.
- HMAC: 비밀키 기반 해시(Hash-based Message Authentication Code)로,
  같은 비밀을 공유하는지를 증명합니다.

## 시크릿 매니저(OpenBao)

운영 환경에서는 시크릿을 파일이나 환경변수에 하드코딩하지 않고
OpenBao 같은 시크릿 매니저에 저장해 주입합니다. OpenBao는
Vault 호환 KV v2 스토리지를 제공하며(Vault는 널리 쓰이는 시크릿 매니저,
KV v2는 버전 관리되는 키/값 시크릿 엔진), bootroot에서는 다음 값을
관리합니다.

- step-ca 키 암호(`password.txt`)
- step-ca DB DSN(Data Source Name: 호스트/계정/비밀번호를 포함한 접속 문자열)
- HTTP-01 responder HMAC
- EAB `kid`/`hmac`

### 시크릿 주입 흐름(OpenBao Agent)

런타임 서비스는 OpenBao에 직접 접속하지 않고, **OpenBao Agent**가
AppRole로 로그인해 시크릿을 파일로 렌더링합니다. 주요 흐름은 다음과
같습니다.

- OpenBao Agent가 AppRole(role_id + secret_id)로 로그인
- 필요한 시크릿을 템플릿 파일로 렌더링(예: `password.txt`,
  `responder.toml`, `agent.toml`)
- `bootroot-agent`, HTTP-01 responder, step-ca가 렌더된 파일을 읽어 사용

`bootroot` CLI는 초기화/회전 같은 **관리 작업**에서만 OpenBao API를
직접 호출합니다.

OpenBao는 **unseal keys**와 **root token**으로 초기화/접속합니다.
unseal keys는 기동 시 스토리지를 해제하는 용도이고, root token은
전체 관리자 권한을 부여합니다. 초기 설정 이후에는 OpenBao Agent가
**AppRole**(role_id + secret_id)로 로그인해 짧은 TTL 토큰을 받고,
필요한 경로만 읽도록 최소 권한 정책을 적용합니다.
unseal keys는 초기화 시 **shares(총 개수)**와 **threshold(필요 개수)**로
분할되며, 언실 시에는 threshold 개수 이상이 필요합니다.
unseal keys와 root token은 OpenBao 초기화 시 **OpenBao가 자동 생성**하며,
운영자가 값을 안전하게 보관해야 합니다.
이 값들은 재기동 시 언실(unseal)과 운영 중 복구/정책 변경 같은
관리 작업에 필요합니다.
AppRole의 `role_id`/`secret_id`는 OpenBao가 발급합니다. `role_id`는
역할 식별자이며 고정값이고, `secret_id`는 로그인에 쓰는 자격증명으로
재발급/회전이 가능합니다. 초기 값은 운영자가 서비스(OpenBao Agent)에
전달하고, 이후에는 `secret_id`를 주기적으로 갱신합니다.

### Dev-only 자동 언실(주의)

개발/테스트 환경에서는 `bootroot infra up` 또는 `bootroot init`에
`--openbao-unseal-from-file <path>` 옵션을 사용해 **파일에서 unseal keys를
읽어 자동으로 언실**할 수 있습니다. 이 방식은 **운영 환경에서 사용하면
안 됩니다**. 키를 디스크에 보관하는 순간 노출 위험이 커지며, 유출 시
OpenBao 전체가 위험해질 수 있습니다.
