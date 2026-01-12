# 개념

이 섹션은 운영에 필요한 최소한의 배경 지식을 제공합니다.

## PKI와 인증서

- **CA(인증기관)** 는 공개키와 신원을 묶어 서명합니다(호스트명 또는 IP).
- **인증서**는 신원 정보(SAN), 유효기간, CA 서명을 포함합니다.
- **개인키**는 반드시 안전하게 보호되어야 합니다.

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

## 시크릿 매니저(OpenBao)

운영 환경에서는 시크릿을 파일이나 환경변수에 하드코딩하지 않고
OpenBao 같은 시크릿 매니저에 저장해 주입합니다. OpenBao는
Vault 호환 KV v2 스토리지를 제공하며, 다음 값을 관리합니다.

- step-ca 키 암호(`password.txt`)
- step-ca DB DSN
- HTTP-01 responder HMAC
- EAB `kid`/`hmac`

OpenBao는 **unseal keys**와 **root token**으로 초기화/접속합니다.
서비스는 AppRole로 인증해 필요한 경로만 읽도록 최소 권한을 적용합니다.

## SAN (Subject Alternative Name)

인증서의 실제 신원 목록입니다. 예:

- **DNS**: `example.internal`
- **IP**: `192.0.2.10`

## mTLS

서버와 클라이언트 모두 인증서를 제시하는 TLS 방식입니다.
자동 발급/갱신이 가능하면 운영 안정성이 크게 높아집니다.
