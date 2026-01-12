# FAQ

## 한 머신에서 여러 인증서를 발급할 수 있나요?

가능합니다. `[[profiles]]`를 여러 개 정의하면 됩니다. 각 프로필은
`instance_id.service_name.hostname.domain` 형식의 고유 신원을 가집니다.

## ACME에서 URI SAN을 넣을 수 있나요?

불가능합니다. ACME는 DNS/IP 식별자만 지원하므로, URI SAN이 포함된 CSR은
step-ca가 거부합니다.

## EAB는 꼭 필요한가요?

step-ca 프로비저너 정책에 따라 필요합니다. 정책이 없다면 생략 가능합니다.

## 개인키는 어디에 저장하나요?

`0700` 디렉터리 안에 `0600` 파일로 저장하는 것을 권장합니다.

## DB 비밀번호는 회전할 수 있나요?

가능합니다. 시크릿/환경을 갱신하고
`scripts/update-ca-db-dsn.sh`로 `ca.json`을 재생성하세요.
