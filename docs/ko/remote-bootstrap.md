# 원격 부트스트랩 운영자 가이드

이 가이드는 step-ca, OpenBao, HTTP-01 리스폰더가 동작하는 머신(**제어
노드**)과 다른 머신에서 실행되는 서비스를 위한 **remote-bootstrap** 전달
모드를 다룹니다.

## remote-bootstrap과 local-file 중 선택 기준

`bootroot service add`는 `--delivery-mode`로 두 가지 전달 모드를 제공합니다.

| 모드 | 사용 시점 | 동작 |
| --- | --- | --- |
| `local-file` (기본값) | 서비스가 step-ca/OpenBao와 **같은** 머신에서 실행 | `service add`가 설정 파일을 디스크에 직접 기록 |
| `remote-bootstrap` | 서비스가 **다른** 머신에서 실행 | `service add`가 JSON 아티팩트를 생성하고, 운영자가 이를 서비스 호스트로 전달한 뒤 `bootroot-remote bootstrap`을 실행 |

서비스 머신이 제어 노드와 파일시스템을 공유하지 않는 경우
`remote-bootstrap`을 선택하세요.

## 원격 호스트 사전 요구사항

1. **`bootroot-remote` 바이너리 설치.** 사전 빌드된 릴리스 바이너리는 아직
    제공되지 않습니다. `cargo build --release --bin bootroot-remote`로
    소스에서 빌드하여 각 서비스 머신에 배포하세요.
    자세한 내용은 [설치](installation.md)를 참고하세요.

2. **네트워크 도달성.** 원격 호스트는 다음에 접근 가능해야 합니다.

    - OpenBao API 엔드포인트 (`--openbao-url` 값, 일반적으로
      `https://openbao.internal:8200` 또는 환경에 맞는 주소).
    - step-ca의 HTTPS ACME 디렉터리 (`--agent-server` 값, 예:
      `https://stepca.internal:9000/acme/acme/directory`).
    - HTTP-01 리스폰더 (`--agent-responder-url` 값, 예:
      `http://responder.internal:8080`).

3. **DNS / 이름 해석.** 서비스 인증서의 SAN(Subject Alternative Name)은
    해당 환경에서 사용하는 DNS, `/etc/hosts`, 또는 클라우드 내부 DNS에서
    해석 가능해야 합니다.

    !!! note
        [#472](https://github.com/aicers/bootroot/issues/472)에서 추적 중인
        compose 내부 DNS 별칭 자동화는 Docker 브리지 네트워크의 번들 컨테이너
        간 트래픽에만 적용됩니다. 원격 호스트는 운영자가 직접 실제 DNS 또는
        동등한 항목을 구성해야 합니다.

4. **파일시스템 레이아웃.** 시크릿, 인증서, 에이전트 설정을 위한 디렉터리가
    원격 호스트에 존재하거나 생성 가능해야 합니다. 경로는 부트스트랩
    아티팩트에 정의되어 `bootroot-remote bootstrap`에 전달됩니다.

## 전송 경계

bootroot는 의도적으로 원격 호스트로 파일을 **전송하지 않습니다**.
`bootroot service add --delivery-mode remote-bootstrap`은 JSON 아티팩트와
자격증명 파일을 생성하며, 운영자가 환경에 맞는 전송 메커니즘을 선택합니다.

원격 호스트에 전달해야 하는 파일은 응답 래핑(response wrapping) 활성화
여부(기본값: 활성)에 따라 달라집니다:

**래핑 활성 (기본):**

| 파일 | 소스 경로 (제어 노드) | 용도 |
| --- | --- | --- |
| `bootstrap.json` | `secrets/remote-bootstrap/services/<service>/bootstrap.json` | `bootroot-remote`가 `wrap_token`을 언래핑하여 `secret_id`를 얻는 머신 판독 가능 아티팩트 (**민감**) |
| `role_id` | `secrets/services/<service>/role_id` | AppRole 식별자 (장기 유효) |

**래핑 비활성 (`--no-wrap`):**

| 파일 | 소스 경로 (제어 노드) | 용도 |
| --- | --- | --- |
| `bootstrap.json` | `secrets/remote-bootstrap/services/<service>/bootstrap.json` | `bootroot-remote bootstrap`이 소비하는 머신 판독 가능 아티팩트 |
| `role_id` | `secrets/services/<service>/role_id` | AppRole 식별자 (장기 유효) |
| `secret_id` | `secrets/services/<service>/secret_id` | AppRole 자격증명 (**민감**) |

### 옵션 1: SSH + 셸 스크립트 (소규모 배포 권장)

소수의 서비스 머신을 운영하는 소규모 배포에 적합합니다.
아래 예시는 민감한 토큰이 셸 명령줄과 `ps` 출력에 노출되지 않도록
`--artifact` 호출 방식을 사용합니다.

```bash
#!/usr/bin/env bash
set -euo pipefail

SERVICE=edge-remote
CONTROL_SECRETS=./secrets
REMOTE_HOST=edge-node-02
REMOTE_USER=deploy
REMOTE_BASE=/srv/bootroot
ARTIFACT="$CONTROL_SECRETS/remote-bootstrap/services/$SERVICE/bootstrap.json"

# 1. 제어 노드에서 서비스 등록
bootroot service add \
  --service-name "$SERVICE" \
  --deploy-type daemon \
  --delivery-mode remote-bootstrap \
  --hostname "$REMOTE_HOST" \
  --domain trusted.domain \
  --agent-config "$REMOTE_BASE/agent.toml" \
  --cert-path "$REMOTE_BASE/certs/$SERVICE.crt" \
  --key-path "$REMOTE_BASE/certs/$SERVICE.key" \
  --root-token "$OPENBAO_ROOT_TOKEN"

# 2. 대상 디렉터리 생성 및 아티팩트 + role_id 전송
ssh "$REMOTE_USER@$REMOTE_HOST" \
  mkdir -p "$REMOTE_BASE/secrets/services/$SERVICE"

scp -p \
  "$ARTIFACT" \
  "$CONTROL_SECRETS/services/$SERVICE/role_id" \
  "$REMOTE_USER@$REMOTE_HOST:$REMOTE_BASE/secrets/services/$SERVICE/"

# 3. 부트스트랩 전 schema_version 검증
if ! jq -e '.schema_version == 2' "$ARTIFACT" > /dev/null; then
  echo "ERROR: $ARTIFACT 의 schema_version이 지원되지 않습니다" >&2
  exit 1
fi

# 4. 원격 호스트에서 --artifact를 사용하여 부트스트랩 실행
#    아티팩트에 포함된 wrap_token을 bootroot-remote가 언래핑하여
#    런타임에 secret_id를 얻습니다.
ssh "$REMOTE_USER@$REMOTE_HOST" \
  bootroot-remote bootstrap \
    --artifact "$REMOTE_BASE/secrets/services/$SERVICE/bootstrap.json" \
    --output json
```

> **참고:** 래핑이 활성(기본값)이면 `bootstrap.json`에 `wrap_token`이
> 포함되어 **민감한 자격증명 파일**입니다. `secret_id`와 동일한 수준으로
> 관리하세요: 파일 권한을 제한하고, 암호화된 채널로 전송하며, 위협 모델에
> 따라 전달 후 제어 노드에서 삭제하세요.
>
> 래핑이 비활성(`--no-wrap`)이면 `secret_id`도 원격 호스트에 복사해야
> 하며, 하위 호환을 위해 `--artifact` 대신 개별 CLI 플래그를 사용할
> 수 있습니다.

### 옵션 2: systemd-credentials (`--no-wrap`)

> **레거시 / 하위 호환 경로.** 이 옵션은 개별 CLI 플래그와 원본
> `secret_id` 파일을 사용합니다. `bootroot service add`에서 래핑을
> 비활성화(`--no-wrap`)한 경우에 해당합니다. 신규 배포에서는 래핑이
> 활성화된(기본값) 옵션 1의 `--artifact` 방식을 권장합니다.

시크릿이 일반 파일시스템에 노출되지 않아야 하는 단일 호스트 구성에
적합합니다. 제어 노드에서 `systemd-creds encrypt`를 사용하고, 원격 호스트의
서비스 유닛에서 `LoadCredential=`을 사용합니다.

```ini
# /etc/systemd/system/bootroot-remote-bootstrap.service
[Service]
Type=oneshot
LoadCredential=secret_id:/etc/credstore/bootroot-edge-remote-secret-id
ExecStart=/usr/local/bin/bootroot-remote bootstrap \
    --openbao-url https://openbao.internal:8200 \
    --service-name edge-remote \
    --secret-id-path %d/secret_id \
    --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id \
    --eab-file-path /srv/bootroot/secrets/services/edge-remote/eab.json \
    --agent-config-path /srv/bootroot/agent.toml \
    --agent-server https://stepca.internal:9000/acme/acme/directory \
    --agent-domain trusted.domain \
    --agent-responder-url http://responder.internal:8080 \
    --profile-hostname edge-node-02 \
    --profile-cert-path /srv/bootroot/certs/edge-remote.crt \
    --profile-key-path /srv/bootroot/certs/edge-remote.key \
    --ca-bundle-path /srv/bootroot/certs/ca-bundle.pem \
    --output json
```

### 옵션 3: Ansible (`--no-wrap`)

> **레거시 / 하위 호환 경로.** 이 옵션은 개별 CLI 플래그와 원본
> `secret_id` 파일 복사를 사용합니다. `bootroot service add`에서 래핑을
> 비활성화(`--no-wrap`)한 경우에 해당합니다. 신규 배포에서는 래핑이
> 활성화된(기본값) 옵션 1의 `--artifact` 방식을 권장합니다.
> 이 플레이북을 래핑 흐름에 맞게 변경하려면 `secret_id` 대신
> `bootstrap.json`을 복사하고 `--artifact`로 호출하세요.

기존 구성 관리 체계가 있는 대규모 플릿에 적합합니다.

```yaml
# playbook: bootroot-remote-bootstrap.yml
- name: bootroot-remote를 통한 원격 서비스 부트스트랩
  hosts: edge_nodes
  become: true
  vars:
    service_name: edge-remote
    control_secrets: ./secrets
    remote_base: /srv/bootroot
    # 필수: 원격 접근 가능한 엔드포인트로 설정하세요.
    # 아티팩트에는 제어 노드에서만 유효한 localhost placeholder가
    # 포함되어 있을 수 있습니다.
    agent_server: https://stepca.internal:9000/acme/acme/directory
    agent_responder_url: http://responder.internal:8080
  tasks:
    - name: 제어 노드에서 부트스트랩 아티팩트 읽기
      ansible.builtin.slurp:
        src: "{{ control_secrets }}/remote-bootstrap/services/{{ service_name }}/bootstrap.json"
      delegate_to: localhost
      become: false
      register: artifact_b64

    - name: 부트스트랩 아티팩트 파싱
      ansible.builtin.set_fact:
        artifact: "{{ artifact_b64.content | b64decode | from_json }}"

    - name: schema_version 검증
      ansible.builtin.assert:
        that:
          - artifact.schema_version == 2
        fail_msg: >-
          지원되지 않는 schema_version {{ artifact.schema_version }};
          이 플레이북은 버전 2만 지원합니다.

    - name: 시크릿 디렉터리 생성
      ansible.builtin.file:
        path: "{{ remote_base }}/secrets/services/{{ service_name }}"
        state: directory
        mode: "0700"

    - name: role_id 복사
      ansible.builtin.copy:
        src: "{{ control_secrets }}/services/{{ service_name }}/role_id"
        dest: "{{ artifact.role_id_path }}"
        mode: "0600"

    - name: secret_id 복사
      ansible.builtin.copy:
        src: "{{ control_secrets }}/services/{{ service_name }}/secret_id"
        dest: "{{ artifact.secret_id_path }}"
        mode: "0600"

    - name: 선택적 플래그 구성
      ansible.builtin.set_fact:
        instance_id_flag: >-
          {{ '--profile-instance-id ' ~ artifact.profile_instance_id
             if artifact.profile_instance_id | default('') | length > 0
             else '' }}

    - name: bootroot-remote bootstrap 실행
      ansible.builtin.command:
        cmd: >-
          bootroot-remote bootstrap
          --openbao-url {{ artifact.openbao_url }}
          --kv-mount {{ artifact.kv_mount }}
          --service-name {{ artifact.service_name }}
          --role-id-path {{ artifact.role_id_path }}
          --secret-id-path {{ artifact.secret_id_path }}
          --eab-file-path {{ artifact.eab_file_path }}
          --agent-config-path {{ artifact.agent_config_path }}
          --agent-email {{ artifact.agent_email }}
          --agent-server {{ agent_server }}
          --agent-domain {{ artifact.agent_domain }}
          --agent-responder-url {{ agent_responder_url }}
          --profile-hostname {{ artifact.profile_hostname }}
          {{ instance_id_flag }}
          --profile-cert-path {{ artifact.profile_cert_path }}
          --profile-key-path {{ artifact.profile_key_path }}
          --ca-bundle-path {{ artifact.ca_bundle_path }}
          --output json
      changed_when: true
```

### 옵션 4: cloud-init (`--no-wrap`)

> **레거시 / 하위 호환 경로.** 이 옵션은 개별 CLI 플래그와 원본
> `secret_id`를 cloud-init 사용자 데이터에 직접 기록합니다.
> `bootroot service add`에서 래핑을 비활성화(`--no-wrap`)한 경우에
> 해당합니다. 신규 배포에서는 래핑이 활성화된(기본값) 옵션 1의
> `--artifact` 방식을 권장합니다. 래핑을 사용할 경우
> `bootstrap.json`을 `write_files`에 넣고 `--artifact`로 호출하세요.

클라우드 VM의 최초 부팅 프로비저닝에 적합합니다.

```yaml
#cloud-config
write_files:
  - path: /srv/bootroot/secrets/services/edge-remote/role_id
    permissions: "0600"
    content: |
      <ROLE_ID_VALUE>
  - path: /srv/bootroot/secrets/services/edge-remote/secret_id
    permissions: "0600"
    content: |
      <SECRET_ID_VALUE>
runcmd:
  - >-
    /usr/local/bin/bootroot-remote bootstrap
    --openbao-url https://openbao.internal:8200
    --service-name edge-remote
    --role-id-path /srv/bootroot/secrets/services/edge-remote/role_id
    --secret-id-path /srv/bootroot/secrets/services/edge-remote/secret_id
    --eab-file-path /srv/bootroot/secrets/services/edge-remote/eab.json
    --agent-config-path /srv/bootroot/agent.toml
    --agent-server https://stepca.internal:9000/acme/acme/directory
    --agent-domain trusted.domain
    --agent-responder-url http://responder.internal:8080
    --profile-hostname edge-node-02
    --profile-cert-path /srv/bootroot/certs/edge-remote.crt
    --profile-key-path /srv/bootroot/certs/edge-remote.key
    --ca-bundle-path /srv/bootroot/certs/ca-bundle.pem
    --output json
```

## Wrap token 복구

래핑이 활성(기본값)이면 `bootstrap.json`에 포함된 `wrap_token`은
제한된 TTL(기본값 30분)을 가집니다.
`bootroot-remote bootstrap --artifact` 실행 시 두 가지 실패 모드가
발생할 수 있습니다:

### 만료된 wrap token

`bootroot-remote`가 언래핑하기 전에 `wrap_token` TTL이 경과한 경우입니다.
`bootroot-remote`는 `wrap_expires_at`과 현재 시간을 비교하여 **만료** 오류와
복구 안내를 출력합니다.

**복구:**

1. control node에서 동일한 인자로 `bootroot service add`를 다시 실행합니다.
   멱등 재실행으로 새 `wrap_token`이 포함된 bootstrap 아티팩트를 재생성합니다.
2. 갱신된 `bootstrap.json`을 원격 호스트로 전송합니다.
3. `bootroot-remote bootstrap --artifact <경로>`를 실행합니다.

### 이미 언래핑된 wrap token

토큰이 이미 소비된 경우입니다. 정당한 `bootroot-remote` 호출 전에 제3자가
언래핑했음을 의미합니다. `bootroot-remote`는 이를 **잠재적 보안 사고**로
표시합니다.

**복구:**

1. 누가 또는 무엇이 토큰을 소비했는지 조사합니다.
2. `secret_id`를 즉시 회전합니다:
   `bootroot rotate approle-secret-id --service-name <service>`.
3. 동일한 인자로 `bootroot service add`를 다시 실행해 새 `wrap_token`을
   생성합니다.
4. 아티팩트를 전송하고 원격 호스트에서 `bootroot-remote bootstrap`을
   실행합니다.

## 강제 재발급(제어 플레인 → 원격 agent)

제어 플레인에는 원격 호스트로의 푸시 채널이 없으므로
`bootroot rotate force-reissue`가 원격의 cert 파일을 직접 삭제할 수
없습니다. 대신 `--delivery-mode remote-bootstrap` 서비스의 경우 명령은
OpenBao KV `{kv_mount}/data/bootroot/services/<service>/reissue`
경로에 버전 관리된 재발급 요청을 기록합니다:

```json
{
  "requested_at": "2026-04-19T12:34:56Z",
  "requester": "<운영자 라벨>"
}
```

원격 `bootroot-agent`는 AppRole로 인증한 뒤 등록된 각 서비스의
재발급 경로를 `fast_poll_interval`(기본 `30s`) 주기로 폴링하는
fast-poll 루프로 요청을 소비합니다. agent가 마지막으로 적용한
버전(`state_path`에 서비스별로 기록)보다 KV v2 버전이 새로워질
때마다 즉시 ACME 갱신을 트리거하고, `completed_at` 및
`completed_version`을 다시 기록해 제어 플레인이 종단 간 지연을
관측할 수 있게 합니다.

이 루프는 `agent.toml`의 `[openbao]` 섹션으로 구동됩니다. 해당
섹션은 모든 remote-bootstrap 호스트에서 **필수**입니다 — 섹션이
없으면 agent는 제어 플레인 KV 요청을 읽을 소비자가 존재하지 않아
`force-reissue`는 인증서가 자연 만료에 가까워질 때까지 큐에
남습니다. `bootroot-remote bootstrap`은 실행할 때마다 연결 필드
(`url`, `kv_mount`, `role_id_path`, `secret_id_path`,
`ca_bundle_path`)를 자동으로 기록하므로 운영자가 직접 편집할 필요는
없습니다. 레거시 원격 호스트가 `bootroot-remote bootstrap`을 다시
실행하지 않은 상태로 bootroot를 업그레이드한 경우 섹션이 비어 있을 수
있으며, 다음 번 bootstrap이 섹션을 채울 때까지 `force-reissue` 요청은
관측되지 않습니다.

```toml
# agent.toml — `bootroot-remote bootstrap`이 자동 반영
[openbao]
url = "https://openbao.internal:8200"
kv_mount = "secret"
role_id_path = "/etc/bootroot/role_id"
secret_id_path = "/etc/bootroot/secret_id"
ca_bundle_path = "/etc/bootroot/ca-bundle.pem"   # https://에는 필수
fast_poll_interval = "30s"                        # 선택; 기본 30s
state_path = "/etc/bootroot/bootroot-agent-state.json" # bootstrap이 기본 제공
```

`state_path`는 재시작 간에 에이전트의
`last_reissue_seen_version`, `in_flight_renewals`,
`pending_completion_writes` 맵을 보존합니다 — 중복 갱신을 피하고 완료
확인을 재시도하기 위해 이 기능이 의존하는 상태입니다. 현재 값이
없거나 *상대 경로*인 경우 bootstrap이 `agent.toml` 옆의 절대 경로로
갱신하므로, systemd 스타일 supervisor(쓰기 가능/안정적인 cwd를
보장하지 않는 환경)에서도 fast-poll 상태가 cwd 상대 경로에 저장되지
않습니다. 따라서 내장 기본값(상대 경로)이 저장된 기존 구성은
`bootroot-remote bootstrap`을 다시 실행하면 수리되며, 이는 구성 검증이
실패 시 출력하는 권고 문구와 일치합니다. 운영자는 원하는 절대 경로로
덮어쓸 수 있으며, 이후 bootstrap 재실행은 사용자가 지정한 절대 경로
값을 보존합니다. 구성 검증은 상대 경로 `state_path`(값이 생략되어
내장 기본값으로 채워지는 경우 포함)도 거부하므로, 설정 오류가 운영
중에 조용히 취약한 상태 파일을 사용하는 대신 `bootroot-agent` 시작
시점에 드러납니다.

이 메커니즘은 원격 agent가 이미 보유한 동일 AppRole 자격증명을
재사용하고, 서비스당 `fast_poll_interval`마다 KV 읽기 1회를 추가하며,
remote-bootstrap 서비스의 최악의 force-reissue 지연을 1
`check_interval`(기본 1시간)에서 약 1 fast-poll 주기로 단축합니다.

운영자는 `bootroot rotate force-reissue`에 `--wait`(및 선택적으로
`--wait-timeout`)을 지정해 원격 agent가 완료를 보고할 때까지 차단할 수
있습니다. `--wait` 타임아웃은 오류가 아닙니다 — 요청은 큐에 남아 있으며
다음 fast-poll 틱에서 적용됩니다.

원격 호스트에 동일한 `service_name`을 가진 여러 `[[profiles]]`가 있을
경우(같은 머신에서 한 서비스를 여러 인스턴스로 운영하는 경우 등),
fast-poll 틱은 KV 버전을 소비된 것으로 표시하기 전에 일치하는 모든
프로파일에 갱신 트리거를 펼쳐 보냅니다. 따라서 단일 force-reissue가
모든 인스턴스를 회전합니다. 펼쳐 보낸 프로파일 중 하나라도 실패하면,
같은 요청에 대해 이미 성공한 프로파일은 `state_path`의 서비스별
`in_flight_renewals` 진행 상황으로 기록됩니다. 다음 틱은 동일한 KV
버전에 대해 실패한 형제 프로파일*만* 재시도하며, 이미 갱신된 프로파일은
건너뛰고 두 번째 강제 갱신을 받지 않습니다. 버전은 모든 프로파일이
성공한 뒤에만 소비된 것으로 표시되고, 더 새로운 재발급 요청이
덮어쓰거나 요청이 KV에서 사라지면 낡은 프로파일 진행 상태는 자동으로
정리됩니다.

`--wait`가 특정 KV 버전에 고정되길 원하는 운영자를 위해
`rotate force-reissue`는 발행 POST의 응답에서 버전을 직접 캡처합니다.
이후 GET에 의존하지 않기 때문에 원격 agent의 완료 기록이 그 사이에
메타데이터 버전을 증가시켜도 `--wait`가 무한 대기하지 않습니다.

원격 agent가 인증서를 갱신했지만 이어지는 `completed_at`의 OpenBao
재기록이 실패한 경우(일시적인 KV 장애, 네트워크 끊김 등), agent는
`state_path`에 `pending_completion_writes` 항목을 영속화하고 다음
틱에서 완료 기록만 재시도합니다. 이로써 인증서가 실제로 회전된
이후에도 `bootroot rotate force-reissue --wait`가 확인을 받지 못한
채 멈추는 상황을 방지합니다. 더 새로운 재발급 요청이 덮어쓰거나 KV에서
요청 자체가 제거되면 미해결 항목은 자동으로 정리됩니다.

## 멱등 service add 재실행

기존 `remote-bootstrap` 서비스에 동일한 인자로 `bootroot service add`를
다시 실행하면 안전합니다. 래핑이 활성(기본값)이면 재실행 시 래핑된 새
`secret_id`를 발급하고 새 `wrap_token`이 포함된 `bootstrap.json`을
기록합니다. 운영자는 갱신된 아티팩트를 원격 호스트로 전달한 뒤
`bootroot-remote bootstrap`을 다시 실행해야 합니다.

정책 필드(`--secret-id-ttl`, `--secret-id-wrap-ttl`, `--no-wrap`)만
다른 경우 명령이 거부되며 `bootroot service update` 사용을 안내합니다.

## `secret_id` 위생 체크리스트

`secret_id`는 remote-bootstrap 흐름에서 가장 민감한 아티팩트입니다.
단기 유효 자격증명으로 취급하세요.

- **파일 권한**: `0600`, 서비스 사용자 소유.
    `bootroot service add`는 이미 제한된 권한으로 파일을 기록합니다.
- **로그 및 커밋 금지**: 버전 관리(`.gitignore`)에서 제외하고, 배포
    스크립트에서 stdout이나 로그 파일에 기록하지 않도록 하세요.
- **전달 후 제어 노드에서 삭제**: `secret_id`를 원격 호스트로 전달한 후
    로컬 복사본을 삭제하세요.
- **짧은 TTL / response wrapping**: `bootroot service add`의
    `--secret-id-ttl`로 `secret_id` 수명을 제한하고, response wrapping을
    활성화(기본값) 상태로 유지하여 부트스트랩 아티팩트에 원본 `secret_id`
    대신 일회용 `wrap_token`이 포함되도록 하세요. 이렇게 하면 wrap token이
    명령줄이나 `ps` 출력에 노출되지 않으며, 원격 전송 노출 시간을 초
    단위로 줄입니다. 단, 제어 노드에는 로컬 운영을 위해
    `secrets/services/<service>/secret_id`에 원본 `secret_id`가 기록되므로,
    전달 후 이 파일을 보호하거나 삭제하세요.
- **회전**: 제어 노드에서 `bootroot rotate approle-secret-id` 실행 후,
    서비스 머신에서 `bootroot-remote apply-secret-id`로 새 `secret_id`를
    전달하세요. 회전 워크플로우는 [운영](operations.md)을 참고하세요.

## 네트워크 요구사항

원격 호스트는 다음 엔드포인트에 네트워크 연결이 가능해야 합니다.

| 엔드포인트 | 프로토콜 | 용도 |
| --- | --- | --- |
| OpenBao API (`--openbao-url`) | HTTPS | 부트스트랩 시 시크릿(`secret_id`, 리스폰더 HMAC, trust 번들, EAB가 설정된 경우에만 포함) pull |
| step-ca ACME 디렉터리 (`--agent-server`) | HTTPS | `bootroot-agent`에 의한 인증서 발급 및 갱신 |
| HTTP-01 리스폰더 (`--agent-responder-url`) | HTTP | 도메인 검증을 위한 ACME 챌린지 토큰 게시 |

부트스트랩 아티팩트의 `--agent-server`, `--agent-responder-url` 값은
기본적으로 localhost placeholder를 사용합니다. 별도 서비스 머신에서 실행하기
전에 원격 접근 가능한 엔드포인트로 교체하세요.

!!! warning
    자동 HTTP-01 DNS 별칭 등록(현재 미출시 버전에 추가됨)은 Docker 브리지
    네트워크의 번들 컨테이너 간 트래픽에만 적용됩니다. 원격 호스트의 경우
    리스폰더와 CA 관점 모두에서 서비스의 SAN이 올바르게 해석되도록 실제 DNS
    레코드 또는 `/etc/hosts` 항목을 구성해야 합니다.

## `RemoteBootstrapArtifact` 스키마 참조

`secrets/remote-bootstrap/services/<service>/bootstrap.json`에 기록되는 JSON
아티팩트는 버전이 지정된 스키마를 따릅니다. 자동화에서는 파싱 전에
`schema_version`을 확인해야 합니다.

현재 버전: **2**

| 필드 | 타입 | 설명 | 사용처 |
| --- | --- | --- | --- |
| `schema_version` | `u32` | 스키마 버전 번호. 호환성을 깨는 변경 시 증가. | 파서 사전 검사 |
| `openbao_url` | `string` | OpenBao API URL | `--openbao-url` |
| `kv_mount` | `string` | OpenBao KV v2 마운트 경로 | `--kv-mount` |
| `service_name` | `string` | 등록된 서비스 이름 | `--service-name` |
| `role_id_path` | `string` | 원격 호스트의 AppRole `role_id` 파일 경로 | `--role-id-path` |
| `secret_id_path` | `string` | 원격 호스트의 AppRole `secret_id` 파일 경로 | `--secret-id-path` |
| `eab_file_path` | `string` | EAB 자격증명 JSON 파일 경로. 운영자가 OpenBao KV에 EAB 자격증명을 프로비저닝한 경우에만 bootroot가 이 파일을 기록합니다. KV 항목이 없는 경우 bootroot는 이전 부트스트랩이 남긴 오래된 `eab.json`을 제거하여 `bootroot-agent --eab-file`이 폐기된 자격증명을 전달하지 못하도록 합니다. 이때 eab 반영 단계는 오래된 파일을 제거한 경우 `applied`로, 애초에 파일이 없었던 경우 `skipped`로 보고합니다. | `--eab-file-path` |
| `agent_config_path` | `string` | 원격 호스트의 `agent.toml` 경로 | `--agent-config-path` |
| `ca_bundle_path` | `string` | 원격 호스트의 CA trust bundle PEM 파일 경로 | `--ca-bundle-path` |
| `ca_bundle_pem` | `string` | 제어 노드 CA trust 앵커의 인라인 PEM 콘텐츠. 부트스트랩 시 `ca_bundle_path`에 기록됨. `openbao_url`이 HTTPS인 경우 시스템 trust store 대신 이 CA를 TLS trust 앵커로 사용. 공유 프리미티브 — http01 admin 클라이언트(#514)에서도 사용. | 내부 사용 (TLS trust) |
| `openbao_agent_config_path` | `string` | OpenBao Agent 설정(HCL) 경로 | 내부 사용 |
| `openbao_agent_template_path` | `string` | OpenBao Agent 템플릿 경로 | 내부 사용 |
| `openbao_agent_token_path` | `string` | OpenBao Agent 토큰 파일 경로 | 내부 사용 |
| `agent_email` | `string` | ACME 계정 이메일 | `--agent-email` |
| `agent_server` | `string` | step-ca ACME 디렉터리 URL (기본값: localhost placeholder) | `--agent-server` |
| `agent_domain` | `string` | 인증서 SAN 도메인 | `--agent-domain` |
| `agent_responder_url` | `string` | HTTP-01 리스폰더 URL (기본값: localhost placeholder) | `--agent-responder-url` |
| `profile_hostname` | `string` | 에이전트 프로필 호스트명 | `--profile-hostname` |
| `profile_instance_id` | `string` | 인스턴스 식별자 (비어있을 수 있음) | `--profile-instance-id` |
| `profile_cert_path` | `string` | 발급된 인증서 출력 경로 | `--profile-cert-path` |
| `profile_key_path` | `string` | 개인키 출력 경로 | `--profile-key-path` |
| `post_renew_hooks` | `array` | 갱신 후 훅 항목 (비어있으면 생략). 각 항목은 `command`, `args`, `timeout_secs`, `on_failure` 포함. | `--post-renew-command` 및 관련 플래그 |
| `wrap_token` | `string?` | 응답 래핑된 `secret_id` 토큰 (`--no-wrap` 사용 시 생략). 민감 정보 — 자격 증명으로 취급하세요. | `bootroot-remote` 언래핑 경로 |
| `wrap_expires_at` | `string?` | `wrap_token` 만료 시각 (RFC 3339 형식, 래핑 비활성화 시 생략). | `bootroot-remote` 언래핑 오류 분류 |

### 버전 이력

| 버전 | 변경사항 |
| --- | --- |
| 2 | 필수 필드 `ca_bundle_pem` 추가 (제어 노드 CA 앵커의 인라인 PEM). |
| 1 | 초기 스키마. |

### 버전 관리 규칙

- **호환성을 깨는 변경** (필드 삭제, 이름 변경, 타입 변경):
    `schema_version` 증가.
- **추가적 변경** (`skip_serializing_if`가 있는 새 선택 필드):
    증가 불필요. 기존 파서는 알 수 없는 키를 무시합니다.
- **소비자 계약**: 필드에 접근하기 전에 `schema_version >= 1` 및
    `schema_version <= <지원 최대값>`을 확인하세요. 지원되지 않는 버전에서는
    명시적으로 실패해야 합니다. `bootroot-remote`는 `--artifact` 사용 시
    이 검사를 자동으로 수행합니다.
