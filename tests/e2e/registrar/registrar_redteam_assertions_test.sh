#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LIBRARY="$ROOT_DIR/scripts/impl/lib/registrar-docker.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bootroot-registrar-assertions-XXXXXX")"

cleanup() {
  chmod -R u+w "$WORK_DIR" 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  return 1
}

# shellcheck source=../../../scripts/impl/lib/registrar-docker.sh
. "$LIBRARY"

SOURCE="$WORK_DIR/source"
BUNDLE="$WORK_DIR/bundle"
MANIFEST="$WORK_DIR/manifest"
mkdir -p "$SOURCE"
cat >"$MANIFEST" <<'EOF'
registrar-client.crt
registrar-client.key
registrar-endpoint.toml
registrar-endpoint-anchors.sha256
registrar-endpoint-ca.pem
EOF
cat >"$SOURCE/registrar-client.crt" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBtjCCAVugAwIBAgIUTESTONLYCERTIFICATEVALUE
-----END CERTIFICATE-----
EOF
cat >"$SOURCE/registrar-client.key" <<'EOF'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ
-----END PRIVATE KEY-----
EOF
cat >"$SOURCE/registrar-endpoint.toml" <<'EOF'
socket_path = "/run/bootroot/registrar.sock"
expected_endpoint_name = "001.bootroot-registrar-endpoint.example.test"
EOF
printf '%064d\n' 0 >"$SOURCE/registrar-endpoint-anchors.sha256"
cat >"$SOURCE/registrar-endpoint-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBtjCCAVugAwIBAgIUTESTONLYCAVALUE
-----END CERTIFICATE-----
EOF

# The only staged regular files are the manifest entries. A contaminated
# sibling proves the scan remains limited to the attacker bundle.
printf 'hvs.outside_the_manifest_token\n' >"$SOURCE/not-in-manifest"
registrar_docker_stage_leak_bundle "$SOURCE" "$BUNDLE" "$MANIFEST"
registrar_docker_assert_no_backend_credentials "$BUNDLE"

assert_rejected() {
  local content="$1"
  chmod u+w "$BUNDLE/registrar-endpoint.toml"
  printf '%s\n' "$content" >"$BUNDLE/registrar-endpoint.toml"
  if registrar_docker_assert_no_backend_credentials "$BUNDLE"; then
    printf 'credential was accepted: %s\n' "$content" >&2
    exit 1
  fi
}

assert_accepted() {
  local content="$1"
  chmod u+w "$BUNDLE/registrar-endpoint.toml"
  printf '%s\n' "$content" >"$BUNDLE/registrar-endpoint.toml"
  if ! registrar_docker_assert_no_backend_credentials "$BUNDLE"; then
    printf 'non-credential was rejected: %s\n' "$content" >&2
    exit 1
  fi
}

assert_rejected 'X-Vault-Token: hvs.labelled_token_value'
assert_rejected 'role_id = "123e4567-e89b-12d3-a456-426614174000"'
assert_rejected 'secret_id = "123e4567-e89b-12d3-a456-426614174001"'
# The values below deliberately do not match any bare token or UUID pattern.
assert_rejected 'x-vAuLt-tOkEn: labelled-vault-token'
assert_rejected 'x-oPeNbAo-tOkEn: labelled-openbao-token'
assert_rejected 'oPeNbAo_ToKeN = "labelled-openbao-token"'
assert_rejected 'vAuLt_ToKeN = "labelled-vault-token"'
assert_rejected 'RoLe_Id = "labelled-role-id"'
assert_rejected 'SeCrEt_Id = "labelled-secret-id"'
assert_rejected 'hvs.bare_openbao_token_value'
assert_rejected '123e4567-e89b-12d3-a456-426614174002'
assert_rejected '123e4567-e89b-12d3-a456-426614174003'
# A bare token prefix is intentionally exact; only credential labels ignore case.
assert_accepted 'HVS.not_a_supported_prefix'
