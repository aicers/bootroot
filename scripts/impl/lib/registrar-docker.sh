# shellcheck shell=bash
# Common support for Docker-backed registrar acceptance scenarios.
#
# The runner is deliberately explicit about its launch inputs. A scenario
# must receive the checkout and the binary it is testing rather than infer
# either from its current directory; wrappers, CI and preflight therefore
# exercise the same contract.

registrar_docker_require_launcher_contract() {
  [ "$#" -eq 0 ] || fail "the registrar-redteam launcher takes no positional arguments"
  for registrar_docker_variable in BOOTROOT_PROJECT_DIR BOOTROOT_BIN ARTIFACT_DIR; do
    registrar_docker_value="${!registrar_docker_variable:-}"
    case "$registrar_docker_value" in
      /*) ;;
      *) fail "${registrar_docker_variable} must be an absolute path" ;;
    esac
    [ -e "$registrar_docker_value" ] || fail "${registrar_docker_variable} does not exist: ${registrar_docker_value}"
  done
  [ -d "$BOOTROOT_PROJECT_DIR" ] || fail "BOOTROOT_PROJECT_DIR is not a directory: $BOOTROOT_PROJECT_DIR"
  [ -x "$BOOTROOT_BIN" ] || fail "BOOTROOT_BIN is not executable: $BOOTROOT_BIN"
  [ -d "$ARTIFACT_DIR" ] || fail "ARTIFACT_DIR is not a directory: $ARTIFACT_DIR"
  [ -w "$ARTIFACT_DIR" ] || fail "ARTIFACT_DIR is not writable: $ARTIFACT_DIR"
}

registrar_docker_run_token() {
  local token
  token="${RUN_TOKEN:-${GITHUB_RUN_ID:-local-$(date +%s)-$$}}"
  token="$(printf '%s' "$token" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
  [ -n "$token" ] || fail "RUN_TOKEN reduced to the empty string; use at least one alphanumeric character"
  printf '%s\n' "$token"
}

# Stages the bounded registrar-leak model. The manifest is intentionally
# evaluated before the recursive credential scan: a missing input is a test
# setup error, never an excuse to scan a wider host or container filesystem.
registrar_docker_stage_leak_bundle() {
  local source_dir="$1" bundle_dir="$2" manifest="$3" entry expected actual
  mkdir -p "$bundle_dir" || fail "could not create registrar leak bundle"
  while IFS= read -r entry || [ -n "$entry" ]; do
    case "$entry" in ''|'#'*) continue ;; esac
    case "$entry" in /*|*'..'*) fail "invalid registrar leak manifest path: $entry" ;; esac
    [ -f "$source_dir/$entry" ] || fail "registrar leak manifest file is absent: $entry"
    mkdir -p "$bundle_dir/$(dirname "$entry")" || fail "could not create bundle parent for $entry"
    cp "$source_dir/$entry" "$bundle_dir/$entry" || fail "could not stage registrar bundle file: $entry"
  done <"$manifest"
  chmod -R a-w "$bundle_dir" || fail "could not make registrar leak bundle read-only"
  expected="$(grep -Ev '^(#|$)' "$manifest" | LC_ALL=C sort)"
  actual="$(cd "$bundle_dir" && find . -type f -print | sed 's|^./||' | LC_ALL=C sort)"
  [ "$actual" = "$expected" ] || fail "staged registrar regular-file set differs from its manifest"
}

registrar_docker_assert_no_backend_credentials() {
  local bundle_dir="$1"
  # These are credential values, not filenames. Restricting find to the
  # read-only bundle is the threat-model boundary; daemon material is never
  # an attacker input in this scenario.
  if grep -RInE '(X-Vault-Token|OPENBAO_TOKEN|role_id[[:space:]]*=|secret_id[[:space:]]*=)' "$bundle_dir"; then
    fail "the registrar leak bundle contains an OpenBao or AppRole credential"
  fi
}

# Creates the minimal deployment tree consumed by registrar Docker scenarios.
# `docker-compose.deploy.yml` has no build context, but it resolves these two
# files relative to itself. Keeping the copy rule here means the endurance arm
# and this per-PR arm cannot slowly grow different private deployments.
registrar_docker_prepare_deployment_tree() {
  local project_dir="$1" work_dir="$2"
  mkdir -p "$work_dir/openbao" || fail "could not create registrar deployment tree"
  cp "$project_dir/docker-compose.deploy.yml" "$work_dir/" ||
    fail "could not copy the deploy compose file"
  cp "$project_dir/openbao/openbao.hcl" "$work_dir/openbao/" ||
    fail "could not copy the OpenBao configuration"
  cp "$project_dir/responder.toml.compose" "$work_dir/" ||
    fail "could not copy the responder configuration"
}
