#!/usr/bin/env bash
#
# Validates the two openssl-compatibility properties the E2E harness
# relies on, without Docker and without a second openssl on the host.
#
# Neither property is observable from CI. The runners carry an OpenSSL
# that has `x509 -ext` and spells the digest `sha256 Fingerprint=`, so a
# probe that stopped rejecting anything, or a read that went back to
# anchoring on one spelling, would leave the whole matrix green and
# break only on a host that ships LibreSSL as `openssl` — which is what
# macOS does. The checks below drive the harness's own functions against
# stub binaries and fixture files so a regression fails here instead.
#
# The functions are extracted from the harness scripts rather than
# copied, so this validates the shipped code. Sourcing whole scripts is
# what it avoids: they derive paths from `BASH_SOURCE` and pull in
# `lib/audit-log.sh`, none of which these functions need.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IMPL_DIR="$ROOT_DIR/scripts/impl"
LABEL="validate-e2e-openssl-compat"

# All six scripts that check for `openssl` gate on `x509 -ext`, not only
# `run-stepca-san.sh`, which is the sole caller: the matrix runs every
# step against one host, so a host that cannot serve the SAN step cannot
# serve the matrix. Pinning the set here is what keeps a later change
# from quietly narrowing it back to the one script that calls the option.
GATED_SCRIPTS=(
  run-ca-key-rotation-recovery.sh
  run-local-lifecycle.sh
  run-openbao-tls-reown.sh
  run-reinit-recovery.sh
  run-remote-lifecycle.sh
  run-stepca-san.sh
)

# The scripts that read a SHA-256 fingerprint back out of a cert-meta
# snapshot they wrote earlier in the same run.
FINGERPRINT_SCRIPTS=(
  run-ca-key-rotation-recovery.sh
  run-local-lifecycle.sh
  run-remote-lifecycle.sh
)

# An OpenSSL 3.x `x509 -help`, trimmed to the lines that matter: `-ext`
# alongside the two options whose names start with it, so a probe that
# matched a prefix rather than the whole option would pass here and fail
# the LibreSSL case below.
HELP_CAPABLE=' -help                      Display this summary
 -ext val                   Restrict which X.509 extensions to print and/or copy
 -extfile infile            Config file with X509V3 extensions to add
 -extensions val            Section of extfile to use - default: unnamed section'

# LibreSSL 3.3.6's `x509 -help`: `-extfile` and `-extensions` are there,
# `-ext` is not.
HELP_WITHOUT_EXT=' -clrext            Clear all extensions
 -extensions section
                    Section from config file with X509V3 extensions to add
 -extfile file      Configuration file with X509V3 extensions to add
 -fingerprint       Print the certificate fingerprint'

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

failures=0

ok() {
  printf '[%s]   ok   %s\n' "$LABEL" "$1"
}

bad() {
  printf '[%s]   FAIL %s\n' "$LABEL" "$1" >&2
  failures=$((failures + 1))
}

expect_eq() {
  local what="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    ok "$what"
  else
    bad "$what: expected [$want], got [$got]"
  fi
}

expect_contains() {
  local what="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*) ok "$what" ;;
    *) bad "$what: [$haystack] does not contain [$needle]" ;;
  esac
}

expect_lacks() {
  local what="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*) bad "$what: [$haystack] should not contain [$needle]" ;;
    *) ok "$what" ;;
  esac
}

# Writes a sourceable file holding the named functions as they appear in
# the harness script, plus the two things they close over: a `fail` that
# prints and exits, and `CERT_META_DIR`. A function that does not extract
# is a hard error rather than an empty suite that reports success.
build_subject() {
  local script="$1" cert_meta_dir="$2" first_fn="$3"
  shift 2
  # Keyed by the first function too: one script is a subject of both
  # suites below, and they want different function sets.
  local subject="$TMP_DIR/subject-$script-$first_fn.sh"
  {
    printf 'CERT_META_DIR=%q\n' "$cert_meta_dir"
    printf 'fail() { printf "%%s\\n" "$1" >&2; exit 1; }\n'
  } >"$subject"

  local fn body
  for fn in "$@"; do
    body="$(sed -n "/^${fn}() {/,/^}/p" "$IMPL_DIR/$script")"
    if [ -z "$body" ]; then
      printf '[%s] %s does not define %s()\n' "$LABEL" "$script" "$fn" >&2
      exit 1
    fi
    printf '%s\n' "$body" >>"$subject"
  done
  printf '%s\n' "$subject"
}

# Runs one call against an extracted subject and prints its combined
# output. The caller asserts on that text, so a `fail` inside the subject
# must not take this script down with it.
call_subject() {
  local subject="$1" call="$2"
  bash -c '. "$1"; eval "$2"' _ "$subject" "$call" 2>&1 || true
}

# A stub `openssl` that answers `x509 -help` with the given text and
# exit status. The status varies because some builds exit non-zero from
# `-help`, which is why the harness reads the text and lets the match
# alone decide.
#
# `cat` is spelled absolutely: the stub runs under a PATH holding only
# itself and the toolbox, so a bare `cat` would resolve to nothing and
# every stub would answer with silence — which reads as "no -ext" and
# would pass the rejection cases for the wrong reason.
CAT_BIN="$(command -v cat)"

make_openssl_stub() {
  local dir="$1" exit_code="$2" help_text="$3"
  mkdir -p "$dir"
  printf '%s\n' "$help_text" >"$dir/help.txt"
  printf '#!/bin/sh\n%q %q\nexit %s\n' "$CAT_BIN" "$dir/help.txt" "$exit_code" >"$dir/openssl"
  chmod +x "$dir/openssl"
}

# ---------------------------------------------------------------------------
# The prerequisite probe
# ---------------------------------------------------------------------------

# `ensure_openssl` needs `grep` on PATH and nothing else, so the absent
# case can hand it a PATH that holds no `openssl` at all.
TOOLBOX="$TMP_DIR/toolbox"
mkdir -p "$TOOLBOX"
ln -s "$(command -v grep)" "$TOOLBOX/grep"

run_ensure_openssl() {
  local subject="$1" path="$2"
  PATH="$path" "$BASH" -c '. "$1"; ensure_openssl && printf "ACCEPTED\n"' _ "$subject" 2>&1 || true
}

check_prerequisite_probe() {
  local script="$1"
  printf '[%s] %s: openssl prerequisite\n' "$LABEL" "$script"
  local subject
  subject="$(build_subject "$script" "$TMP_DIR/unused" ensure_openssl)"

  local capable="$TMP_DIR/bin-capable-$script"
  local capable_noisy="$TMP_DIR/bin-capable-noisy-$script"
  local libre="$TMP_DIR/bin-libre-$script"
  local mute="$TMP_DIR/bin-mute-$script"
  make_openssl_stub "$capable" 0 "$HELP_CAPABLE"
  make_openssl_stub "$capable_noisy" 1 "$HELP_CAPABLE"
  make_openssl_stub "$libre" 0 "$HELP_WITHOUT_EXT"
  make_openssl_stub "$mute" 1 ""

  expect_contains "accepts an openssl with x509 -ext" \
    "$(run_ensure_openssl "$subject" "$capable:$TOOLBOX")" ACCEPTED

  # The `|| true` around the probe exists for exactly this: a build that
  # prints the option but exits non-zero from `-help` still has it.
  expect_contains "accepts it even when -help exits non-zero" \
    "$(run_ensure_openssl "$subject" "$capable_noisy:$TOOLBOX")" ACCEPTED

  local rejected
  rejected="$(run_ensure_openssl "$subject" "$libre:$TOOLBOX")"
  expect_lacks "rejects an openssl without x509 -ext" "$rejected" ACCEPTED
  expect_contains "rejection names the binary it found" "$rejected" "$libre/openssl"
  expect_contains "rejection names the missing option" "$rejected" "x509 -ext"
  expect_contains "rejection names the PATH fix" "$rejected" "first on PATH"
  # On the hosts this triggers on, a capable openssl is usually already
  # installed and merely later on PATH, and which command would install
  # one is not something the harness can know. Word-bounded, so the
  # `port` in "does not support" is not read as MacPorts.
  if printf '%s' "$rejected" | grep -qwE 'brew|apt|apt-get|yum|dnf|pacman|macports|choco|nix|install'; then
    bad "rejection recommends installing something: [$rejected]"
  else
    ok "rejection recommends no package manager"
  fi

  expect_lacks "rejects an openssl whose -help says nothing" \
    "$(run_ensure_openssl "$subject" "$mute:$TOOLBOX")" ACCEPTED

  # No openssl at all keeps the original message: the binary is what is
  # missing, not a capability of one.
  local absent
  absent="$(run_ensure_openssl "$subject" "$TOOLBOX")"
  expect_lacks "rejects a PATH with no openssl" "$absent" ACCEPTED
  expect_contains "absent openssl reports the binary, not the option" \
    "$absent" "openssl is required"
}

# ---------------------------------------------------------------------------
# The fingerprint read
# ---------------------------------------------------------------------------

HEX_A='90:1F:CA:37:5A:0B:CE:11:2D:88:4F:6E:23:91:70:AC'
HEX_B='4C:7D:E9:02:B8:61:34:AA:5F:10:9D:73:C6:28:E4:51'

check_fingerprint_read() {
  local script="$1"
  printf '[%s] %s: cert-meta fingerprint read\n' "$LABEL" "$script"
  local meta="$TMP_DIR/cert-meta-$script"
  mkdir -p "$meta"

  # `x509 -fingerprint -sha256` under OpenSSL and under LibreSSL. Every
  # other line of the snapshot is byte-identical; only the digest name's
  # case differs.
  printf 'serial=0A\nnotBefore=x\nnotAfter=y\nsha256 Fingerprint=%s\n' "$HEX_A" >"$meta/svc-openssl.txt"
  printf 'serial=0A\nnotBefore=x\nnotAfter=y\nSHA256 Fingerprint=%s\n' "$HEX_A" >"$meta/svc-libressl.txt"
  printf 'serial=0B\nnotBefore=x\nnotAfter=y\nsha256 Fingerprint=%s\n' "$HEX_B" >"$meta/svc-rotated.txt"
  printf 'serial=0A\nnotBefore=x\nnotAfter=y\n' >"$meta/svc-nofingerprint.txt"
  # Matching the whole field rather than a prefix is what keeps another
  # digest from satisfying the read.
  printf 'sha512 Fingerprint=DE:AD:BE:EF\n' >"$meta/svc-otherdigest.txt"

  local subject
  subject="$(build_subject "$script" "$meta" \
    cert_meta_file fingerprint_of assert_cert_meta_readable assert_fingerprint_changed)"

  expect_eq "reads OpenSSL's spelling" \
    "$(call_subject "$subject" 'fingerprint_of svc openssl')" "$HEX_A"
  expect_eq "reads LibreSSL's spelling" \
    "$(call_subject "$subject" 'fingerprint_of svc libressl')" "$HEX_A"
  expect_eq "ignores a different digest" \
    "$(call_subject "$subject" 'fingerprint_of svc otherdigest')" ""

  expect_contains "an absent snapshot names the path" \
    "$(call_subject "$subject" 'assert_cert_meta_readable svc missing')" \
    "$meta/svc-missing.txt"

  local unparsable
  unparsable="$(call_subject "$subject" 'assert_cert_meta_readable svc nofingerprint')"
  expect_contains "an unparsable snapshot reads differently from an absent one" \
    "$unparsable" "No SHA-256 fingerprint parsed"
  expect_lacks "an unparsable snapshot is not reported as missing" \
    "$unparsable" "Missing cert-meta file"
  expect_contains "an unparsable snapshot quotes what it holds" \
    "$unparsable" 'serial=0A notBefore=x notAfter=y'

  expect_contains "a readable snapshot passes" \
    "$(call_subject "$subject" 'assert_cert_meta_readable svc openssl && printf READABLE\\n')" \
    READABLE

  # The comparison has to survive the two snapshots being written by
  # different spellings, which is what happens across an upgrade of the
  # host's openssl mid-matrix.
  expect_contains "an unchanged fingerprint still fails the assertion" \
    "$(call_subject "$subject" 'assert_fingerprint_changed svc openssl libressl')" \
    "Fingerprint did not change"
  expect_contains "a real rotation passes across spellings" \
    "$(call_subject "$subject" 'assert_fingerprint_changed svc libressl rotated && printf CHANGED\\n')" \
    CHANGED

  expect_contains "the comparison surfaces an absent snapshot" \
    "$(call_subject "$subject" 'assert_fingerprint_changed svc openssl missing')" \
    "Missing cert-meta file"
  expect_contains "the comparison surfaces an unparsable snapshot" \
    "$(call_subject "$subject" 'assert_fingerprint_changed svc openssl nofingerprint')" \
    "No SHA-256 fingerprint parsed"
}

# ---------------------------------------------------------------------------
# Structural assertions
# ---------------------------------------------------------------------------

check_gating_is_not_narrowed() {
  printf '[%s] every script that checks for openssl checks for the option\n' "$LABEL"

  local discovered
  discovered="$(cd "$IMPL_DIR" && { grep -lE '^ensure_openssl\(\) \{' ./*.sh || true; } | sed 's|^\./||' | sort | tr '\n' ' ')"
  local expected
  expected="$(printf '%s\n' "${GATED_SCRIPTS[@]}" | sort | tr '\n' ' ')"
  expect_eq "the gated set is exactly the six scripts that check for openssl" \
    "$discovered" "$expected"

  local script
  for script in "${GATED_SCRIPTS[@]}"; do
    if grep -qE '^[[:space:]]*ensure_openssl$' "$IMPL_DIR/$script"; then
      ok "$script calls ensure_openssl from its prerequisite block"
    else
      bad "$script defines ensure_openssl but never calls it"
    fi
  done

  # The check this replaced passed on a LibreSSL host and let the run
  # proceed to die minutes later. Nothing under scripts/impl should be
  # spelling it that way again.
  local stragglers
  stragglers="$(grep -rlF 'command -v openssl >/dev/null' "$IMPL_DIR" || true)"
  if [ -n "$stragglers" ]; then
    bad "these still check only that some openssl exists: $(printf '%s' "$stragglers" | tr '\n' ' ')"
  else
    ok "no script is left checking only that some openssl exists"
  fi
}

# ---------------------------------------------------------------------------

for script in "${GATED_SCRIPTS[@]}"; do
  check_prerequisite_probe "$script"
done

for script in "${FINGERPRINT_SCRIPTS[@]}"; do
  check_fingerprint_read "$script"
done

check_gating_is_not_narrowed

if [ "$failures" -ne 0 ]; then
  printf '[%s] %d check(s) failed\n' "$LABEL" "$failures" >&2
  exit 1
fi

printf '[%s] all checks passed\n' "$LABEL"
