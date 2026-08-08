#!/usr/bin/env bash
# Verify the vendored docs theme and build the manual.
#
# docs/theme/ is committed, so nothing is fetched to build the site.
# Running the installer here only verifies: a tree that agrees with
# docs/theme.toml and still matches the digest in docs/theme/.meta makes
# it exit without touching anything, so a hand-edit or a stale vendored
# tree surfaces as a failure instead of a silently divergent site.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "[docs] Verify vendored theme"
# A reinstall is a failure here, so the installer's exit status is not the
# signal — its report is. Keep going on failure and let the check below
# produce the actionable message.
report="$(./scripts/fetch-theme.sh 2>&1)" || true
echo "$report"
case "$report" in
  *"already installed"*) ;;
  *)
    echo "Error: docs/theme/ does not match docs/theme.toml and the digest" \
      "recorded in docs/theme/.meta. Run ./scripts/fetch-theme.sh locally" \
      "and commit the resulting docs/theme/." >&2
    exit 1
    ;;
esac

echo "[docs] Build site"
mkdocs build --strict

# MkDocs drops every dot-prefixed path inside docs_dir from the build, and
# --strict does not validate that extra_css entries resolve, so an unstyled
# site builds green. Assert the stylesheets actually reached site/.
echo "[docs] Verify theme stylesheets reached the site"
shopt -s nullglob
installed=(docs/theme/styles/*.css)
if ((${#installed[@]} == 0)); then
  echo "Error: docs/theme/styles/ contains no stylesheets" >&2
  exit 1
fi

missing=0
for css in "${installed[@]}"; do
  published="site/theme/styles/$(basename "$css")"
  if [[ ! -f "$published" ]]; then
    echo "Error: $css was not published to $published" >&2
    missing=1
  fi
done
((missing == 0)) || exit 1

echo "[docs] done"
