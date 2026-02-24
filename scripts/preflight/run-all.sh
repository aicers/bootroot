#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Preflight: CI-equivalent checks ==="

echo "--- ci/check.sh ---"
"$SCRIPT_DIR/ci/check.sh"

echo "--- ci/test-core.sh ---"
"$SCRIPT_DIR/ci/test-core.sh"

echo "--- ci/e2e-matrix.sh ---"
"$SCRIPT_DIR/ci/e2e-matrix.sh" "$@"

echo "--- ci/e2e-extended.sh ---"
"$SCRIPT_DIR/ci/e2e-extended.sh"

echo "=== Preflight: Extra local-only checks ==="

echo "--- extra/agent-scenarios.sh ---"
"$SCRIPT_DIR/extra/agent-scenarios.sh" happy

echo "--- extra/cli-scenarios.sh ---"
"$SCRIPT_DIR/extra/cli-scenarios.sh"

echo "=== All preflight checks passed ==="
