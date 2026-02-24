#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

echo "[check] Rust formatting"
cargo fmt -- --check --config group_imports=StdExternalCrate

echo "[check] Rust lints (Clippy)"
cargo clippy --all-targets -- -D warnings

echo "[check] Python formatting"
ruff format --check .

echo "[check] Python lints"
ruff check .

echo "[check] Biome (config/JSON)"
biome ci --error-on-warnings .

echo "[check] Markdown lint"
markdownlint-cli2 "**/*.md" "#node_modules" "#target"

echo "[check] Build docs"
mkdocs build --strict

echo "[check] Security audit"
cargo audit

echo "[check] done"
