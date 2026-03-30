#!/usr/bin/env bash
# Fetch a docs-theme release and install it into docs/.theme/.
# Reads docs/theme.toml for repo, template, and version.
# Skips the download when the installed metadata already matches.
#
# Requirements: gh (GitHub CLI), tar
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIG="$ROOT_DIR/docs/theme.toml"
DEST="$ROOT_DIR/docs/.theme"

if [[ ! -f "$CONFIG" ]]; then
  echo "Error: $CONFIG not found" >&2
  exit 1
fi

read_toml() {
  grep "^${1} " "$CONFIG" | sed 's/.*= *"\(.*\)"/\1/'
}

REPO="$(read_toml repo)"
TEMPLATE="$(read_toml template)"
VERSION="$(read_toml version)"

if [[ -z "$REPO" || -z "$TEMPLATE" || -z "$VERSION" ]]; then
  echo "Error: docs/theme.toml must define repo, template, and version" >&2
  exit 1
fi

# Skip if installed metadata already matches.
META="$DEST/.meta"
if [[ -f "$META" ]]; then
  installed_repo="$(grep "^repo " "$META" | sed 's/.*= *"\(.*\)"/\1/' || true)"
  installed_version="$(grep "^version " "$META" | sed 's/.*= *"\(.*\)"/\1/' || true)"
  installed_template="$(grep "^template " "$META" | sed 's/.*= *"\(.*\)"/\1/' || true)"
  if [[ "$installed_repo" == "$REPO" && "$installed_version" == "$VERSION" && "$installed_template" == "$TEMPLATE" ]]; then
    echo "docs-theme $VERSION ($TEMPLATE) already installed — skipping"
    exit 0
  fi
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "Fetching docs-theme $VERSION (template: $TEMPLATE)..."
gh release download "$VERSION" \
  --repo "$REPO" \
  --archive tar.gz \
  --dir "$WORK_DIR"

ARCHIVE="$(ls "$WORK_DIR"/*.tar.gz)"
tar -xzf "$ARCHIVE" -C "$WORK_DIR"

EXTRACTED="$(ls -d "$WORK_DIR"/docs-theme-*/)"

TEMPLATE_DIR="$EXTRACTED/templates/$TEMPLATE"
if [[ ! -d "$TEMPLATE_DIR" ]]; then
  echo "Error: template '$TEMPLATE' not found in release $VERSION" >&2
  exit 1
fi

SHARED_DIR="$EXTRACTED/shared"

rm -rf "$DEST"
mkdir -p "$DEST"

# Copy template-specific assets.
cp -r "$TEMPLATE_DIR"/styles "$DEST"/
if [[ -d "$TEMPLATE_DIR/pdf" ]]; then
  cp -r "$TEMPLATE_DIR"/pdf "$DEST"/
fi

# Copy shared assets.
if [[ -d "$SHARED_DIR/fonts" ]]; then
  mkdir -p "$DEST/fonts"
  cp -r "$SHARED_DIR"/fonts/* "$DEST"/fonts/
fi

if [[ -f "$SHARED_DIR/brand.svg" ]]; then
  cp "$SHARED_DIR/brand.svg" "$DEST"/
fi

# Write installed metadata so subsequent runs can skip.
cat > "$META" <<EOF
repo = "$REPO"
version = "$VERSION"
template = "$TEMPLATE"
EOF

echo "Installed docs-theme $VERSION ($TEMPLATE) into $DEST"
