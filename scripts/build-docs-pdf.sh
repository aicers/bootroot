#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <en|ko>" >&2
  exit 1
fi

locale="$1"
python_bin="python3"
mkdocs_bin="mkdocs"

if [[ -x ".venv/bin/python" ]]; then
  python_bin=".venv/bin/python"
fi

if [[ -x ".venv/bin/mkdocs" ]]; then
  mkdocs_bin=".venv/bin/mkdocs"
fi

case "$locale" in
  en|ko) ;;
  *)
    echo "Unsupported locale: $locale" >&2
    exit 1
    ;;
esac

trap 'rm -f mkdocs.tmp.yml' EXIT

BOOTROOT_LOCALE="$locale" "$python_bin" - <<'PY'
import copy
import os
import sys
import yaml

locale = os.environ.get("BOOTROOT_LOCALE")
if not locale:
    print("BOOTROOT_LOCALE is required", file=sys.stderr)
    sys.exit(1)

with open("mkdocs.yml", "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)

data = copy.deepcopy(data)
root = os.getcwd()
data["strict"] = False
data["site_dir"] = f"site-pdf-{locale}"

theme = data.get("theme")
if isinstance(theme, dict):
    # Avoid remote font fetches during PDF rendering.
    theme["font"] = False

for plugin in data.get("plugins", []):
    if isinstance(plugin, dict) and "i18n" in plugin:
        plugin["i18n"]["build_only_locale"] = locale

pdf_plugin = {
    "with-pdf": {
        "enabled_if_env": "BOOTROOT_PDF_EXPORT",
        "output_path": os.path.join(root, "site", "pdf", f"bootroot-manual.{locale}.pdf"),
        "custom_template_path": "docs/pdf",
        "author": "",
        "copyright": "",
    }
}

if locale == "ko":
    pdf_plugin["with-pdf"]["cover_title"] = "Bootroot 매뉴얼"
    pdf_plugin["with-pdf"]["cover_subtitle"] = "사용자 매뉴얼"
    pdf_plugin["with-pdf"]["toc_title"] = "목차"
else:
    pdf_plugin["with-pdf"]["cover_title"] = "Bootroot Manual"
    pdf_plugin["with-pdf"]["cover_subtitle"] = "User Manual"
    pdf_plugin["with-pdf"]["toc_title"] = "Table of Contents"

data.setdefault("plugins", []).append(pdf_plugin)

with open("mkdocs.tmp.yml", "w", encoding="utf-8") as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY

BOOTROOT_PDF_EXPORT=1 "$mkdocs_bin" build -f mkdocs.tmp.yml
