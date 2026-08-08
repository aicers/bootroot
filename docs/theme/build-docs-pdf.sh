#!/usr/bin/env bash
# Build a PDF from an MkDocs project that uses the docs-theme PDF template.
#
# Usage:
#   ./docs/theme/build-docs-pdf.sh <en|ko> [config]
#
# `config` defaults to mkdocs.yml, so a project with a single config
# passes only the locale.  Theme assets are read from docs/theme/, where
# fetch-theme.sh installs both these assets and this script.
#
# Cover text and the output filename come from the `extra.pdf` block of
# the config:
#
#   extra:
#     pdf:
#       cover_title: {en: <title>, ko: <title>}
#       cover_subtitle: {en: <subtitle>, ko: <subtitle>}
#       cover_tagline: {en: <tagline>, ko: <tagline>}
#       toc_title: {en: <heading>, ko: <heading>}
#       author: <line under the cover rule>
#       copyright: <copyright line>
#       output_basename: <basename>
#
# Every text value is either a plain string used for every locale or a
# mapping of locale to string.  `output_basename` is always a plain
# string; the locale is appended, giving
# site/pdf/<basename>.<locale>.pdf.  Unset keys fall back to site_name
# (cover_title), the plugin default (toc_title), the top-level copyright
# key, the build date formatted for the locale (author), or are omitted
# from the cover.
#
# Environment:
#   DOCS_PDF_DEBUG=1  keep the generated config and .pdf-tmp/ for
#                     inspection instead of deleting them, and report
#                     the path of the generated config on stderr.
#
# Font paths in the SCSS are rewritten to absolute file:// URIs so
# WeasyPrint can resolve them.
set -euo pipefail

usage() {
  echo "Usage: $0 <en|ko> [config]" >&2
  exit 1
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
fi

locale="$1"
config="${2:-mkdocs.yml}"

case "$locale" in
  en|ko) ;;
  *)
    echo "Unsupported locale: $locale" >&2
    usage
    ;;
esac

if [[ ! -f "$config" ]]; then
  echo "Config not found: $config" >&2
  exit 1
fi

python_bin="python3"
mkdocs_bin="mkdocs"

if [[ -x ".venv/bin/python" ]]; then
  python_bin=".venv/bin/python"
fi

if [[ -x ".venv/bin/mkdocs" ]]; then
  mkdocs_bin=".venv/bin/mkdocs"
fi

# The generated config lives beside the caller's config, because MkDocs
# resolves docs_dir and site_dir relative to the config file.  The name
# is unique and created with noclobber, so a run never writes over a
# file the caller already has there -- including the input config
# itself -- and the exit trap only ever removes a file this run made.
config_dir="$(dirname "$config")"
tmp_config=""
attempt=0

while ((attempt < 100)); do
  candidate="$config_dir/mkdocs.tmp.$$.$attempt.yml"
  if (set -o noclobber; : > "$candidate") 2>/dev/null; then
    tmp_config="$candidate"
    break
  fi
  attempt=$((attempt + 1))
done

if [[ -z "$tmp_config" ]]; then
  echo "Could not create a temporary config in $config_dir" >&2
  exit 1
fi

trap 'if [[ "${DOCS_PDF_DEBUG:-0}" != "1" ]]; then rm -f "$tmp_config"; rm -rf .pdf-tmp; fi' EXIT

DOCS_LOCALE="$locale" DOCS_CONFIG="$config" DOCS_TMP_CONFIG="$tmp_config" \
  "$python_bin" - <<'PY'
import os
import shutil
import sys
from datetime import datetime

import yaml

locale = os.environ["DOCS_LOCALE"]
config_path = os.environ["DOCS_CONFIG"]
tmp_config_path = os.environ["DOCS_TMP_CONFIG"]


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


class UnknownTag:
    """A YAML node carrying a tag this script does not interpret.

    MkDocs configs use tags such as
    `!!python/object/apply:pymdownx.slugs.slugify` that a safe loader
    cannot construct.  Keeping the tag and its raw value lets the node
    round-trip into the generated config unchanged.
    """

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value


class Loader(yaml.SafeLoader):
    pass


class Dumper(yaml.SafeDumper):
    pass


def construct_unknown(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return UnknownTag(node.tag, value)


def represent_unknown(dumper, data):
    if isinstance(data.value, dict):
        return dumper.represent_mapping(data.tag, data.value)
    if isinstance(data.value, list):
        return dumper.represent_sequence(data.tag, data.value)
    return dumper.represent_scalar(data.tag, data.value)


Loader.add_multi_constructor("", construct_unknown)
Dumper.add_representer(UnknownTag, represent_unknown)

with open(config_path, "r", encoding="utf-8") as f:
    data = yaml.load(f, Loader=Loader)

if not isinstance(data, dict):
    fail(f"{config_path}: expected a mapping at the top level")

root = os.getcwd()

theme_dir = os.path.join(root, "docs", "theme")
if not os.path.isdir(theme_dir):
    fail("docs/theme/ not found. Install the theme first:\n"
         "  ./scripts/fetch-theme.sh")

# Which docs-theme rendered this file.  A PDF is handed to a reader and
# leaves the repository that produced it, so unless the artifact says so
# there is nothing to reproduce a rendering complaint against -- and once
# several projects bump the theme on their own schedules, the answer
# stops being inferable.  .meta is the record of what is installed; the
# requested value in docs/theme.toml would misreport a drifted tree.
meta_path = os.path.join(theme_dir, ".meta")
if not os.path.isfile(meta_path):
    fail(f"{meta_path} not found. The installed theme is incomplete; "
         "re-run ./scripts/fetch-theme.sh.")

installed = {}
with open(meta_path, "r", encoding="utf-8") as f:
    for line in f:
        key, sep, value = line.partition("=")
        if sep:
            installed[key.strip()] = value.strip().strip('"')

theme_version = installed.get("version")
theme_source = installed.get("source")
if not theme_version or not theme_source:
    fail(f"{meta_path} records no version or source; re-run "
         "./scripts/fetch-theme.sh.")

# A --source install takes its version from docs/theme.toml without ever
# resolving a release, so printing that number would assert something
# untrue.  Name the build instead.
if theme_source == "release":
    theme_provenance = f"docs-theme {theme_version}"
else:
    theme_provenance = ("docs-theme (local build)" if locale == "en"
                        else "docs-theme (로컬 빌드)")

theme_pdf = os.path.join(theme_dir, "pdf")
if not os.path.isdir(theme_pdf):
    fail("docs/theme/pdf/ not found. The installed template ships no PDF "
         "assets; check 'template' in docs/theme.toml.")

tmp_pdf_dir = os.path.join(root, ".pdf-tmp")
if os.path.exists(tmp_pdf_dir):
    shutil.rmtree(tmp_pdf_dir)
shutil.copytree(theme_pdf, tmp_pdf_dir)

# Copy the shared fonts next to the SCSS so relative paths resolve.
theme_fonts = os.path.join(theme_dir, "fonts")
if os.path.isdir(theme_fonts):
    fonts_dest = os.path.join(tmp_pdf_dir, "fonts")
    os.makedirs(fonts_dest, exist_ok=True)
    for name in os.listdir(theme_fonts):
        src = os.path.join(theme_fonts, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(fonts_dest, name))

styles_path = os.path.join(tmp_pdf_dir, "styles.scss")
if not os.path.isfile(styles_path):
    fail("docs/theme/pdf/styles.scss not found. The installed template is "
         "incomplete; re-run ./scripts/fetch-theme.sh.")

fonts_base = f'file://{os.path.join(tmp_pdf_dir, "fonts")}/'

with open(styles_path, "r", encoding="utf-8") as f:
    styles = f.read()

for prefix in ('../fonts/', 'pdf/fonts/', '/pdf/fonts/', 'fonts/'):
    styles = styles.replace(f'url("{prefix}', f'url("{fonts_base}')

with open(styles_path, "w", encoding="utf-8") as f:
    f.write(styles)

extra = data.get("extra")
if extra is None:
    extra = {}
if not isinstance(extra, dict):
    fail(f"{config_path}: 'extra' must be a mapping")

if "pdf_copyright" in extra:
    fail(f"{config_path}: 'extra.pdf_copyright' is no longer supported; "
         "move the value to 'extra.pdf.copyright'")

pdf_conf = extra.get("pdf")
if pdf_conf is None:
    pdf_conf = {}
if not isinstance(pdf_conf, dict):
    fail(f"{config_path}: 'extra.pdf' must be a mapping")


def text(key):
    """Resolve a plain string or a locale mapping under extra.pdf."""
    value = pdf_conf.get(key)
    if isinstance(value, dict):
        value = value.get(locale)
    if value is None:
        return None
    return str(value)


site_name = data.get("site_name") or "Document"

cover_title = text("cover_title") or site_name
cover_subtitle = text("cover_subtitle")
cover_tagline = text("cover_tagline")
toc_title = text("toc_title")

copyright_text = text("copyright")
if copyright_text is None:
    copyright_text = str(data.get("copyright") or "")

author = text("author")
if author is None:
    now = datetime.now()
    author = (now.strftime('%B %-d, %Y') if locale == "en"
              else now.strftime('%Y년 %-m월 %-d일'))

basename = pdf_conf.get("output_basename")
if isinstance(basename, dict):
    fail(f"{config_path}: 'extra.pdf.output_basename' must be a plain "
         "string; the locale is appended to the filename")
if basename is None or not str(basename).strip():
    basename = site_name.lower().replace(" ", "-")
else:
    basename = str(basename).strip()

data["strict"] = False
data["site_dir"] = f"site-pdf-{locale}"

theme = data.get("theme")
if isinstance(theme, dict):
    theme["font"] = False

# MkDocs accepts `plugins` either as a list of names and single-key
# mappings or as one mapping of name to options.  Whichever form the
# consumer wrote is kept, so their own plugins survive into the
# generated config.
plugins = data.get("plugins")

# Pin the i18n plugin, if there is one, to the locale being built.
i18n = None
if isinstance(plugins, dict):
    i18n = plugins.get("i18n")
elif isinstance(plugins, list):
    for entry in plugins:
        if isinstance(entry, dict) and "i18n" in entry:
            i18n = entry["i18n"]
            break
if isinstance(i18n, dict):
    i18n["build_only_locale"] = locale

options = {
    "enabled_if_env": "DOCS_PDF_EXPORT",
    "output_path": os.path.join(root, "site", "pdf",
                                f"{basename}.{locale}.pdf"),
    "custom_template_path": tmp_pdf_dir,
    "author": author,
    "copyright": copyright_text,
    "cover_title": cover_title,
}

if cover_subtitle is not None:
    options["cover_subtitle"] = cover_subtitle
if toc_title is not None:
    options["toc_title"] = toc_title

# The cover sits on white paper, so it needs the black-lettering variant.
# theme/brand.svg is the white-lettering one the site header uses; putting
# that on the cover renders an invisible logo and nothing downstream would
# report it.  A consumer documenting a product with its own mark points
# extra.pdf.cover_logo at it, relative to docs_dir.
cover_logo = text("cover_logo")
if cover_logo is not None:
    docs_dir = str(data.get("docs_dir") or "docs")
    cover_logo = os.path.join(root, docs_dir, cover_logo)
    if not os.path.isfile(cover_logo):
        fail(f"{config_path}: 'extra.pdf.cover_logo' does not exist at "
             f"{cover_logo}")
else:
    cover_logo = os.path.join(theme_dir, "brand-print.svg")
    if not os.path.isfile(cover_logo):
        fail(f"{cover_logo} is missing; the installed theme is incomplete. "
             "Re-run ./scripts/fetch-theme.sh.")
options["cover_logo"] = cover_logo

# cover_tagline is not a mkdocs-with-pdf option.  The plugin seeds the
# cover template context from `extra` and never overwrites this name, so
# this is how the value reaches {{ cover_tagline }} in pdf/cover.html.j2
# -- and why an unresolved tagline has to be removed from `extra` rather
# than merely left unset: a top-level `extra.cover_tagline` the consumer
# still carries would otherwise render, in whatever locale it was
# written in, against a contract that says the cover has no tagline.
if cover_tagline is not None:
    extra["cover_tagline"] = cover_tagline
    data["extra"] = extra
elif "cover_tagline" in extra:
    del extra["cover_tagline"]
    data["extra"] = extra

# theme_provenance reaches {{ theme_provenance }} in pdf/cover.html.j2 the
# same way, through `extra`.  It is derived from the installed theme, not
# configured, so a consumer value is overwritten rather than honoured.
extra["theme_provenance"] = theme_provenance
data["extra"] = extra

if isinstance(plugins, dict):
    plugins["with-pdf"] = options
elif isinstance(plugins, list):
    plugins.append({"with-pdf": options})
else:
    plugins = [{"with-pdf": options}]
data["plugins"] = plugins

with open(tmp_config_path, "w", encoding="utf-8") as f:
    yaml.dump(data, f, Dumper=Dumper, sort_keys=False, allow_unicode=True)
PY

if [[ "${DOCS_PDF_DEBUG:-0}" == "1" ]]; then
  echo "Generated config: $tmp_config" >&2
fi

DOCS_PDF_EXPORT=1 "$mkdocs_bin" build -f "$tmp_config"
