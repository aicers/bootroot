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

# Three things have to hold for the site to be styled, and `mkdocs build
# --strict` checks none of them: the stylesheets must be copied into site/,
# the pages must actually link them, and every other theme asset they and
# the pages reference must resolve.
echo "[docs] Verify the theme reached the site"
python3 - <<'PY'
import glob
import os
import re
import sys
from urllib.parse import unquote, urlparse

SITE = "site"
STYLES = "docs/theme/styles"
HTML_REF = re.compile(r'(?:href|src)="([^"]+)"')
CSS_REF = re.compile(r"url\(\s*['\"]?([^'\")]+)")
# Matches however a page spells the path: relative from a nested page
# ("../theme/styles/base.css") or rooted at site_url as 404.html writes it
# ("/bootroot/theme/styles/base.css").
STYLE_LINK = re.compile(r"theme/styles/([^/\"'?#]+\.css)")

errors = []

installed = sorted(os.path.basename(p) for p in glob.glob(f"{STYLES}/*.css"))
if not installed:
    print(f"Error: {STYLES}/ contains no stylesheets", file=sys.stderr)
    sys.exit(1)

# MkDocs drops every dot-prefixed path inside docs_dir from the build, which
# is how the whole theme went missing while CI stayed green.
for name in installed:
    published = os.path.join(SITE, "theme", "styles", name)
    if not os.path.isfile(published):
        errors.append(f"{STYLES}/{name} was not published to {published}")

unresolved = set()


def check(page, ref):
    ref = unquote(ref.strip())
    parsed = urlparse(ref)
    if parsed.scheme or parsed.netloc or not parsed.path:
        return
    base = "" if ref.startswith("/") else os.path.dirname(page)
    target = os.path.normpath(os.path.join(base, parsed.path.lstrip("/")))
    if ref.startswith("/"):
        # A rooted ref carries the site_url path prefix ("/bootroot/theme/...")
        # that site/ itself does not have, so it never matches the "theme/"
        # test below and would be exempt from this check. 404.html is the one
        # page MkDocs writes this way, and it references the same stylesheets
        # as every other page. Re-anchor at the theme/ segment so it counts.
        head, sep, tail = target.partition("theme/")
        if sep and (not head or head.endswith("/")):
            target = sep + tail
    # Only theme assets are this check's business; MkDocs' own --strict
    # already validates internal page links.
    if not target.startswith("theme/"):
        return
    if not os.path.isfile(os.path.join(SITE, target)):
        unresolved.add((page, ref, target))


# The stylesheets are only the assets the original bug happened to expose.
# The wordmark, the tab icon and the Pretendard/Roboto faces are referenced
# from the built HTML and from the stylesheets' url() rules, and dropping
# any of them 404s just as silently. Resolve every theme/ reference the site
# actually makes rather than restating the expected file list, so this keeps
# holding when docs-theme changes what it ships or what it excludes.
linked = {}

for dirpath, _, filenames in os.walk(SITE):
    for name in filenames:
        path = os.path.join(dirpath, name)
        page = os.path.relpath(path, SITE)
        if name.endswith(".html"):
            pattern = HTML_REF
        elif name.endswith(".css"):
            pattern = CSS_REF
        else:
            continue
        with open(path, encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
        for ref in pattern.findall(text):
            check(page, ref)
        if name.endswith(".html"):
            linked[page] = set(STYLE_LINK.findall(text))

for page, ref, target in sorted(unresolved):
    errors.append(f"{page} references {ref}, but site/{target} does not exist")

# Being published is not the same as being linked, and the difference is
# invisible to both checks above: re-declaring extra_css in mkdocs.yml
# replaces the list the inherited base provides instead of extending it, yet
# the dropped stylesheets are still copied into site/ as ordinary docs_dir
# files. That leaves an unstyled site that resolves every reference it makes
# because it no longer makes them. Require the pages to link the full set.
ADVICE = (
    "check that mkdocs.yml does not re-declare extra_css, which "
    "replaces the inherited list rather than extending it"
)
styled = {page: names for page, names in linked.items() if names}
if not styled:
    errors.append(f"no built page links any {STYLES}/ stylesheet; {ADVICE}")

unlinked = {}
for page, names in styled.items():
    for name in set(installed) - names:
        unlinked.setdefault(name, []).append(page)
for name, pages in sorted(unlinked.items()):
    errors.append(
        f"theme/styles/{name} is published but {len(pages)} built page(s) do "
        f"not link it, e.g. {min(pages)}; {ADVICE}"
    )

for error in errors:
    print(f"Error: {error}", file=sys.stderr)
sys.exit(1 if errors else 0)
PY

echo "[docs] done"
