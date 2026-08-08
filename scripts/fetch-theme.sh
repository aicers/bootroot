#!/usr/bin/env bash
# Install docs-theme assets into a consuming project's docs/theme/.
#
# Usage:
#   ./scripts/fetch-theme.sh [--source <dir>]
#
# The repository, template, and version are read from docs/theme.toml,
# which the consuming project commits:
#
#   [theme]
#   repo = "aicers/docs-theme"
#   template = "manual"
#   version = "<version>"
#
# With --source the assets are copied from a local docs-theme checkout
# instead of being downloaded, and docs/theme/.meta records
# source = "local" so a local install is never mistaken for a released
# one.
#
# The installed tree is described by docs/theme/.meta.  A run whose
# .meta agrees with docs/theme.toml and whose recorded digest still
# matches the installed files exits without downloading anything.
#
# Requirements: python3, tar, and gh (GitHub CLI) unless --source is used.
set -euo pipefail

CONFIG="docs/theme.toml"
DEST="docs/theme"
SOURCE_DIR=""

usage() {
  cat >&2 <<'EOF'
Usage: fetch-theme.sh [--source <dir>]

  --source <dir>  Install from a local docs-theme checkout instead of
                  downloading the release named in docs/theme.toml.

The repository, template, and version are read from docs/theme.toml.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      [[ $# -ge 2 ]] || usage
      SOURCE_DIR="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

python_bin="python3"
if [[ -x ".venv/bin/python" ]]; then
  python_bin=".venv/bin/python"
fi

args=(--config "$CONFIG" --dest "$DEST")
if [[ -n "$SOURCE_DIR" ]]; then
  args+=(--source "$SOURCE_DIR")
fi

"$python_bin" - "${args[@]}" <<'PY'
"""Resolve docs/theme.toml, install the theme, and record docs/theme/.meta."""
import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile

META_NAME = ".meta"
META_KEYS = ("repo", "version", "template", "digest", "source")
SAMPLE_CONFIG = (
    '  [theme]\n'
    '  repo = "aicers/docs-theme"\n'
    '  template = "manual"\n'
    '  version = "<version>"'
)


def fail(message):
    print("fetch-theme: " + message, file=sys.stderr)
    sys.exit(1)


def parse_simple_toml(path):
    """Parse the subset of TOML used by theme.toml on pre-3.11 Pythons."""
    data = {}
    table = data
    with open(path, encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                if not line.endswith("]"):
                    fail(f"{path}:{lineno}: malformed table header")
                table = data
                for part in line[1:-1].split("."):
                    table = table.setdefault(part.strip(), {})
                continue
            key, sep, value = line.partition("=")
            value = value.strip()
            if not sep or not key.strip():
                fail(f"{path}:{lineno}: expected 'key = \"value\"'")
            if len(value) < 2 or value[0] != value[-1] or value[0] not in "\"'":
                fail(f"{path}:{lineno}: only quoted string values are "
                     "supported by the built-in parser; install Python 3.11 "
                     "or newer, or the 'tomli' package")
            table[key.strip()] = value[1:-1]
    return data


def load_config(path):
    if not os.path.isfile(path):
        fail(f"{path}: not found. Create it with a [theme] table:\n\n"
             f"{SAMPLE_CONFIG}")
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return parse_simple_toml(path)
    with open(path, "rb") as handle:
        try:
            return tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            fail(f"{path}: invalid TOML: {exc}")


def required(config, path, key):
    theme = config.get("theme")
    if not isinstance(theme, dict):
        fail(f"{path}: missing the [theme] table. Expected:\n\n"
             f"{SAMPLE_CONFIG}")
    value = theme.get(key)
    if value is None:
        fail(f"{path}: missing required key 'theme.{key}'")
    if not isinstance(value, str) or not value.strip():
        fail(f"{path}: 'theme.{key}' must be a non-empty string")
    return value.strip()


def digest_tree(root):
    """Hash the installed tree.

    The digest covers each file's relative path, executable bit, and
    contents, walked in sorted order, so it is reproducible across
    machines and independent of where the project lives.  `.meta` is
    excluded because it carries the digest itself.
    """
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if rel == META_NAME:
                continue
            entries.append((rel, full))

    digest = hashlib.sha256()
    for rel, full in sorted(entries):
        if os.path.islink(full):
            kind = b"l"
            executable = b"0"
            payload = os.readlink(full).encode("utf-8")
        else:
            kind = b"f"
            mode = os.stat(full).st_mode
            executable = b"1" if mode & 0o111 else b"0"
            with open(full, "rb") as handle:
                payload = handle.read()
        digest.update(rel.encode("utf-8") + b"\0")
        digest.update(kind + executable + b"\0")
        digest.update(str(len(payload)).encode("ascii") + b"\0")
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def read_meta(path):
    if not os.path.isfile(path):
        return None
    meta = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            meta[key.strip()] = value
    return meta


def write_meta(path, meta):
    with open(path, "w", encoding="utf-8") as handle:
        for key in META_KEYS:
            handle.write(f'{key} = "{meta[key]}"\n')
    os.chmod(path, 0o644)


def copy_file(src, dst, executable=False):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)
    # Normalize modes so the digest does not depend on the umask or on
    # how the source tree was checked out.
    os.chmod(dst, 0o755 if executable else 0o644)


def copy_tree(src, dst):
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for name in sorted(filenames):
            source = os.path.join(dirpath, name)
            if os.path.islink(source) and not os.path.isfile(source):
                continue
            copy_file(source, os.path.join(dst, os.path.relpath(source, src)))


def install(src, dest, template, label):
    template_dir = os.path.join(src, "templates", template)
    if not os.path.isdir(template_dir):
        fail(f"template '{template}' not found in {label}")

    # Stage the whole tree first, so a failure part-way through never
    # leaves a half-installed docs/theme/ -- nor the staging directory,
    # which sits under docs_dir and would otherwise be published.
    #
    # mkdtemp picks a name that does not exist yet and creates it
    # atomically, beside the destination so the final os.replace stays on
    # one filesystem.  The installer owns only docs/theme/; a fixed
    # staging name would have to be cleared before use, and clearing it
    # would delete whatever the project happened to keep there.
    parent = os.path.dirname(dest) or "."
    staging = tempfile.mkdtemp(prefix=os.path.basename(dest) + ".stage-",
                               dir=parent)
    try:
        stage(src, staging, template, template_dir, label)
        # mkdtemp creates the directory 0o700; the installed tree has to
        # stay readable to whoever builds the site.
        os.chmod(staging, 0o755)
        shutil.rmtree(dest, ignore_errors=True)
        os.replace(staging, dest)
    finally:
        # Only ever the directory this run created.
        shutil.rmtree(staging, ignore_errors=True)


def stage(src, staging, template, template_dir, label):
    template_styles = os.path.join(template_dir, "styles")
    if not os.path.isdir(template_styles):
        fail(f"template '{template}' in {label} has no styles/ directory")
    copy_tree(template_styles, os.path.join(staging, "styles"))

    template_pdf = os.path.join(template_dir, "pdf")
    if os.path.isdir(template_pdf):
        copy_tree(template_pdf, os.path.join(staging, "pdf"))

    base_config = os.path.join(template_dir, "mkdocs-base.yml")
    if not os.path.isfile(base_config):
        fail(f"template '{template}' in {label} has no mkdocs-base.yml")
    copy_file(base_config, os.path.join(staging, "mkdocs-base.yml"))

    shared_base_css = os.path.join(src, "shared", "styles", "base.css")
    installed_base_css = os.path.join(staging, "styles", "base.css")
    if os.path.exists(installed_base_css):
        fail(f"template '{template}' ships styles/base.css, which would be "
             "overwritten by shared/styles/base.css; rename one of them")
    if not os.path.isfile(shared_base_css):
        fail(f"shared/styles/base.css not found in {label}")
    copy_file(shared_base_css, installed_base_css)

    shared_fonts = os.path.join(src, "shared", "fonts")
    if not os.path.isdir(shared_fonts):
        fail(f"shared/fonts/ not found in {label}")
    copy_tree(shared_fonts, os.path.join(staging, "fonts"))

    # brand.svg carries white lettering for the site header, which sits on
    # the primary-coloured bar; brand-print.svg is the black-lettering
    # variant the PDF cover needs on white paper; brand-symbol.svg is the
    # cube alone, which is the only one of the three that stays legible at
    # favicon size.
    for name in ("brand.svg", "brand-print.svg", "brand-symbol.svg"):
        asset = os.path.join(src, "shared", name)
        if not os.path.isfile(asset):
            fail(f"shared/{name} not found in {label}")
        copy_file(asset, os.path.join(staging, name))

    pdf_script = os.path.join(src, "scripts", "build-docs-pdf.sh")
    if not os.path.isfile(pdf_script):
        fail(f"scripts/build-docs-pdf.sh not found in {label}")
    copy_file(pdf_script, os.path.join(staging, "build-docs-pdf.sh"),
              executable=True)


def download(repo, version, workdir):
    try:
        subprocess.run(
            ["gh", "release", "download", version, "--repo", repo,
             "--archive", "tar.gz", "--dir", workdir],
            check=True,
        )
    except FileNotFoundError:
        fail("gh (GitHub CLI) is required to download a release; install it "
             "or use --source <dir>")
    except subprocess.CalledProcessError:
        fail(f"could not download release {version} from {repo}")

    archives = sorted(
        name for name in os.listdir(workdir) if name.endswith(".tar.gz")
    )
    if len(archives) != 1:
        fail(f"expected exactly one .tar.gz in the download of {repo} "
             f"{version}, found {len(archives)}")
    try:
        subprocess.run(
            ["tar", "-xzf", os.path.join(workdir, archives[0]), "-C", workdir],
            check=True,
        )
    except subprocess.CalledProcessError:
        fail(f"could not extract {archives[0]}")

    # The top-level directory is whatever the archive happens to carry;
    # forks and renamed repositories do not produce "docs-theme-*".
    tops = sorted(
        name for name in os.listdir(workdir)
        if os.path.isdir(os.path.join(workdir, name))
    )
    if len(tops) != 1:
        fail("could not determine the top-level directory of the release "
             f"archive; found {len(tops)} candidates")
    return os.path.join(workdir, tops[0])


def main():
    parser = argparse.ArgumentParser(prog="fetch-theme.sh")
    parser.add_argument("--config", required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--source")
    args = parser.parse_args()

    config = load_config(args.config)
    repo = required(config, args.config, "repo")
    template = required(config, args.config, "template")
    version = required(config, args.config, "version")

    # A template is a directory name under templates/, not a path.
    if "/" in template or template in (".", ".."):
        fail(f"{args.config}: 'theme.template' must be a template name such "
             f"as 'manual', not a path (got '{template}')")

    source_kind = "local" if args.source else "release"
    dest = args.dest
    meta_path = os.path.join(dest, META_NAME)

    meta = read_meta(meta_path)
    if (meta
            and meta.get("repo") == repo
            and meta.get("version") == version
            and meta.get("template") == template
            and meta.get("source") == source_kind
            and meta.get("digest") == digest_tree(dest)):
        print(f"docs-theme {version} ({template}) is already installed in "
              f"{dest}; skipping")
        return

    parent = os.path.dirname(dest) or "."
    if not os.path.isdir(parent):
        fail(f"{parent}/ does not exist; run this from the project root")

    if args.source:
        src = os.path.abspath(args.source)
        if not os.path.isdir(src):
            fail(f"--source: {args.source} is not a directory")
        print(f"Installing docs-theme from {src} (template: {template})...")
        install(src, dest, template, args.source)
    else:
        workdir = tempfile.mkdtemp(prefix="docs-theme-")
        try:
            print(f"Fetching docs-theme {version} from {repo} "
                  f"(template: {template})...")
            src = download(repo, version, workdir)
            install(src, dest, template, f"release {version} of {repo}")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # Check before writing .meta: a .meta recorded over a broken install
    # would match on the next run and keep the broken install in place.
    script = os.path.join(dest, "build-docs-pdf.sh")
    if not os.stat(script).st_mode & stat.S_IXUSR:
        fail(f"{script} is not executable after install")

    write_meta(meta_path, {
        "repo": repo,
        "version": version,
        "template": template,
        "digest": digest_tree(dest),
        "source": source_kind,
    })

    print(f"Installed docs-theme {version} ({template}, {source_kind}) "
          f"into {dest}")


main()
PY
