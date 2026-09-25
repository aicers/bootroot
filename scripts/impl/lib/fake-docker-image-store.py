#!/usr/bin/env python3
"""A fake `docker` holding an image/tag store in JSON, for smoke regressions.

`scripts/validate-deploy-no-build-smoke.sh` puts this on PATH as `docker`
and runs `scripts/preflight/ci/deploy-no-build-smoke.sh` against it. It
models just enough of a containerd image store to make the smoke's image
handling observable without a daemon or a registry:

- a registry (`registry.json`) mapping `repository@digest` to an index
  with one child per platform, and optionally a moving tag;
- a tag store (`tags.json`) mapping names to image IDs;
- `pull` by digest records `repository@digest` -> index, as the
  containerd store does, and never touches a tag;
- `image inspect` without `--platform` answers for the host platform
  (`linux/arm64`), so a smoke that forgot `--platform` would see the
  wrong one;
- `save --platform` exports the platform child, and `load` names it,
  so the loaded tag's ID differs from the pre-save index ID;
- `compose build` writes the responder tag and refreshes the build base
  named by `FAKE_DOCKER_BUILD_BASE`, as a containerd store records it.

Removal by image ID, forced removal and prune are refused outright:
the smoke must never do any of them.

Failure injection, each a regular expression matched against the
space-joined argv:

- `FAKE_DOCKER_FAIL_ON` — exit 1 instead of running the command;
- `FAKE_DOCKER_SIGNAL_ON` — `<regex>=<SIGNAME>`: signal the parent
  (the smoke's shell) and exit 1;
- `FAKE_DOCKER_FOREIGN_ON` — `<regex>=<tag>=<id>`: another writer points
  `<tag>` at `<id>` just before the command runs;
- `FAKE_DOCKER_AFTER_ON` — `<regex>=FAIL` or `<regex>=<SIGNAME>`: run the
  command, keeping every change it made to the store, then exit 1, having
  signalled the smoke first for a signal name — a build that pulled its
  base before failing, or was interrupted after it had.

Every invocation is appended to `argv.log`.
"""

import json
import os
import re
import signal
import subprocess
import sys

STATE = os.environ["FAKE_DOCKER_STATE"]
HOST_PLATFORM = "linux/arm64"
SMOKE_SCRIPT = "preflight/ci/deploy-no-build-smoke.sh"
SERVICE_IMAGE_VARIABLES = {
    "openbao": "OPENBAO_IMAGE",
    "postgres": "POSTGRES_IMAGE",
    "step-ca": "BOOTROOT_STEP_CA_IMAGE",
    "bootroot-http01": "BOOTROOT_HTTP01_IMAGE",
}
COMPOSE_OPTIONS_WITH_VALUE = ("-p", "-f", "--env-file", "--profile", "--project-directory")


def path(name):
    return os.path.join(STATE, name)


def load(name, default):
    try:
        with open(path(name), encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


def store(name, value):
    with open(path(name), "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=1, sort_keys=True)


def die(message, code=1):
    print(message, file=sys.stderr)
    sys.exit(code)


def take_option(args, name):
    """Removes `name <value>` from args, returning the value or None."""
    if name in args:
        index = args.index(name)
        value = args[index + 1]
        del args[index : index + 2]
        return value
    return None


def resolve(ref, tags, images):
    if ref in tags:
        return tags[ref]
    if ref.startswith("sha256:") and ref in images:
        return ref
    return None


def select_platform(image_id, platform, images, ref):
    image = images[image_id]
    children = image.get("children")
    if children:
        child = children.get(platform)
        if child is None:
            die(f"Error response from daemon: {ref} does not provide the platform {platform}")
        return child
    if image["platform"] != platform:
        die(f"Error response from daemon: {ref} is {image['platform']}, not {platform}")
    return image_id


def repo_digests(image_id, tags):
    return sorted({name for name, target in tags.items() if "@" in name and target == image_id})


def inspect_image(args, tags, images):
    platform = take_option(args, "--platform")
    template = take_option(args, "--format")
    ref = args[0]
    image_id = resolve(ref, tags, images)
    if image_id is None:
        die(f"Error response from daemon: No such image: {ref}")
    if platform is not None:
        selected = select_platform(image_id, platform, images, ref)
        shown_id = selected
    elif images[image_id].get("children"):
        # Without --platform, an index answers for the host platform but
        # keeps its own ID, as the containerd store does.
        selected = select_platform(image_id, HOST_PLATFORM, images, ref)
        shown_id = image_id
    else:
        selected = shown_id = image_id
    if template == "{{.Id}}":
        print(shown_id)
        return
    parts = images[selected]["platform"].split("/")
    record = {"Id": shown_id, "Os": parts[0], "Architecture": parts[1]}
    if len(parts) > 2:
        record["Variant"] = parts[2]
    record["RepoDigests"] = repo_digests(image_id, tags)
    print(json.dumps([record]))


def pull(args, tags, images):
    platform = take_option(args, "--platform")
    ref = args[0]
    registry = load("registry.json", {})
    entry = registry.get(ref)
    if entry is None:
        die(f"Error response from daemon: manifest unknown: {ref}")
    for image_id, record in entry["images"].items():
        images[image_id] = record
    if platform is not None:
        select_platform(entry["target"], platform, images, ref)
    tags[ref] = entry["target"]
    print(f"Pulled {ref}")


def remove(args, tags):
    if any(arg in ("-f", "--force") for arg in args):
        die("fake docker: forced removal is forbidden", 3)
    for ref in args:
        if ref.startswith("sha256:"):
            die(f"fake docker: removal by image ID ({ref}) is forbidden", 3)
        if "@" in ref:
            die(f"fake docker: removal of a digest reference ({ref}) is forbidden", 3)
        if ref not in tags:
            die(f"Error response from daemon: No such image: {ref}")
        del tags[ref]
        print(f"Untagged: {ref}")


def save(args, tags, images):
    platform = take_option(args, "--platform")
    out = take_option(args, "-o")
    ref = args[0]
    image_id = resolve(ref, tags, images)
    if image_id is None:
        die(f"Error response from daemon: No such image: {ref}")
    if platform is not None:
        image_id = select_platform(image_id, platform, images, ref)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump({"tag": ref, "id": image_id, "image": images[image_id]}, handle)


def load_archive(args, tags, images):
    archive = take_option(args, "-i")
    with open(archive, encoding="utf-8") as handle:
        content = json.load(handle)
    images[content["id"]] = content["image"]
    tags[content["tag"]] = content["id"]
    print(f"Loaded image: {content['tag']}")


def compose(args, tags, images):
    project = take_option(args, "-p") or "default"
    while args and args[0] in COMPOSE_OPTIONS_WITH_VALUE:
        del args[0:2]
    command, rest = args[0], args[1:]
    containers = load("containers.json", {})
    if command == "down":
        for cid in [cid for cid, c in containers.items() if c["project"] == project]:
            del containers[cid]
    elif command == "build":
        counter = load("counter.json", 0) + 1
        store("counter.json", counter)
        built = f"sha256:{counter:064x}"
        images[built] = {"platform": HOST_PLATFORM}
        tags[os.environ.get("BOOTROOT_HTTP01_IMAGE", "bootroot-http01-responder:latest")] = built
        # A containerd store records refreshed build bases under their tags.
        base = f"sha256:{counter + 1000:064x}"
        images[base] = {"platform": HOST_PLATFORM}
        tags[os.environ["FAKE_DOCKER_BUILD_BASE"]] = base
    elif command == "up":
        services = rest[rest.index("-d") + 1 :]
        for service in services:
            ref = os.environ.get(SERVICE_IMAGE_VARIABLES[service])
            image_id = resolve(ref, tags, images) if ref else None
            if image_id is None:
                die(f"fake compose: {service} image {ref} is not present and pulls are off")
            containers[f"cid-{project}-{service}"] = {
                "project": project,
                "service": service,
                "image": image_id,
            }
    elif command == "ps":
        service = rest[-1]
        for cid, container in containers.items():
            if container["project"] == project and container["service"] == service:
                print(cid)
    else:
        die(f"fake compose: unsupported command {command}")
    store("containers.json", containers)


def container_inspect(args):
    take_option(args, "--format")
    containers = load("containers.json", {})
    container = containers.get(args[0])
    if container is None:
        die(f"Error: No such container: {args[0]}")
    print(container["image"])


def smoke_pid():
    """Returns the smoke's own shell: the outermost of the smoke processes
    directly above this one.

    A command substitution forks a subshell with the same command line,
    and signalling that would not be what `kill <smoke pid>` does. The
    walk stops at the first ancestor that is not the smoke, so nothing
    above the harness can be picked.
    """
    target = None
    pid = os.getppid()
    while pid > 1:
        result = subprocess.run(
            ["ps", "-o", "ppid=,command=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=True,
        )
        ppid, _, command = result.stdout.strip().partition(" ")
        if SMOKE_SCRIPT not in command:
            break
        target = pid
        pid = int(ppid)
    if target is None:
        die("fake docker: no deploy-no-build-smoke.sh ancestor to signal")
    return target


def inject(argv_text, tags, images):
    fail_on = os.environ.get("FAKE_DOCKER_FAIL_ON")
    if fail_on and re.search(fail_on, argv_text):
        die(f"fake docker: injected failure for: {argv_text}")
    signal_on = os.environ.get("FAKE_DOCKER_SIGNAL_ON")
    if signal_on:
        pattern, _, name = signal_on.rpartition("=")
        if re.search(pattern, argv_text):
            os.kill(smoke_pid(), getattr(signal, f"SIG{name}"))
            die(f"fake docker: sent {name} during: {argv_text}")
    foreign_on = os.environ.get("FAKE_DOCKER_FOREIGN_ON")
    if foreign_on:
        pattern, tag, image_id = foreign_on.rsplit("=", 2)
        if re.search(pattern, argv_text):
            images.setdefault(image_id, {"platform": "linux/amd64"})
            tags[tag] = image_id


def inject_after(argv_text):
    after_on = os.environ.get("FAKE_DOCKER_AFTER_ON")
    if not after_on:
        return
    pattern, _, action = after_on.rpartition("=")
    if not re.search(pattern, argv_text):
        return
    if action != "FAIL":
        os.kill(smoke_pid(), getattr(signal, f"SIG{action}"))
        die(f"fake docker: sent {action} after: {argv_text}")
    die(f"fake docker: injected failure after: {argv_text}")


def main(argv):
    argv_text = " ".join(argv)
    with open(path("argv.log"), "a", encoding="utf-8") as handle:
        handle.write(argv_text + "\n")
    tags = load("tags.json", {})
    images = load("images.json", {})
    inject(argv_text, tags, images)
    store("tags.json", tags)
    store("images.json", images)

    args = list(argv)
    if args[:2] == ["image", "inspect"]:
        inspect_image(args[2:], tags, images)
    elif args[:2] == ["container", "inspect"]:
        container_inspect(args[2:])
    elif args[:2] == ["image", "rm"]:
        remove(args[2:], tags)
    elif args[0] == "rmi":
        remove(args[1:], tags)
    elif args[0] == "pull":
        pull(args[1:], tags, images)
    elif args[0] == "tag":
        image_id = resolve(args[1], tags, images)
        if image_id is None:
            die(f"Error response from daemon: No such image: {args[1]}")
        tags[args[2]] = image_id
    elif args[0] == "save":
        save(args[1:], tags, images)
    elif args[0] == "load":
        load_archive(args[1:], tags, images)
    elif args[0] == "compose":
        compose(args[1:], tags, images)
    elif args[0] in ("prune", "system") or args[:2] == ["image", "prune"]:
        die("fake docker: prune is forbidden", 3)
    else:
        die(f"fake docker: unsupported command: {argv_text}")
    store("tags.json", tags)
    store("images.json", images)
    inject_after(argv_text)


if __name__ == "__main__":
    main(sys.argv[1:])
