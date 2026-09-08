<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# Registrar provisioning surface (`bootroot registrar`)

This file is the contract between bootroot and the provisioning tool that
installs a registrar. bootroot **owns** this surface: the argv, the JSON bodies,
the exit codes and the identity rule below are decided here, and a consumer
adopts them. It is checked in outside the mirrored `docs/en/` + `docs/ko/`
operator pair, on the precedent of `docs/rfcs/` and
`docs/reference/registrar-client-identity.md`: it is a cross-repository contract
rather than operator documentation, so `mkdocs.yml` lists it in neither locale's
nav and there is no `docs/ko/` counterpart. The operator-facing description of
the same two verbs lives in `docs/en/cli.md`.

This is the **provisioning** surface, not the endpoint. The restricted
`registrar.mint` and `registrar.deregister` verbs are served over the
mutually-authenticated host-local socket described in
`docs/reference/registrar-wire-contract.md` and are reachable only there. What
this surface adds is the step in front of them: reporting that they exist, and
issuing the one credential that can reach them.

## 1. The wire identifier

Every response on this surface carries `api_version` with the exact value:

```text
bootroot.registrar.v1
```

It is a wire token: never translated, never matched as a prefix.

## 2. `bootroot registrar capabilities --json`

Read-only, with no side effects, and independent of the runtime — it answers
whether or not `[registrar_endpoint] enabled` is set on this host and whether or
not `bootroot-agent` is running. It describes the surface, not what is
listening.

| field | type | value |
| --- | --- | --- |
| `api_version` | string | `bootroot.registrar.v1`, exactly |
| `socket_path` | string | the pathname the host-local endpoint is served on |
| `verbs` | array of string | the wire names this surface carries, in the fixed order below |

The verb order is part of the contract, not an implementation detail: a caller
reporting what a bootroot is missing names them in this order, so two runs
against the same bootroot never word the same gap differently.

| position | wire name | served by |
| --- | --- | --- |
| 1 | `registrar.issue` | this CLI, `bootroot registrar issue` |
| 2 | `registrar.mint` | the host-local endpoint |
| 3 | `registrar.deregister` | the host-local endpoint |

A caller ignores names it does not know, so bootroot may grow the surface
without breaking one.

### 2.1 Where `socket_path` comes from

From the **installed socket unit**, and from nothing else. No configuration key
names the endpoint's path — the daemon learns its own from the descriptor
systemd hands it (`src/registrar/endpoint/activation.rs`) — and `capabilities`
must answer while no daemon is running, so neither configuration nor a live
socket can be the source.

`bootroot-registrar.socket` is looked for in systemd's own unit-directory
precedence order, so an operator-installed unit under `/etc` outranks a packaged
one under `/usr`:

```text
/etc/systemd/system
/run/systemd/system
/usr/local/lib/systemd/system
/lib/systemd/system
/usr/lib/systemd/system
```

The first unit found carrying a `[Socket] ListenStream=` answers. With none
installed anywhere, the answer is the `ListenStream=` of the unit this build
ships (`systemd/bootroot-registrar.socket`, embedded at compile time), which is
`/run/bootroot/registrar.sock`. `--socket-unit <path>` names a unit directly and
is authoritative: a file that cannot be read, or one carrying no
`ListenStream=`, is a refusal rather than a fall-through.

**A caller reports what bootroot answers rather than comparing it against a
value derived from its own layout.** The answer is what is true of this host.

## 3. `bootroot registrar issue --json`

```text
bootroot registrar issue \
  --host <label> --domain <domain> \
  --cert-path <path> --key-path <path> \
  [--secrets-dir <path>] --json
```

Issues the registrar client leaf and publishes three files at the modes
`bootroot service add --cert-path/--key-path` establishes:

| file | mode |
| --- | --- |
| `--cert-path` — the leaf followed by its issuer chain | `0644` |
| `--key-path` | `0600` |
| `ca-bundle.pem`, the certificate path's sibling | `0644` |

| field | type | value |
| --- | --- | --- |
| `api_version` | string | `bootroot.registrar.v1`, exactly |
| `identity` | string | the composed name the leaf carries |
| `not_after` | string | the leaf's expiry, as an RFC 3339 instant |

### 3.1 The identity is composed by bootroot

**The verb takes the identity's parts and composes the name itself.** There is
no flag on this surface that accepts a composed name, and passing one through
`--host` is refused by the single-DNS-label rule before anything is issued.

The composed name is
`<instance>.bootroot-registrar.<host>.<domain>`, at the fixed instance label
`001` (`bootroot::registrar::REGISTRAR_SURFACE_INSTANCE`) and under
`bootroot::registrar::REGISTRAR_CLIENT_LABEL` — exactly the name
`recognize_registrar_client` accepts, per
`docs/reference/registrar-client-identity.md` §3. A caller-supplied name is a
name that can disagree with what the verifier recognizes, and there is then no
single place that decides what the identity is; the response reports the
composed name so the caller **learns** the identity rather than asserting it.

`--domain` is a *suffix* of whatever label count it carries, never a single
label.

### 3.2 What it does not do

- It issues the **initial** credential only. Renewal is the daemon's, under its
  own bootroot-internal credential; this verb installs no timer, no unit, no
  AppRole and no agent profile.
- It is not a way into `registrar.mint` or `registrar.deregister`. Those ship,
  are served over the socket, and are untouched by this surface.

### 3.3 Atomicity

The material is issued into a staging directory below `--secrets-dir` and
published only once every byte of it is in hand, so a run that fails part-way
leaves no half-written pair at the caller's paths. Re-invocation re-issues into
the same paths, with a fresh key every time.

## 4. Exit codes

| code | meaning |
| --- | --- |
| `0` | the verb succeeded; the JSON body is on stdout |
| `1` | the verb ran and refused; the reason is on stderr |
| `2` | clap's usage error — an unknown verb, an unknown flag, or a missing required flag |

`2` alone cannot tell "bootroot has not shipped the surface" from "it shipped
one that disagrees": clap prints its `unrecognized subcommand` diagnostic and
quotes the name it did not recognize, and the quoted name is what separates the
two.
