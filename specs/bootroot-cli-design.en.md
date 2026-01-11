# Bootroot CLI Design Draft

## Purpose

Capture the implementation-oriented design for the `bootroot` CLI. This document
breaks the spec into actionable units and fixes inputs/outputs and flows before
coding.

## Scope

- Per-command input/output flow
- OpenBao API call order
- State storage structure
- i18n message key layout
- Verification and error handling criteria

## Command Design

### `bootroot infra up`

- Inputs
  - Local image archive directory (optional)
  - OpenBao/PostgreSQL/step-ca/responder image tags (defaults provided)
- Process
  - If local images exist, run `docker load` first
  - Otherwise `docker pull`
  - Start containers and set restart policies
- Output
  - Container status summary
  - Next step guidance: `bootroot init`

### `bootroot init`

- Preconditions
  - Infrastructure containers must be running
- Inputs (prompts)
  - OpenBao URL
  - KV mount path (default `secret`)
  - Secret input mode: user-provided vs CLI-generated
- Process
  - OpenBao init/unseal
  - Enable KV v2
  - Create policies and AppRoles
  - Register secrets
  - Initialize step-ca
  - Issue and register EAB
- Output
  - Artifact paths summary
  - AppRole handoff info
  - Verification/next-step guidance

### `bootroot status`

- Inputs: none
- Process
  - Check container status
  - OpenBao health check
- Output
  - OK/FAIL summary with reasons

### `bootroot app add`

- Inputs
  - App type: daemon / nextjs
  - App identifier, domain, cert/key paths
- Process
  - Daemon: update `profiles[]`
  - Next.js: create AppRole and output sidecar templates
- Output
  - Applied changes + verify option

### `bootroot app info`

- Inputs
  - App identifier
- Process
  - Look up stored state/paths/policies
- Output
  - App-specific config/path summary

### `bootroot verify`

- Inputs
  - App identifier or profile
- Process
  - One-shot issuance + file presence checks
- Output
  - PASS/FAIL

## OpenBao API Call Order (init)

1) `sys/init` (if needed)
2) `sys/unseal` (if needed)
3) `sys/mounts/<mount>` (enable KV v2)
4) `sys/auth/approle` (enable AppRole)
5) `sys/policies/acl/<name>` (create policy)
6) `auth/approle/role/<name>` (create AppRole)
7) `auth/approle/role/<name>/role-id` (read role_id)
8) `auth/approle/role/<name>/secret-id` (create secret_id)
9) `<mount>/data/<path>` (write secrets)

## State Storage (state.json)

- openbao_url
- kv_mount
- policies
- approles
- apps

Example:

```json
{
  "openbao_url": "http://localhost:8200",
  "kv_mount": "secret",
  "policies": {
    "bootroot_agent": "bootroot-agent",
    "responder": "bootroot-responder",
    "stepca": "bootroot-stepca"
  },
  "approles": {
    "bootroot_agent": "bootroot-agent-role",
    "responder": "bootroot-responder-role",
    "stepca": "bootroot-stepca-role"
  },
  "apps": {
    "daemon-001": {
      "type": "daemon",
      "cert_path": "certs/daemon-001.crt",
      "key_path": "certs/daemon-001.key"
    }
  }
}
```

## i18n Key Layout

- `prompt.*`
- `info.*`
- `error.*`
- `confirm.*`

Example: `prompt.openbao_url`, `error.unseal_failed`

## Error Handling Criteria

- Errors include cause and next-step hint
- Fail fast if OpenBao is unreachable
- Destructive actions require double confirmation

## Verification Criteria

- bootroot-agent logs include success message
- cert/key files exist with expected permissions
