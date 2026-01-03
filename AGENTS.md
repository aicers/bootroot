# Instructions for AI Coding Agents

This document defines the rules, context, and standards for AI agents
contributing to the `bootroot` project. Read this carefully before generating
code.

## 1. Core Philosophy

* **Security First**: This is a PKI infrastructure tool. Security
  vulnerabilities (e.g., weak permissions, command injection) are
  unacceptable.
* **Production Readiness**: Code must design for reliability, logging, and
  recovery, not just "happy path".
* **Minimal Dependencies**: Prefer standard library (`os`, `net/http`) over
  3rd party libs unless necessary.

## 2. Coding Standards (Go)

* **Error Handling**: Always wrap errors with context using
  `fmt.Errorf("action: %w", err)`. Never return raw errors.
* **Linting**: Code MUST pass `golangci-lint` default rules.
* **Security Scanning**: Code MUST pass `gosec`. Use `// #nosec Gxxx` ONLY if
  you have verified it is safe and added a comment explaining why.
* **Concurrency**: Use `context.Context` for cancellation and timeouts. Avoid
  orphaned goroutines.

## 3. Quality Gates (Strict)

**Every code change** must satisfy the following Quality Gates. You must
verify these locally before proposing any code. Breakdown:

* **Linting (Go)**: Must pass `golangci-lint run ./...` without errors.
* **Linting (Docs/Misc)**: must comply with style guides.
  * **Markdown**: `markdownlint-cli2 "**/*.md" "#node_modules"`
  * **Formatting**: `biome check .`
* **Security Scan**: `gosec ./...`
  * Zero tolerance for High/Medium issues.
  * Exceptions must be explicitly annotated with `// #nosec Gxxx`.
* **Unit Tests**: `go test -v ./...`
* **E2E Tests**: The CI builds Docker images and verifies certificate issuance
  against a real CA. Ensure changes do not break the bootstrapping flow.

## 4. Architectural Constraints

* **Secret Management**: NEVER hardcode secrets. Use CLI flags or Environment
  Variables.
* **Docker**:
  * Avoid running containers as `root` unless strictly required.
  * Use specific image tags (not `latest`) for reproducibility.
* **File Permissions**:
  * Private keys: `0600`
  * Secrets directory: `0700` (or `0750`)

## 5. Domain Context

* **ACME Protocol**: We use the `lego` library (v4). Note that
  `RegisterWithExternalAccountBinding` requires `RegisterEABOptions` struct
  in newer versions.
* **Step CA**: We use `smallstep/step-ca`.
* **Development Environment**: Be aware of Docker Desktop (Mac) volume
  permission issues. We use temporary workarounds in `cmd/bootroot`
  (e.g., permission fixups), but these should be isolated and documented.
