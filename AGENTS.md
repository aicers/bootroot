# Instructions for AI Coding Agents

This document defines the rules, context, and standards for AI agents
contributing to the `bootroot` project (Rust Edition). Read this carefully
before generating code.

## 1. Core Philosophy

* **Safety First**: Leverage Rust's ownership model to guarantee memory safety.
  Avoid `unsafe` blocks unless absolutely necessary and documented.
* **Production Readiness**: Code must design for reliability, logging, and
  recovery. Handle all `Result` types explicitly.
* **Minimal Dependencies**: Use established crates (`tokio`, `clap`, `anyhow`)
  but avoid bloating the binary with unused features.

## 2. Coding Standards (Rust)

* **Error Handling**: Use `anyhow::Result` for application code and
  `thiserror` for library code. Never use `unwrap()` or `expect()` in
  production paths (panic is unacceptable).
* **Linting**: Code MUST pass `cargo clippy` with no warnings.
* **Formatting**: Code MUST be formatted with `rustfmt` (default settings).
* **Async**: Use `tokio` runtime. Avoid blocking operations in async contexts.

## 3. Quality Gates (Strict)

**Every code change** must satisfy the following Quality Gates. You must
verify these locally before proposing any code. Breakdown:

* **Linting (Rust)**: Must pass `cargo clippy --all-targets -- -D warnings`.
* **Formatting**: Must pass `cargo fmt -- --check`.
* **Security Audit**: Must pass `cargo audit` (check for vulnerable dependencies).
* **Testing**: `cargo test` must pass all unit and integration tests.
* **Linting (Docs/Misc)**:
  * **Markdown**: `markdownlint-cli2 "**/*.md" "#node_modules" "#target"`

## 4. Architectural Constraints

* **Secret Management**: NEVER hardcode secrets. Use `clap` (Env/Args) to
  inject sensitive data.
* **File Permissions**:
  * Private keys: `0600` (Use `std::os::unix::fs::PermissionsExt`)
  * Secrets directory: `0700`
* **Docker**:
  * The Rust agent will run as a standalone binary in a distroless or alpine
    container.

## 5. Domain Context

* **ACME Protocol**: We use `instant-acme` or `rustls-acme`. Be careful with
  nonce handling and retries.
* **Step CA**: Integration targets `smallstep/step-ca`.
* **Deployment**: The agent runs as a sidecar. Ensure graceful shutdown on
  `SIGTERM`.
