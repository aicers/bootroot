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
  `thiserror` for library code.
  * **No `unwrap()`**: Do not use `unwrap()` in production code. Usage in
    tests is permitted.
  * **`expect("reason")`**: Use when you are certain a panic will NOT occur.
    The message must explain *why* the condition is invariant.
  * **`panic!("reason")`**: Use when you intentionally need to crash the
    program to alert the user of a critical, unrecoverable state.
* **Linting**: Code MUST pass `cargo clippy` with no warnings.
* **Formatting**: Code MUST be formatted with `rustfmt` (use `group_imports=StdExternalCrate`).
* **Async**: Use `tokio` runtime. Avoid blocking operations in async contexts.

## 3. Quality Gates (Strict)

**Every code change** must satisfy the following Quality Gates. You must
verify these locally before proposing any code. Breakdown:

* **Linting (Rust)**: Must pass `cargo clippy --all-targets -- -D warnings`.
* **Formatting**: Must pass `cargo fmt -- --check --config group_imports=StdExternalCrate`.
* **Linting (Biome)**: Must pass `biome ci --error-on-warnings .`.
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

* **ACME Protocol**: We implement a custom ACME client (`src/acme.rs`) using
  `reqwest` and `ring`, adhering strictly to RFC 8555. Be careful with nonce
  handling, JWK thumbprints, and retries.
* **Step CA**: Integration targets `smallstep/step-ca`.
* **Deployment**: The agent runs as a sidecar. Ensure graceful shutdown on
  `SIGTERM`.

## 6. Communication & Workflow Guidelines

* **Commit Messages & Issue/PR Titles**:
  * **No Prefixes**: Do NOT use prefixes like `feat:`, `chore:`, `fix:`, etc.
  * **Commits Only**:
    * **Title format**: Use the **imperative mood** (e.g., "Add feature", "Fix bug").
    * **Title limit**: **50 characters**.
    * **Body limit**: Wrap at **72 characters**.

## 7. Code Review Guidelines

* **Constants**:
  * Use `const` for fixed values instead of "magic strings/numbers".
  * Define constants at the **top of the file**, not inside functions.
  * **Tests**: Keep test-only constants near the tests for readability.
* **Type Casting (`as`)**:
  * Use `as` only when the conversion is 100% safe.
  * Otherwise use `num_traits` conversions and handle errors explicitly.
* **Types**:
  * Prefer `enum` over `String` whenever a finite set of values is expected.
* **Comments**:
  * Delete redundant or "noisy" comments that just describe code syntax.
* **Documentation (Rustdoc)**:
  * Doc comments (`///`) must start with a verb in the **third-person singular**
    form (e.g., "Creates...", "Returns...", "Calculates...").
* **Lints (Clippy)**:
  * Avoid `#[allow(...)]` as much as possible.
  * If `allow` is necessary, you **MUST** add a comment explaining why.
  * Exceptions: `clippy::too_many_lines` can be treated loosely.
