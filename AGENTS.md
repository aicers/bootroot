# Instructions for AI Coding Agents

This document defines the rules, context, and standards for AI agents
contributing to the `bootroot` project (Rust Edition). Read this carefully
before generating code.

## 1. Coding Standards (Rust)

* **Error Handling**: Use `anyhow::Result` for application code and
  `thiserror` for library code.
  * **No `unwrap()`**: Do not use `unwrap()` in production code. Usage in
    tests is permitted.
  * **`expect("reason")`**: Use when you are certain a panic will NOT occur.
    The message must explain *why* the condition is invariant.
  * **`panic!("reason")`**: Use when you intentionally need to crash the
    program to alert the user of a critical, unrecoverable state.
  * **Indexed Access**: Do not use `[]` to index into indexed collections
    (`&[T]`, `Vec<T>`, arrays). Use safe methods that return `Option` or
    `Result` (e.g., `.get()`, `.next()`) to avoid out-of-bounds panics.
* **Linting**: Code MUST pass `cargo clippy` with no warnings.
* **Formatting**: Code MUST be formatted with `rustfmt` (use `group_imports=StdExternalCrate`).
* **Async**: Use `tokio` runtime. Avoid blocking operations in async contexts.
* **Constants**:
  * Use `const` for fixed values instead of "magic strings/numbers".
  * Define constants at the **top of the file**, not inside functions.
  * **Tests**: Keep test-only constants near the tests for readability.
* **Type Casting (`as`)**:
  * Use `as` only when the conversion is 100% safe.
  * Otherwise use `num_traits` conversions and handle errors explicitly.
* **Types**:
  * Prefer `enum` over `String` whenever a finite set of values is expected.
* **Sorting**: Prefer `sort_unstable`, `sort_unstable_by`, and
  `sort_unstable_by_key` over their stable counterparts. The unstable
  variants are faster and allocate no extra memory. Use stable `sort` only
  when equal elements must preserve their original relative order.
* **Minimizing `clone`**: Avoid unnecessary `clone()` or similar methods
  (e.g., `to_string()`, `to_owned()`). Performance-critical code must not
  harbour hidden copies.
  * **Prefer references and slices**: Use `&str` over `String` and `&[T]`
    over `Vec<T>` for function parameters and struct field getters. This
    avoids copies and increases compatibility via deref coercion.
  * **Defer cloning**: When cloning is unavoidable, call it at the latest
    possible stage to minimise the scope of copied data and to make the
    necessity visible.
  * **Use clone-avoiding idioms**: Prefer `Iterator::cloned()`,
    `Option::cloned()`, and `Option::as_deref()` over explicit
    `.map(Clone::clone)` or manual unwrap-and-clone patterns.
* **Visibility**: Expose the minimum necessary scope.
  * Prefer `pub(super)` or `pub(crate)` over `pub`. Use `pub` only for
    library public APIs exported from `lib.rs`.
  * When adding a new item, start with the most restrictive visibility and
    widen only when a compiler error or an explicit design decision requires
    it.
* **Imports**:
  * Do NOT use wildcard imports (`use module::*`). The only exception is
    `use super::*` inside `#[cfg(test)]` test modules.
* **Testing**:
  * Use `tempfile::tempdir()` for tests that need temporary files or
    directories. Never write to fixed paths.
  * When tests manipulate environment variables (`env::set_var`), protect
    them with a shared `Mutex` lock so that parallel test threads do not
    interfere with each other.
* **Comments**:
  * Delete redundant or "noisy" comments that just describe code syntax.
* **Documentation (Rustdoc)**:
  * Doc comments (`///`) must start with a verb in the **third-person singular**
    form (e.g., "Creates...", "Returns...", "Calculates...").
* **Module files**: Prefer `module_name.rs` over `module_name/mod.rs`.
  Use the named sibling file style introduced in Rust 2018.
* **Lints (Clippy)**:
  * Avoid `#[allow(...)]` as much as possible.
  * If `allow` is necessary, you **MUST** add a comment explaining why.
  * Exceptions: `clippy::too_many_lines` can be treated loosely.

## 2. Commit Messages

* Title: preferably under 50 characters, start with imperative verb
  (e.g., `Add`, `Fix`, `Remove`)
* Body: wrap at 72 characters, free-form, explain *why* not *what*
* Separate title and body with a blank line
* Reference issues: use `Closes #N` to close an issue, or
  `Part of #N` when the commit addresses part of an issue

## 3. Language

* Code, comments, commit messages, PR descriptions, and issues are written in
  English.

## 4. Branching and Pushing

* NEVER push directly to `main`. Always create a new branch before pushing.
* Branch names must follow the format `<github-username>/issue-#` (e.g.,
  `alice/issue-42`). If there is no related issue, ask the user how to
  proceed before creating the branch.

## 5. Attribution

* Do NOT add `Co-Authored-By: Claude`, `Co-Authored-By: Codex`,
  `Co-Authored-By: Gemini`, or any similar AI name to commit messages.
* Do NOT add "Generated with Claude Code", "Generated with Codex",
  "Generated with Gemini", or any similar AI attribution to PR descriptions
  or issue comments.

## 6. CI Requirements

* Before committing, ensure the `check` job (Quality Check) in `.github/workflows/ci.yml`
  would pass for the changed files.
* Before pushing or opening a PR, ensure all CI jobs pass (`check`,
  `test-core`, `test-docker-e2e-matrix` from `ci.yml`, and
  `run-extended` from `e2e-extended.yml`).
* **Local preflight verification**: Run `scripts/preflight/run-all.sh`
  before pushing. At minimum, run `scripts/preflight/ci/e2e-matrix.sh`
  and `scripts/preflight/ci/e2e-extended.sh`. These may be skipped only
  when your changes do not affect the Docker lifecycle, E2E scripts, or
  any code paths exercised by the E2E tests (rotation, service add/verify,
  daemon, config, etc.).
