# Instructions for AI Coding Agents

This document defines the rules, context, and standards for AI agents
contributing to the `bootroot` project (Rust Edition). Read this carefully
before generating code.

<!-- BEGIN shared:workflow -->
## Language

- Code, comments, commit messages, PR descriptions, and issues are written
  in English.

## Commit messages

- Title: preferably under 50 characters, start with an imperative verb
  (e.g., `Add`, `Fix`, `Remove`).
- Do NOT use prefixes such as `feat:`, `chore:`, or `fix:`.
- Do NOT put issue or PR numbers in the title.
- Body: wrap at 72 characters, free-form, explain *why* not *what*.
- Separate title and body with a blank line.
- Reference issues in the body, not the title: `Closes #N` to close an
  issue, or `Part of #N` when the commit addresses part of one.

## Branching and pushing

- NEVER push directly to `main`. Always create a new branch before
  pushing.
- Branch names must follow the format `<github-username>/issue-#` (e.g.,
  `alice/issue-42`). If there is no related issue, ask the user how to
  proceed before creating the branch.
- The sole exception is a branch carrying an update to the shared blocks
  below, which needs no issue. CI opens it as
  `shared-instructions/<release>`; a maintainer running the fan-out by
  hand opens it as `<github-username>/instructions-<release>`.

## GitHub issues and PRs

- Do NOT hard-wrap lines in issue or PR body text. GitHub renders
  Markdown, so manual line breaks hurt readability. (This applies to the
  body text only — commit messages still wrap at 72.)
- Issues and PRs share ONE number namespace, so `gh issue edit N` and
  `gh issue view N` can silently operate on PR #N when N is a PR. Before
  ANY `gh` write (edit, close, comment), confirm the target's type and
  identity with a read first: `gh issue view N --json
  number,title,state,url`, and check `/pull/` vs `/issues/` in the URL.
- Never act on failed or garbled command output. Re-verify every create
  and edit with a structured `--json` re-query before reporting success.

## Markdown lint configuration

- The repository-root `.markdownlint-cli2.yaml` carries `globs`,
  `ignores`, and `MD024: siblings_only`. No other rule configuration
  belongs there, and no rule is disabled there.
- Configure or disable any other rule at the narrowest scope that
  works, choosing in this order: the line, then the file, then the
  directory. Use `markdownlint-disable-next-line` for one line,
  `markdownlint-disable-file` for one file, and a
  `.markdownlint-cli2.yaml` beside the files for one directory.
- A directory config named `.markdownlint-cli2.yaml` merges with the
  root config; one named `.markdownlint.yaml` replaces it wholesale.
  Use the former.
- Scope narrowly because a global entry outlives its reason. It
  silences the file that needed it and every file added afterwards
  that should have tripped the rule, and nothing in the config records
  which was which.

## Shared instruction blocks

- The regions between `<!-- BEGIN shared:... -->` and
  `<!-- END shared:... -->` in this file are generated from a shared
  source. Do NOT edit them here. Change the wording upstream and cut a
  release there; it arrives as a pull request against this repository.
  An edit made here is overwritten by the next one of those, and turns
  the drift check red until it lands.
- `.agent-instructions.toml` records which release those regions came
  from and which blocks this repository carries. It is source, not tool
  output: the drift check reads it, the apply rewrites it, and nothing
  generates it from anything else. Never add it to `.gitignore`, and
  never untrack it — a repository whose pin cannot be read fails the
  check outright rather than being read as carrying no blocks.

## Attribution

- Do NOT add `Co-Authored-By` lines naming an AI (`Claude`, `Codex`,
  `Gemini`, or any similar name) to commit messages.
- Do NOT add "Generated with Claude Code", "Generated with Codex",
  "Generated with Gemini", or any similar AI attribution to PR
  descriptions or issue comments.
<!-- END shared:workflow -->

<!-- BEGIN shared:agentcoop -->
## AgentCoop

AgentCoop is the AI agent orchestration system this organization runs
over its GitHub issues, so its vocabulary turns up in issue bodies and
pull request comments here — and an agent working in this repository
may itself be running inside it.

- Two agents do the work. The **author** (Agent A) produces, the
  **reviewer** (Agent B) reviews independently, and the two converge
  through structured feedback; a deadlock escalates to a human rather
  than resolving silently. They are usually different models.
- **Implementation** turns one issue into a pull request with green CI.
  The author implements it in a dedicated worktree, self-checks, opens
  the pull request, and drives CI to green; the reviewer then reviews
  the pushed branch and the two iterate in the pull request's comment
  thread, tagged `[Author Round N]` and `[Reviewer Round N]`, until it
  is approved.
- **Design** shapes work into issues: an RFC file becomes an umbrella
  issue over a sub-issue tree, or a single issue is refined — and split
  only when one pull request cannot cover it.
- **Verification** holds a completed issue against the diffs that closed
  it and files follow-up sub-issues for whatever it did not deliver.
- The issue is the contract, and the only input a run is given. A human
  writes that seed and merges the result; AgentCoop invents no
  requirement and asks no clarifying question along the way.
<!-- END shared:agentcoop -->

<!-- BEGIN shared:rust -->
## Coding standards (Rust)

### Errors and panics

- **Error types**: Use `thiserror` where a caller needs to match on the
  error kind, `anyhow` otherwise. Application and library are the usual
  shorthand for that split, not the rule itself: a binary whose layers
  pick a recovery strategy from the error still needs typed errors, and
  a library reaching an application boundary may use `anyhow`.
- **Context**: Attach context to every fallible call that crosses a
  meaningful boundary: `.with_context(|| format!("reading config from
  {path}"))`. State what was being attempted and on which concrete target
  (path, host, service name). Start lowercase, no trailing period, and do
  not repeat what an outer layer will already say.
- **No `unwrap()`**: Do not use `unwrap()` in production code. Usage in
  tests is permitted.
- **`expect("reason")`**: Use when you are certain a panic will NOT occur.
  The message must explain *why* the condition is invariant. Never
  `expect()` on a value derived from network input, file contents, or
  configuration — those are recoverable errors, not invariants.
- **`panic!("reason")`**: Use when you intentionally need to crash the
  program to alert the user of a critical, unrecoverable state.
- **Indexed access**: Prefer methods that return `Option`/`Result`
  (`.get()`, `.first()`, `.next()`) over `[]` on `&[T]`, `Vec<T>`, and
  arrays. Indexing is acceptable only when the bound is established
  immediately above the access and is locally obvious to a reader.
  Indexing a `HashMap`/`BTreeMap` with `[]` is never acceptable.

### Types and conversions

- **Prefer `enum` over `String`** whenever a finite set of values is
  expected.
- **Type casting (`as`)**: `as` checks nothing and reports nothing. Use
  the checked form wherever one exists. Two directions have none, and
  there `as` is a decision to be stated, not a reflex.
  - **Integer to integer, lossless**: use `From` — `u64::from(value)`,
    not `value as u64`. The compiler enforces the losslessness: change
    the types so the conversion no longer fits and the impl is gone and
    the build fails, where `as` would silently start truncating.
  - **Integer to integer, otherwise**: use `TryFrom`/`try_into()` and
    propagate the `TryFromIntError`.
  - **Float to integer**: no `TryFrom` exists, and `as` saturates and
    maps `NaN` to 0. Check the value is finite and in range yourself,
    or use `num-traits`' `ToPrimitive` (`to_u32()`, ...) in a crate
    that already depends on it — subject to the dependency rule below,
    since an explicit check needs nothing. Either way, decide about the
    fraction: `ToPrimitive` rejects `NaN` and out-of-range, then
    truncates toward zero, so `(-0.9_f64).to_u32()` is `Some(0)`. Where
    the value was supposed to be integral, handling the `None` is not
    enough — test `fract() == 0.0` too.
  - **Integer to float**: `From` where it exists (`f64::from(x: u32)`)
    — exactly the conversions that cannot lose anything. Past them
    nothing checks: `u64 as f64` rounds above 2^53, and `f32` stops
    being exact above 2^24. Nor does `ToPrimitive` here — `to_f64()`
    and `to_f32()` are `Some(x as _)`, leaving a `None` arm that can
    never run. Use `as` after deciding rounding is acceptable across
    the value's real range, and record why where that is not obvious.
  - **Float to float**: `f64::from(x: f32)` widens exactly. Narrowing
    has no checked form — `f64 as f32` rounds to nearest, so a value
    just past `f32::MAX` lands back on it, and only one large enough to
    overflow becomes infinity. Neither is an error. Same rule: a
    decision, never a default.
  - `num-traits` is also the right tool for code generic over numeric
    types. Use `num-derive` only to derive its `FromPrimitive` and
    `ToPrimitive` on simple enums or newtypes; it is not std's
    `TryFrom`, which an enum rejecting an unknown discriminant still
    needs.

### Ownership and performance

- **Minimizing `clone`**: Avoid unnecessary `clone()` or similar methods
  (e.g., `to_string()`, `to_owned()`). Performance-critical code must not
  harbour hidden copies.
  - **Prefer references and slices**: Use `&str` over `String` and `&[T]`
    over `Vec<T>` for function parameters and struct field getters. This
    avoids copies and increases compatibility via deref coercion.
  - **Defer cloning**: When cloning is unavoidable, call it at the latest
    possible stage to minimise the scope of copied data and to make the
    necessity visible.
  - **Use clone-avoiding idioms**: Prefer `Iterator::cloned()`,
    `Option::cloned()`, and `Option::as_deref()` over explicit
    `.map(Clone::clone)` or manual unwrap-and-clone patterns.
- **Sorting**: Prefer `sort_unstable`, `sort_unstable_by`, and
  `sort_unstable_by_key` over their stable counterparts. The unstable
  variants are faster and allocate no extra memory. Use stable `sort` only
  when equal elements must preserve their original relative order, and
  `sort_by_cached_key` when the key is expensive to compute.

### Async

Where the crate has async code:

- Use the `tokio` runtime. Avoid blocking operations in async contexts.
- **No orphan tasks**: Do not discard the `JoinHandle` returned by
  `tokio::spawn`. Hold it, or use a `JoinSet`, and cancel outstanding
  tasks on shutdown. A dropped handle turns a task failure into silence.
  - Dropping a `JoinSet` aborts its async tasks at whichever `.await`
    point each has reached. Locals are dropped, so `Drop` runs and an
    RAII guard still releases; what is lost is the rest of the body,
    which is everything that had to be awaited — a flush, a commit, a
    goodbye frame — along with the task's result. None of it reaches a
    `spawn_blocking` task: abort may prevent one that has not started,
    and cannot stop one that has, so a blocking task needs its own way
    of being told to stop. Where shutdown must be graceful, signal the
    tasks — a cancellation token, a closed channel — and `join_next`
    until the set drains. Do not let the set's `Drop` be the shutdown.
- **No locks across `.await`**: Never hold a `std::sync::Mutex`/`RwLock`
  guard across an `.await` point (`clippy::await_holding_lock`). Use
  `tokio::sync` primitives, or scope the guard so it is dropped first.
- **Cancellation safety**: Every branch of `tokio::select!` must be
  cancel-safe. Where a future is not, spawning it and selecting on the
  handle is not by itself the fix: a losing branch drops the handle,
  the task detaches, and it keeps running unobserved — exactly the
  orphan the rule above forbids. Spawn it once into a `JoinSet` or a
  field the loop owns, select on that, and join or abort it at
  shutdown.

### `unsafe`

- Do not introduce new `unsafe`. If FFI or a platform call makes it
  unavoidable, keep the block as small as possible and precede it with a
  `// SAFETY:` comment stating the invariant that makes it sound.
- Note that in edition 2024 `std::env::set_var`/`remove_var` are `unsafe`;
  the `SAFETY` comment must justify why no other thread can be reading the
  environment at that point.

### Files and I/O

- **Atomic writes**: Write state, config, and other files that another
  process may read atomically — write to a temporary file in the same
  directory, then `fs::rename`. Never truncate-and-write in place.
  - The temporary file is created with the permissions the finished
    file needs, by the rule below. `rename` puts the temporary file's
    inode in place, so the destination ends up with whatever mode the
    temporary had and not the mode of the file it replaced. Which
    mode that is depends on how the temporary was made — `OpenOptions`
    leaves it to the umask, `tempfile` defaults to `0o600` — and
    neither is a decision anyone made about this file. The write meant
    to preserve the file is what changes it.
  - Atomic replacement is not durability. The rename either happens or
    does not, but neither it nor the bytes before it are on disk until
    they are flushed. Where the file has to survive a crash or a power
    loss — anything the program reads back to resume from — `sync_all`
    the temporary file before the rename, then open the containing
    directory and `sync_all` that too. This costs a disk round trip
    each time, so it is a decision per file rather than a default:
    where a write takes it, say in a comment what is being protected.
- **Restrictive permissions at creation**: A file holding a secret gets
  its final permissions as it is created, never afterwards —
  `set_permissions` once the bytes are on disk leaves a window in which
  the file is world-readable. On Unix that is
  `OpenOptions::new().mode(0o600)`, from
  `std::os::unix::fs::OpenOptionsExt`. These crates target Unix; if one
  ever ships elsewhere, the equivalent has to exist before the first
  byte is written.

### Output and logging

- Reserve `stdout` for output the user asked for. All diagnostics,
  progress, and debugging go through `tracing`.

### Secrets

- Do not carry a secret (token, password, private key material) as a
  bare `String`. Wrap it in a newtype whose hand-written `Debug` prints
  `<redacted>`, so a `#[derive(Debug)]` on an enclosing struct cannot
  leak it.
- Never interpolate a secret into a `tracing` event, an error message,
  or a `Display` implementation.
- A secret read from a file or an environment variable is still a
  secret. Wrap it at the boundary where it enters the program, not
  wherever it is eventually used.

### Certificate verification

Where the crate verifies certificates:

- Verification is never disabled or weakened to make something work. If
  a handshake or a chain check fails, fix the trust anchors, the SANs,
  or the clock. There is no temporary exception here — only permanent
  ones that were introduced temporarily.
- All verification lives in one dedicated module per crate, named in the
  repository-specific section below, whether it reaches for a library's
  escape hatch (`rustls`'s `dangerous()`, a hand-written
  `ServerCertVerifier` or `ClientCertVerifier`) or drives a verifier
  directly (`webpki`'s `EndEntityCert`). Do not verify anywhere else,
  and do not add a new path without a design decision recorded in the
  pull request.
- Never widen what is accepted — algorithms, key usages, name
  constraints, validity windows — to make one certificate pass. Widening
  admits every other certificate that fits the new opening, not only the
  one in front of you.

### Cryptography

Where the crate handles key material or secrets:

- Compare secrets, tokens, MACs, and certificate fingerprints in
  constant time — `constant_time::verify_slices_are_equal`, from
  whichever crypto stack the crate already depends on; `ring` and
  `aws-lc-rs` both spell it that way. Never `==`: the derived
  `PartialEq` on a secret-bearing type is a timing oracle. A crate
  with no such stack does not grow a hand-written loop instead —
  nothing stops the compiler turning one back into an early return.
- Draw key material, and any value whose security rests on being
  unguessable (session identifiers, API keys, opaque bearer tokens),
  from a cryptographically secure source — the same stack's
  `rand::SystemRandom`. Never a general-purpose PRNG, a timestamp, or
  a process ID. A signed token such as a JWT is not drawn this way at
  all: its strength comes from the signing key, which is key material.
- A nonce must meet whatever its construction documents, which is
  usually uniqueness under a given key rather than randomness. Counter
  and deterministically derived nonces are correct where the algorithm
  calls for them. What is never acceptable is reusing one under the
  same key.
- Do not implement a cryptographic primitive by hand. If the operation is
  not available in an existing dependency, that is a design discussion,
  not a coding task.

### Visibility, imports, and modules

- **Visibility**: Expose the minimum necessary scope.
  - Prefer `pub(super)` or `pub(crate)` over `pub`. Use `pub` only for
    library public APIs exported from `lib.rs`.
  - When adding a new item, start with the most restrictive visibility and
    widen only when a compiler error or an explicit design decision
    requires it.
- **Imports**: Do NOT use wildcard imports (`use module::*`). The only
  exception is `use super::*` inside `#[cfg(test)]` test modules.
- **Module files**: Prefer `module_name.rs` over `module_name/mod.rs`. Use
  the named sibling file style introduced in Rust 2018.

### Constants and comments

- Use `const` for fixed values instead of "magic strings/numbers".
- Define constants at the top of the file. A `const` used by exactly one
  function may live inside that function.
- Keep test-only constants near the tests for readability.
- Delete redundant or "noisy" comments that just describe code syntax.

### Documentation (rustdoc)

- Every public item opens its doc comment with one concise summary
  sentence. For functions that sentence starts with a verb in the
  **third-person singular** ("Creates...", "Returns...",
  "Calculates..."); types, traits, modules, and constants take a noun
  phrase instead ("A connection pool that...").
- Every public function returning `Result` needs an `# Errors` section,
  and every one that can panic needs a `# Panics` section, describing the
  conditions rather than restating the type.
- Mark functions whose return value is the entire point with `#[must_use]`.

### Dependencies

- Adding a dependency requires a stated reason. Prefer the standard
  library, then an existing dependency of the crate, before adding a new
  one.
- Do not add a dependency for functionality that a crate already in
  `Cargo.toml` provides.

### Testing

- Use `tempfile::tempdir()` for tests that need temporary files or
  directories. Never write to fixed paths.
- Do not mutate the process environment in tests with `env::set_var` or
  `env::remove_var`. In Rust 2024 these are `unsafe`: outside Windows,
  another thread reading the environment concurrently can cause
  undefined behaviour. A `Mutex` shared between tests does not make the
  call sound — it serialises only the code that takes the lock, not a
  runtime thread or a dependency reading in the background. Where a
  test already mutates the environment, remove the mutation rather than
  adding another lock.
- Test environment-dependent behaviour by passing the value in — as a
  parameter, a configuration map, or a resolver the test substitutes.
  For a child process, set its environment with `Command::env`,
  `Command::env_remove`, or `Command::env_clear`, rather than changing
  this process's.
- Keep `env::var` at a thin composition boundary: read the values once
  and pass them to the logic underneath. Test that boundary through a
  child process when an exact environment must be asserted; logic that
  receives its values needs no environment at all.
- Do not synchronise with `sleep`. Await the condition, or use
  `tokio::time` pause/advance with the `test-util` feature.
- Do not hard-code port numbers; bind port 0 and read back the assigned
  address.
- Tests must not reach the network. Use a local mock server.

### Linting and formatting

- **Linting**: Code MUST pass `cargo clippy` with `-D warnings`, over
  every target and every feature configuration the crate supports. The
  repository-specific section below names the exact invocations; they
  must match what CI runs.
  - `--all-targets` covers lib, bins, tests, benches, and examples. It
    does NOT touch features — with it alone, code behind a non-default
    feature is never linted at all.
  - `--all-features` is correct only when every feature can be on at
    once. Where a crate has mutually exclusive features, that
    combination does not compile; lint each configuration separately
    with `--no-default-features --features <name>`.
- **Formatting**: Code MUST be formatted with `rustfmt`. `group_imports`
  is still nightly-gated, so it cannot live in `rustfmt.toml` — pass it on
  the command line, exactly as CI does:

  ```sh
  cargo fmt -- --config group_imports=StdExternalCrate
  ```

  Plain `cargo fmt`, including editor format-on-save, will NOT group
  imports and will produce a result CI rejects.
- **`#[allow(...)]`**:
  - Avoid `#[allow(...)]` as much as possible.
  - If `allow` is necessary, you MUST add a comment explaining why.
  - Exceptions: `clippy::too_many_lines` can be treated loosely.
<!-- END shared:rust -->

<!-- BEGIN shared:changelog -->
## Changelog

- `CHANGELOG.md` records what changed for a user of the **last release**,
  not how `main` got there. Before writing an entry, ask whether someone
  running the last released version could observe it. Work that builds,
  reworks, or removes something they never had is invisible to them and
  does not belong.
- Entries carry NO issue or PR references. `Closes #N` and `Part of #N`
  are GitHub automation keywords: they close an issue when they appear
  in a commit message or a pull request body, and do nothing whatever
  inside `CHANGELOG.md`. All that is left there is a command addressed
  to a bot, stranded in a record of what already shipped — it cannot
  act, and the reader has no use for it. Git and the issue tracker
  already hold that history.
- Announce a feature once, under `### Added`, describing what it does.
  If it was reworked or renamed before the release shipped, that is not
  a separate `### Changed` entry — no user saw the earlier form.
<!-- END shared:changelog -->

## CI Requirements

- Before committing, ensure the `check` job (Quality Check) in `.github/workflows/ci.yml`
  would pass for the changed files.
- Before pushing or opening a PR, ensure all CI jobs pass (`check`,
  `test-core`, `test-docker-e2e-matrix` from `ci.yml`, and
  `run-extended` from `e2e-extended.yml`).
- **Local preflight verification**: Run `scripts/preflight/run-all.sh`
  before pushing. At minimum, run `scripts/preflight/ci/e2e-matrix.sh`
  and `scripts/preflight/ci/e2e-extended.sh`. These may be skipped only
  when your changes do not affect the Docker lifecycle, E2E scripts, or
  any code paths exercised by the E2E tests (rotation, service add/verify,
  daemon, config, etc.).

## Documentation Build

- A change under `docs/` (or to `mkdocs.yml`) MUST pass
  `mkdocs build --strict`. Run `./scripts/check-docs.sh`, which is what CI
  runs: it verifies the vendored theme, builds with `--strict`, and asserts
  the built pages link the theme stylesheets and that every referenced
  theme asset reached `site/`.
- No theme setup is required. The shared docs theme is vendored under
  `docs/theme/` and committed, so a fresh clone builds the manual with no
  network access and no `gh` — only `pip install mkdocs-material
  mkdocs-static-i18n`.
- Never edit anything under `docs/theme/`. The installer records a content
  digest in `docs/theme/.meta` and the CI verification step fails on any
  drift. Changes there belong in
  [aicers/docs-theme](https://github.com/aicers/docs-theme).
- To adopt a new theme release, edit `version` in `docs/theme.toml`, run
  `./scripts/fetch-theme.sh` (needs `gh`), and commit the resulting
  `docs/theme/`.
- `mkdocs.yml` inherits `docs/theme/mkdocs-base.yml`. MkDocs merges
  mappings recursively but replaces lists and scalars wholesale, so do NOT
  redeclare `theme.features`, `markdown_extensions`, `extra_css`, or
  `exclude_docs` here — even partially. Doing so silently discards
  everything the base defines for that key.
