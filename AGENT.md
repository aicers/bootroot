# Coding Standards for Agents

This document records coding rules for AI agents (Copilot, Claude Code, etc.)
contributing to the `bootroot` project. Rules here complement `CLAUDE.md`.

## Rust

* **Module files**: Prefer `module_name.rs` over `module_name/mod.rs`.
  Use the named sibling file style introduced in Rust 2018.
  Example: use `src/commands.rs` alongside a `src/commands/` directory
  rather than `src/commands/mod.rs`.
