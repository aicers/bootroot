# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fix `bootroot rotate stepca-password` failing with TTY allocation error
  when running in non-interactive environments by adding `-f` flag to `step
  crypto change-pass` command
- Bind PostgreSQL to localhost in `docker-compose.yml` so that
  `bootroot rotate db` can connect from the host without exposing the DB
  to external interfaces. Set `POSTGRES_HOST_PORT` if the default port 5432
  conflicts with a local PostgreSQL instance.
- Fixed `bootroot rotate db` failing with SQL syntax error. PostgreSQL's
  `ALTER ROLE ... WITH PASSWORD` and `CREATE ROLE ... WITH PASSWORD` statements
  do not support parameterized queries (`$1`). The password is now properly
  escaped as a string literal.

## [0.1.0] - 2026-02-01

### Added

- Initial public release of the bootroot

[Unreleased]: https://github.com/aicers/bootroot/compare/0.1.0...main
[0.1.0]: https://github.com/aicers/bootroot/tree/0.1.0
