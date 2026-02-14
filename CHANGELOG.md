# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `bootroot rotate approle-secret-id` now treats a non-running OpenBao Agent
  as a warning instead of a fatal error, since the `secret_id` file is already
  updated successfully at that point.

## [0.1.0] - 2026-02-01

### Added

- Initial public release of the bootroot

[Unreleased]: https://github.com/aicers/bootroot/compare/0.1.0...main
[0.1.0]: https://github.com/aicers/bootroot/tree/0.1.0
