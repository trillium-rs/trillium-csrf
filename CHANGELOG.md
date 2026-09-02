# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1](https://github.com/trillium-rs/trillium-csrf/compare/v0.1.0...v0.1.1) - 2026-09-02

### Other

- *(deps)* update codecov/codecov-action action to v7
- Merge pull request #2 from trillium-rs/renovate/actions-upload-pages-artifact-5.x
- *(deps)* update actions/upload-pages-artifact action to v5

## [0.1.0] - 2026-08-26

First release with a version dependents can receive patch updates against.
Identical in content to 0.0.0, which it supersedes: cargo treats every `0.0.x`
as semver-incompatible with every other, so nothing published as `0.0.x` can
ever reach a dependent through `cargo update`.

### Added

- `Csrf` handler rejecting state-changing cross-origin requests via
  `Sec-Fetch-Site` with an `Origin`-vs-host fallback; requests with neither
  header (non-browser clients) are allowed. GET, HEAD, and OPTIONS are exempt.
- `Csrf::with_trusted_origins` for exact-match cross-origin allowlisting. To
  exempt a route, run the handler conditionally (see the crate docs).
