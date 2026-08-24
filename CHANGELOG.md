# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Csrf` handler rejecting state-changing cross-origin requests via
  `Sec-Fetch-Site` with an `Origin`-vs-host fallback; requests with neither
  header (non-browser clients) are allowed. GET, HEAD, and OPTIONS are exempt.
- `Csrf::with_trusted_origins` for exact-match cross-origin allowlisting. To
  exempt a route, run the handler conditionally (see the crate docs).
