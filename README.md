# trillium-csrf

[![ci][ci-badge]][ci]
[![crates.io version][version-badge]][crate]
[![docs.rs][docs-badge]][docs]
[![codecov][codecov-badge]][codecov]

[ci]: https://github.com/trillium-rs/trillium-csrf/actions?query=workflow%3ACI
[ci-badge]: https://github.com/trillium-rs/trillium-csrf/workflows/CI/badge.svg
[version-badge]: https://img.shields.io/crates/v/trillium-csrf.svg?style=flat-square
[crate]: https://crates.io/crates/trillium-csrf
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square
[docs]: https://docs.rs/trillium-csrf
[codecov-badge]: https://codecov.io/gh/trillium-rs/trillium-csrf/graph/badge.svg
[codecov]: https://codecov.io/gh/trillium-rs/trillium-csrf

Cross-site request forgery (CSRF) protection for the [trillium.rs](https://trillium.rs) web framework.

This handler rejects state-changing cross-origin requests using metadata that
browsers attach to every request (`Sec-Fetch-Site`, with an `Origin` fallback).
It needs no tokens, no cookies, and no configuration to protect an app whose
frontend and api share an origin. See [the docs][docs] for the exact decision
sequence and its limits.

## Example

```rust
use trillium_csrf::csrf;

let app = (
    csrf().with_trusted_origins(["https://app.example.com"]),
    |conn: trillium::Conn| async move { conn.ok("hello") },
);
```

## Safety

This crate uses `#![forbid(unsafe_code)]`.

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br/>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
