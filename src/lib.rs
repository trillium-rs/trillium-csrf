//! Cross-site request forgery (CSRF) protection for [trillium](https://trillium.rs).
//!
//! This crate is a work in progress and does not yet have a public API.
#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    missing_copy_implementations,
    rustdoc::missing_crate_level_docs,
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    unused_qualifications
)]

// Compile the README as a doctest so its examples stay in sync with the crate.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme {}
