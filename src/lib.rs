//! Cross-site request forgery (CSRF) protection for [trillium](https://trillium.rs).
//!
//! This handler rejects state-changing cross-origin requests using metadata that browsers attach
//! to every request. It needs no tokens, no cookies, and no configuration to protect an app whose
//! frontend and api share an origin:
//!
//! ```
//! use trillium_csrf::csrf;
//!
//! let app = (
//!     csrf(),
//!     |conn: trillium::Conn| async move { conn.ok("hello") },
//! );
//! ```
//!
//! For each request, in order:
//!
//! - GET, HEAD, and OPTIONS requests are always allowed.
//! - If the request has a `Sec-Fetch-Site` header, it is allowed when the value is `same-origin` or
//!   `none` (a user-initiated request such as a bookmark or a typed address) and otherwise
//!   rejected, unless the `Origin` header is trusted (see [`Csrf::with_trusted_origins`]).
//! - Without `Sec-Fetch-Site` but with an `Origin` header, the request is allowed when the origin's
//!   host and port match the request's own host and otherwise rejected, unless the origin is
//!   trusted. Schemes are not compared, so this behaves correctly behind a tls-terminating reverse
//!   proxy.
//! - A request with neither header is allowed: it did not come from a browser, so it cannot carry a
//!   browser's ambient credentials, and cross-site request forgery does not apply.
//!
//! Rejections halt the conn with a 403 status and log the check that failed along with the
//! configuration that would allow the request if it was legitimate.
//!
//! The allowed-method list is exactly GET, HEAD, and OPTIONS, and is not configurable. It exists
//! because browsers send those methods ambiently — navigations, images, plain forms — without a
//! CORS preflight, so rejecting them cross-origin would break ordinary links to your site. Other
//! methods that http defines as safe, such as QUERY, stay protected: a browser only sends them
//! cross-origin after a preflight your server already controls, so exempting them here would
//! trust every handler's implementation without enabling any request that works today.
//!
//! # Exempting a route
//!
//! Webhook endpoints don't need an exemption: webhook senders are not browsers, send neither
//! header, and are allowed. If a route must accept browser requests from origins you can't
//! enumerate — a multi-tenant single-sign-on callback, say — run this handler conditionally by
//! wrapping it:
//!
//! ```
//! use trillium::{Conn, Handler};
//! use trillium_csrf::{Csrf, csrf};
//!
//! struct ExemptSsoCallback(Csrf);
//!
//! impl Handler for ExemptSsoCallback {
//!     async fn run(&self, conn: Conn) -> Conn {
//!         if conn.path() == "/sso/callback" {
//!             conn
//!         } else {
//!             self.0.run(conn).await
//!         }
//!     }
//! }
//!
//! let handler = ExemptSsoCallback(csrf());
//! ```
//!
//! # What this does not cover
//!
//! Browsers released before roughly 2019 may send neither `Sec-Fetch-Site` nor `Origin` on
//! cross-site form submissions, and this handler allows those requests. Protecting that
//! population requires request tokens, which this crate does not provide. For the reasoning
//! behind header-based protection, see [Cross-Site Request
//! Forgery](https://words.filippo.io/csrf/). If you need token support, open an issue.
//!
//! Apis authenticated exclusively by a bearer token or other explicit request header don't need
//! this crate: cross-site request forgery is only possible when authentication is ambient, as
//! with cookies or network position.
#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    missing_copy_implementations,
    rustdoc::missing_crate_level_docs,
    missing_debug_implementations,
    nonstandard_style,
    unused_qualifications
)]
#![warn(missing_docs, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::multiple_crate_versions
)]

use trillium::{
    Conn, Handler,
    KnownHeaderName::{Origin, SecFetchSite},
    Method,
    Status::Forbidden,
};
use url::Url;

/// A [`Handler`] that rejects state-changing cross-origin requests.
///
/// See the [crate-level docs](crate) for the exact decision sequence. Construct with [`csrf`] or
/// [`Csrf::new`] and place it in the handler tuple before any handler with side effects.
#[derive(Debug)]
pub struct Csrf {
    trusted_origins: Vec<url::Origin>,
}

/// Constructs a new [`Csrf`] handler with no trusted origins.
pub const fn csrf() -> Csrf {
    Csrf::new()
}

impl Csrf {
    /// Constructs a new [`Csrf`] handler with no trusted origins.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trusted_origins: Vec::new(),
        }
    }

    /// Allows cross-origin requests from these origins.
    ///
    /// Each entry must be a full origin — scheme, host, and optional port, such as
    /// `"https://app.example.com"` — with nothing else. Requests are compared by exact origin:
    /// no wildcards, and subdomains of a trusted origin are not trusted.
    ///
    /// ```
    /// use trillium_csrf::csrf;
    /// let handler = csrf().with_trusted_origins(["https://app.example.com"]);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if an entry is not parseable as an origin, is not http or https, or contains a
    /// path, query, or credentials. A path would be silently ignored during comparison, so an
    /// entry like `"https://example.com/app"` is rejected rather than matching more broadly
    /// than it reads.
    #[must_use]
    pub fn with_trusted_origins<I>(mut self, origins: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        self.trusted_origins.extend(
            origins
                .into_iter()
                .map(|origin| parse_trusted_origin(origin.as_ref())),
        );
        self
    }

    fn is_trusted(&self, origin: &str) -> bool {
        !self.trusted_origins.is_empty()
            && Url::parse(origin).is_ok_and(|url| self.trusted_origins.contains(&url.origin()))
    }

    fn deny_reason(&self, conn: &Conn) -> Option<String> {
        if matches!(conn.method(), Method::Get | Method::Head | Method::Options) {
            return None;
        }

        let origin = conn
            .request_headers()
            .get_str(Origin)
            .filter(|origin| !origin.is_empty());

        let sec_fetch_site = conn
            .request_headers()
            .get_str(SecFetchSite)
            .filter(|value| !value.is_empty());

        match sec_fetch_site {
            Some("same-origin" | "none") => None,

            Some(sec_fetch_site) => {
                if origin.is_some_and(|origin| self.is_trusted(origin)) {
                    None
                } else {
                    Some(format!(
                        "sec-fetch-site was `{sec_fetch_site}` and origin ({origin:?}) was not \
                         trusted; if this cross-origin request is legitimate, add the origin with \
                         with_trusted_origins or run this handler conditionally for the route"
                    ))
                }
            }

            None => {
                let origin = origin?;
                if origin_matches_host(origin, conn.host()) || self.is_trusted(origin) {
                    None
                } else {
                    Some(format!(
                        "origin `{origin}` did not match request host ({:?}) and was not trusted; \
                         if this cross-origin request is legitimate, add the origin with \
                         with_trusted_origins or run this handler conditionally for the route",
                        conn.host()
                    ))
                }
            }
        }
    }
}

impl Default for Csrf {
    fn default() -> Self {
        Self::new()
    }
}

impl Handler for Csrf {
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the decision needs no io; async is the trait's signature, not this impl's"
    )]
    async fn run(&self, conn: Conn) -> Conn {
        match self.deny_reason(&conn) {
            None => conn,
            Some(reason) => {
                log::warn!(
                    "blocked a {} request to {}: {reason}",
                    conn.method(),
                    conn.path()
                );
                conn.with_status(Forbidden)
                    .with_body("cross-origin request forbidden")
                    .halt()
            }
        }
    }
}

fn parse_trusted_origin(origin: &str) -> url::Origin {
    let url = Url::parse(origin)
        .unwrap_or_else(|error| panic!("could not parse trusted origin `{origin}`: {error}"));

    assert!(
        matches!(url.scheme(), "http" | "https"),
        "trusted origin `{origin}` must be http or https"
    );

    assert!(
        url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        "trusted origin `{origin}` must be a bare origin (scheme://host[:port]) with no path, \
         query, or credentials"
    );

    url.origin()
}

fn origin_matches_host(origin: &str, request_host: Option<&str>) -> bool {
    let Some(request_host) = request_host else {
        return false;
    };
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    let (Some(origin_host), Some(origin_port)) = (url.host_str(), url.port_or_known_default())
    else {
        return false;
    };

    let (request_host, request_port) = split_host_port(request_host);

    request_host.eq_ignore_ascii_case(origin_host)
        && request_port.map_or(
            // a portless Host implies the browser-default port, but the request's scheme isn't
            // knowable behind a tls-terminating proxy, so either default is accepted
            origin_port == 80 || origin_port == 443,
            |request_port| request_port == origin_port,
        )
}

fn split_host_port(host: &str) -> (&str, Option<u16>) {
    if host.starts_with('[') {
        if let Some(close) = host.find(']') {
            let port = host[close + 1..]
                .strip_prefix(':')
                .and_then(|port| port.parse().ok());
            return (&host[..=close], port);
        }
        return (host, None);
    }

    match host.rsplit_once(':') {
        Some((bare_host, port)) => port
            .parse()
            .ok()
            .map_or((host, None), |port| (bare_host, Some(port))),
        None => (host, None),
    }
}

// Compile the README as a doctest so its examples stay in sync with the crate.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme {}
