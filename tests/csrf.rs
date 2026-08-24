use trillium::Handler;
use trillium_csrf::{Csrf, csrf};
use trillium_testing::{TestConn, assert_body, assert_status};

fn app(csrf: Csrf) -> impl Handler {
    (csrf, "ok")
}

fn post() -> TestConn {
    TestConn::build("post", "/", "body")
}

#[test]
fn safe_methods_are_always_allowed() {
    for method in ["get", "head", "options"] {
        let conn = TestConn::build(method, "/", ())
            .with_request_header("sec-fetch-site", "cross-site")
            .on(&app(csrf()));
        assert_status!(conn, 200);
    }
}

#[test]
fn requests_without_browser_headers_are_allowed() {
    assert_status!(post().on(&app(csrf())), 200);
}

#[test]
fn empty_sec_fetch_site_is_treated_as_absent() {
    let conn = post()
        .with_request_header("sec-fetch-site", "")
        .on(&app(csrf()));
    assert_status!(conn, 200);
}

#[test]
fn same_origin_and_none_are_allowed() {
    for value in ["same-origin", "none"] {
        let conn = post()
            .with_request_header("sec-fetch-site", value)
            .on(&app(csrf()));
        assert_status!(conn, 200);
    }
}

#[test]
fn cross_site_same_site_and_unknown_values_are_rejected() {
    for value in ["cross-site", "same-site", "unexpected-value"] {
        let mut conn = post()
            .with_request_header("sec-fetch-site", value)
            .on(&app(csrf()));
        assert_status!(conn, 403);
        assert_body!(conn, "cross-origin request forbidden");
    }
}

#[test]
fn query_method_is_protected() {
    let conn = post()
        .with_request_header("sec-fetch-site", "cross-site")
        .on(&app(csrf()));
    assert_status!(conn, 403);

    let conn = TestConn::build("query", "/", "{}")
        .with_request_header("sec-fetch-site", "cross-site")
        .on(&app(csrf()));
    assert_status!(conn, 403);
}

#[test]
fn origin_fallback_matching_host_is_allowed() {
    let conn = post()
        .with_request_header("host", "example.com")
        .with_request_header("origin", "https://example.com")
        .on(&app(csrf()));
    assert_status!(conn, 200);
}

#[test]
fn origin_fallback_is_case_insensitive_and_ignores_scheme() {
    let conn = post()
        .with_request_header("host", "Example.COM")
        .with_request_header("origin", "http://example.com")
        .on(&app(csrf()));
    assert_status!(conn, 200);
}

#[test]
fn origin_fallback_mismatched_host_is_rejected() {
    let conn = post()
        .with_request_header("host", "example.com")
        .with_request_header("origin", "https://attacker.example")
        .on(&app(csrf()));
    assert_status!(conn, 403);
}

#[test]
fn origin_null_is_rejected() {
    let conn = post()
        .with_request_header("host", "example.com")
        .with_request_header("origin", "null")
        .on(&app(csrf()));
    assert_status!(conn, 403);
}

#[test]
fn similar_hostnames_are_rejected() {
    for origin in [
        "https://evil-example.com",
        "https://example.com.evil.example",
        "https://wwwexample.com",
    ] {
        let conn = post()
            .with_request_header("host", "example.com")
            .with_request_header("origin", origin)
            .on(&app(csrf()));
        assert_status!(conn, 403);
    }
}

#[test]
fn explicit_ports_must_match() {
    let conn = post()
        .with_request_header("host", "localhost:8080")
        .with_request_header("origin", "http://localhost:8080")
        .on(&app(csrf()));
    assert_status!(conn, 200);

    let conn = post()
        .with_request_header("host", "localhost:8080")
        .with_request_header("origin", "http://localhost:8081")
        .on(&app(csrf()));
    assert_status!(conn, 403);
}

#[test]
fn default_ports_are_normalized() {
    let conn = post()
        .with_request_header("host", "example.com:443")
        .with_request_header("origin", "https://example.com")
        .on(&app(csrf()));
    assert_status!(conn, 200);

    let conn = post()
        .with_request_header("host", "example.com:80")
        .with_request_header("origin", "http://example.com")
        .on(&app(csrf()));
    assert_status!(conn, 200);

    let conn = post()
        .with_request_header("host", "example.com:8080")
        .with_request_header("origin", "https://example.com")
        .on(&app(csrf()));
    assert_status!(conn, 403);
}

#[test]
fn ipv6_hosts_match() {
    let conn = post()
        .with_request_header("host", "[::1]:8080")
        .with_request_header("origin", "http://[::1]:8080")
        .on(&app(csrf()));
    assert_status!(conn, 200);

    let conn = post()
        .with_request_header("host", "[::1]:8080")
        .with_request_header("origin", "http://[::2]:8080")
        .on(&app(csrf()));
    assert_status!(conn, 403);
}

#[test]
fn trusted_origin_allows_sec_fetch_site_cross_site() {
    let handler = app(csrf().with_trusted_origins(["https://app.example.com"]));

    let conn = post()
        .with_request_header("sec-fetch-site", "cross-site")
        .with_request_header("origin", "https://app.example.com")
        .on(&handler);
    assert_status!(conn, 200);

    let conn = post()
        .with_request_header("sec-fetch-site", "cross-site")
        .with_request_header("origin", "https://other.example.com")
        .on(&handler);
    assert_status!(conn, 403);

    let conn = post()
        .with_request_header("sec-fetch-site", "cross-site")
        .on(&handler);
    assert_status!(conn, 403);
}

#[test]
fn trusted_origin_allows_origin_fallback_mismatch() {
    let handler = app(csrf().with_trusted_origins(["https://app.example.com"]));

    let conn = post()
        .with_request_header("host", "api.example.com")
        .with_request_header("origin", "https://app.example.com")
        .on(&handler);
    assert_status!(conn, 200);
}

#[test]
fn trusted_origins_normalize_default_ports() {
    let handler = app(csrf().with_trusted_origins(["https://app.example.com:443"]));

    let conn = post()
        .with_request_header("sec-fetch-site", "cross-site")
        .with_request_header("origin", "https://app.example.com")
        .on(&handler);
    assert_status!(conn, 200);
}

#[test]
fn trusted_origins_compare_schemes() {
    let handler = app(csrf().with_trusted_origins(["https://app.example.com"]));

    let conn = post()
        .with_request_header("sec-fetch-site", "cross-site")
        .with_request_header("origin", "http://app.example.com")
        .on(&handler);
    assert_status!(conn, 403);
}

#[test]
fn subdomains_of_trusted_origins_are_not_trusted() {
    let handler = app(csrf().with_trusted_origins(["https://example.com"]));

    let conn = post()
        .with_request_header("sec-fetch-site", "cross-site")
        .with_request_header("origin", "https://sub.example.com")
        .on(&handler);
    assert_status!(conn, 403);
}

struct ExemptSsoCallback(Csrf);

impl Handler for ExemptSsoCallback {
    async fn run(&self, conn: trillium::Conn) -> trillium::Conn {
        if conn.path() == "/sso/callback" {
            conn
        } else {
            self.0.run(conn).await
        }
    }
}

#[test]
fn conditional_wrapping_exempts_a_route() {
    let handler = (ExemptSsoCallback(csrf()), "ok");

    let conn = TestConn::build("post", "/sso/callback", "body")
        .with_request_header("sec-fetch-site", "cross-site")
        .on(&handler);
    assert_status!(conn, 200);

    let conn = post()
        .with_request_header("sec-fetch-site", "cross-site")
        .on(&handler);
    assert_status!(conn, 403);
}

#[test]
#[should_panic = "must be a bare origin"]
fn trusted_origin_with_path_panics() {
    let _ = csrf().with_trusted_origins(["https://example.com/app"]);
}

#[test]
#[should_panic = "could not parse trusted origin"]
fn unparseable_trusted_origin_panics() {
    let _ = csrf().with_trusted_origins(["not an origin"]);
}

#[test]
#[should_panic = "must be http or https"]
fn non_http_trusted_origin_panics() {
    let _ = csrf().with_trusted_origins(["wss://example.com"]);
}
