//! The default transport: routes, gateways, TLS settings, connection reuse.
#![cfg(all(feature = "session", feature = "tls"))]

mod support;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use coqui_syshttp::session::{
    Body, Error, Headers, HttpEnv, PreparedRequest, Timeouts, Transport, UreqTransport,
};
use coqui_syshttp::tls::Trust;
use support::http_server::{Reply, Server};
use support::pki::Ca;
use support::tls_server::{ClientAuth, TlsServer};
use ureq::http::Method;

fn env(extra: &[(&str, &str)]) -> HttpEnv {
    let mut pairs = vec![("SYSHTTP_SYSTEM_PROXY".to_string(), "off".to_string())];
    pairs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    HttpEnv::builder().environment(pairs).build().unwrap()
}

fn get(url: &str) -> PreparedRequest {
    PreparedRequest::prepare(
        Method::GET,
        url,
        Headers::new(),
        Body::Empty,
        Timeouts::both(Some(Duration::from_secs(10))),
    )
    .unwrap()
}

fn pem(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(line).unwrap());
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    text
}

#[test]
fn a_prepared_request_is_checked_before_anything_is_sent() {
    let body = |text: &str| Body::from(text);
    let url = "http://127.0.0.1/";
    let headers = Headers::new();
    let post = PreparedRequest::prepare(
        Method::POST,
        url,
        headers.clone(),
        Body::Empty,
        Timeouts::unlimited(),
    )
    .unwrap();
    assert_eq!(post.headers.get("Content-Length").as_deref(), Some("0"));
    assert_eq!(
        post.headers.get("Accept-Encoding").as_deref(),
        Some("gzip, deflate")
    );
    assert!(post.decode);
    let own = PreparedRequest::prepare(
        Method::GET,
        "http://127.0.0.1/p#fragment",
        Headers::from_pairs([("accept-encoding", "br")]),
        Body::Empty,
        Timeouts::unlimited(),
    )
    .unwrap();
    assert!(!own.decode);
    assert_eq!(own.headers.get("Accept-Encoding").as_deref(), Some("br"));
    assert_eq!(own.url.fragment(), None);
    for (what, result) in [
        (
            "a method-less URL scheme",
            PreparedRequest::prepare(
                Method::GET,
                "ftp://x/",
                headers.clone(),
                Body::Empty,
                Timeouts::unlimited(),
            ),
        ),
        (
            "credentials in the URL",
            PreparedRequest::prepare(
                Method::GET,
                "http://u:p@x/",
                headers.clone(),
                Body::Empty,
                Timeouts::unlimited(),
            ),
        ),
        (
            "a header name that is not a token",
            PreparedRequest::prepare(
                Method::GET,
                url,
                Headers::from_pairs([("a b", "c")]),
                Body::Empty,
                Timeouts::unlimited(),
            ),
        ),
        (
            "a header value with a line break",
            PreparedRequest::prepare(
                Method::GET,
                url,
                Headers::from_pairs([("A", "b\nc")]),
                Body::Empty,
                Timeouts::unlimited(),
            ),
        ),
        (
            "a repeated Content-Length",
            PreparedRequest::prepare(
                Method::POST,
                url,
                Headers::from_pairs([("Content-Length", "1"), ("content-length", "1")]),
                body("a"),
                Timeouts::unlimited(),
            ),
        ),
        (
            "a zero timeout",
            PreparedRequest::prepare(
                Method::GET,
                url,
                headers.clone(),
                Body::Empty,
                Timeouts::both(Some(Duration::ZERO)),
            ),
        ),
    ] {
        let error = result.unwrap_err();
        assert!(matches!(error, Error::InvalidRequest(_)), "{what}: {error}");
    }
}

#[test]
fn sequential_requests_share_one_connection_and_close_drops_it() {
    let server = Server::start(|_| Reply::ok("x"));
    let transport = UreqTransport::builder().env(env(&[])).build().unwrap();
    for _ in 0..3 {
        let mut response = transport.send(get(&server.url("/")), false).unwrap();
        assert_eq!(response.text().unwrap(), "x");
    }
    assert_eq!(server.connections(), 1);
    transport.close();
    transport.send(get(&server.url("/")), false).unwrap();
    assert_eq!(server.connections(), 2, "a later request connects afresh");
}

#[test]
fn a_request_that_cannot_be_sent_again_does_not_use_a_stale_idle_connection() {
    let server = Server::start(|_| Reply::ok("x"));
    let mut pool = coqui_syshttp::session::PoolSettings::default();
    pool.reuse_window = Duration::from_millis(50);
    let transport = UreqTransport::builder()
        .env(env(&[]))
        .pool(pool)
        .build()
        .unwrap();
    let post = || {
        PreparedRequest::prepare(
            Method::POST,
            &server.url("/"),
            Headers::new(),
            Body::from("x"),
            Timeouts::unlimited(),
        )
        .unwrap()
    };
    transport.send(post(), false).unwrap();
    transport.send(post(), false).unwrap();
    assert_eq!(
        server.connections(),
        1,
        "within the window the connection is reused"
    );
    std::thread::sleep(Duration::from_millis(200));
    transport.send(post(), false).unwrap();
    assert_eq!(server.connections(), 2, "after it a new one is made");
    // A repeatable request keeps using the idle connection.
    let again = Server::start(|_| Reply::ok("x"));
    let mut pool = coqui_syshttp::session::PoolSettings::default();
    pool.reuse_window = Duration::from_millis(50);
    let transport = UreqTransport::builder()
        .env(env(&[]))
        .pool(pool)
        .build()
        .unwrap();
    transport.send(get(&again.url("/")), false).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    transport.send(get(&again.url("/")), false).unwrap();
    assert_eq!(again.connections(), 1);
}

#[test]
fn a_url_prefix_gateway_is_asked_for_the_origin_url_and_the_reply_keeps_it() {
    let gateway = Server::start(|_| Reply::ok("through the gateway"));
    let env = env(&[
        (
            "SYSHTTP_PROXY",
            &format!("http://127.0.0.1:{}", gateway.addr.port()),
        ),
        ("SYSHTTP_PROXY_TYPE", "prefix:/fetch/"),
        ("SYSHTTP_PROXY_AUTH", "Bearer gatewaytoken"),
        ("SYSHTTP_PROXY_AUTH_HEADER", "X-Proxy-Token"),
        ("NO_PROXY", ""),
    ]);
    let transport = UreqTransport::builder().env(env).build().unwrap();
    let mut response = transport
        .send(get("http://api.origin.test/x?y=1"), false)
        .unwrap();
    assert_eq!(response.text().unwrap(), "through the gateway");
    assert_eq!(response.url().as_str(), "http://api.origin.test/x?y=1");
    let seen = &gateway.log()[0];
    assert_eq!(seen.target, "/fetch/http://api.origin.test/x?y=1");
    assert_eq!(seen.header("x-proxy-token"), Some("Bearer gatewaytoken"));
    // Authority of the gateway, not the origin.
    assert!(seen.header("host").unwrap().starts_with("127.0.0.1"));
}

#[test]
fn a_plain_http_gateway_is_never_offered_an_https_origin() {
    let gateway = Server::start(|_| Reply::ok("never"));
    let env = env(&[
        (
            "SYSHTTP_PROXY",
            &format!("http://127.0.0.1:{}", gateway.addr.port()),
        ),
        ("SYSHTTP_PROXY_TYPE", "prefix"),
    ]);
    let transport = UreqTransport::builder().env(env).build().unwrap();
    let error = transport
        .send(get("https://api.origin.test/"), false)
        .unwrap_err();
    assert!(!error.is_connection_failure(), "{error}");
    assert!(gateway.log().is_empty());
}

#[test]
fn a_malformed_proxy_setting_is_refused_when_the_transport_is_made() {
    let bad = env(&[
        ("SYSHTTP_PROXY", "http://gw.test"),
        ("SYSHTTP_PROXY_TYPE", "tunnel"),
    ]);
    let error = UreqTransport::builder().env(bad).build().unwrap_err();
    assert!(matches!(error, Error::Configuration { .. }), "{error}");
}

fn https_server(ca: &Ca) -> TlsServer {
    TlsServer::start(&ca.issue_server("localhost"), &[], ClientAuth::Off)
}

#[test]
fn an_https_origin_is_verified_against_ca_bundle_and_trust_disabled_turns_it_off() {
    let ca = Ca::new("session test ca");
    let server = https_server(&ca);
    let url = format!("https://localhost:{}/", server.addr.port());
    let directory = tempfile::tempdir().unwrap();
    let bundle = directory.path().join("bundle.pem");
    std::fs::File::create(&bundle)
        .unwrap()
        .write_all(pem(ca.der().as_ref()).as_bytes())
        .unwrap();

    // The system's store does not know the test CA.
    let system = UreqTransport::builder().env(env(&[])).build().unwrap();
    assert!(system.send(get(&url), false).is_err());

    let with_bundle = UreqTransport::builder()
        .env(env(&[("CA_BUNDLE", &bundle.to_string_lossy())]))
        .build()
        .unwrap();
    let mut response = with_bundle.send(get(&url), false).unwrap();
    assert_eq!(response.text().unwrap(), "no client certificate");

    let prefixed = UreqTransport::builder()
        .env(env(&[
            ("SYSHTTP_PREFIX", "MINE_"),
            ("MINE_CA_BUNDLE", &bundle.to_string_lossy()),
        ]))
        .build()
        .unwrap();
    assert_eq!(prefixed.send(get(&url), false).unwrap().status(), 200);

    let disabled = UreqTransport::builder()
        .env(env(&[]))
        .trust(Trust::Disabled)
        .build()
        .unwrap();
    assert_eq!(disabled.send(get(&url), false).unwrap().status(), 200);
    assert!(
        UreqTransport::builder()
            .trust(Trust::Disabled)
            .non_defaults()
            .iter()
            .any(|line| line.contains("not verified"))
    );
}

#[test]
fn the_other_tools_bundle_variables_are_not_read() {
    let ca = Ca::new("session test ca");
    let server = https_server(&ca);
    let url = format!("https://localhost:{}/", server.addr.port());
    let directory = tempfile::tempdir().unwrap();
    let bundle = directory.path().join("bundle.pem");
    std::fs::write(&bundle, pem(ca.der().as_ref())).unwrap();
    let transport = UreqTransport::builder()
        .env(env(&[
            ("CURL_CA_BUNDLE", &bundle.to_string_lossy()),
            ("REQUESTS_CA_BUNDLE", &bundle.to_string_lossy()),
            ("SSL_CERT_FILE", &bundle.to_string_lossy()),
        ]))
        .build()
        .unwrap();
    assert!(transport.send(get(&url), false).is_err());
}

#[test]
fn an_unreadable_ca_bundle_is_a_configuration_error_naming_the_variable() {
    let error = UreqTransport::builder()
        .env(env(&[("CA_BUNDLE", "/definitely/not/there.pem")]))
        .build()
        .unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("CA_BUNDLE") && !message.contains("not/there"),
        "{message}"
    );
}

#[test]
fn a_fixed_tls_configuration_is_used_as_given() {
    let ca = Ca::new("session test ca");
    let server = https_server(&ca);
    let url = format!("https://localhost:{}/", server.addr.port());
    let tls = coqui_syshttp::tls::Tls::builder()
        .trust(Trust::Roots(vec![ca.der()]))
        .build()
        .unwrap();
    let transport = UreqTransport::builder()
        .env(env(&[]))
        .tls(tls)
        .build()
        .unwrap();
    assert_eq!(transport.send(get(&url), false).unwrap().status(), 200);
    let _ = Arc::new(transport);
}

#[test]
fn a_tls_given_whole_is_inspected_for_what_it_loosens() {
    let tls = coqui_syshttp::tls::Tls::builder()
        .trust(Trust::Disabled)
        .build()
        .unwrap();
    let lines = UreqTransport::builder().tls(tls).non_defaults();
    assert!(lines.iter().any(|line| line.contains("trust")), "{lines:?}");
    let origin_auth = coqui_syshttp::OriginAuth::builder()
        .plain_http(true)
        .build()
        .unwrap();
    let lines = UreqTransport::builder()
        .origin_auth(origin_auth)
        .non_defaults();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("OriginAuth::plain_http")),
        "{lines:?}"
    );
    let lines = UreqTransport::builder().non_defaults();
    assert!(lines.is_empty(), "{lines:?}");
}

/// A proxy that answers any `CONNECT` with a head of about `padding` bytes, then closes.
fn long_head_proxy(padding: usize) -> std::net::SocketAddr {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let reply = format!(
                    "HTTP/1.1 200 Connection established\r\nX-Padding: {}\r\n\r\n",
                    "a".repeat(padding)
                );
                let _ = stream.write_all(reply.as_bytes());
            });
        }
    });
    address
}

#[test]
fn the_connectors_bounds_survive_a_tls_configuration_for_the_proxy() {
    let proxy = long_head_proxy(200);
    let mut settings = coqui_syshttp::proxy::ConnectorSettings::default();
    settings.max_response_head_bytes = 64;
    let connector = coqui_syshttp::ProxyConnector::builder()
        .settings(settings)
        .build();
    let config = coqui_syshttp::tls::Tls::builder()
        .build()
        .unwrap()
        .client_config("proxy.example")
        .unwrap();
    let transport = UreqTransport::builder()
        .env(env(&[
            ("SYSHTTP_PROXY", &format!("http://{proxy}")),
            ("NO_PROXY", ""),
        ]))
        .connector(connector)
        .proxy_tls(config)
        .build()
        .unwrap();
    let error = transport
        .send(get("http://app.internal.test/"), false)
        .unwrap_err();
    assert!(error.to_string().contains("too long"), "{error}");
}
