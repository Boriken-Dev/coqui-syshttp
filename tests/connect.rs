mod support;

use coqui_syshttp::{
    Credentials, Environment, Error, Proxy, ProxyConnector, ProxyScheme, Resolver, Route,
};
use support::{Require, StandInOrigin, StandInProxy, get};

fn proxy_with_login(proxy: &StandInProxy, user: &str, password: &str) -> Proxy {
    Proxy::builder(ProxyScheme::Http, "127.0.0.1", proxy.addr.port())
        .credentials(Credentials::new(user, password))
        .build()
        .unwrap()
}

#[test]
fn a_connect_through_a_proxy_that_requires_basic_carries_the_credentials_and_reaches_the_origin() {
    let origin = StandInOrigin::start("hello from the origin");
    let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), origin.addr);
    let route = Route::Proxy(proxy_with_login(&proxy, "ada", "s3cret"));
    let mut connection = ProxyConnector::default()
        .connect(&route, "app.internal.test", 80)
        .unwrap();
    let reply = get(&mut connection, "app.internal.test");
    assert!(reply.ends_with("hello from the origin"), "{reply}");
    let seen = proxy.seen();
    assert_eq!(
        seen[0].request_line,
        "CONNECT app.internal.test:80 HTTP/1.1"
    );
    assert_eq!(
        seen[0].header("proxy-authorization"),
        Some("Basic YWRhOnMzY3JldA==")
    );
}

#[test]
fn a_proxy_that_refuses_the_credentials_is_a_login_error_that_does_not_echo_them() {
    let origin = StandInOrigin::start("x");
    let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), origin.addr);
    let route = Route::Proxy(proxy_with_login(&proxy, "ada", "wrong"));
    let error = ProxyConnector::default()
        .connect(&route, "app.internal.test", 80)
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)), "{error}");
    assert!(!error.to_string().contains("wrong"));
}

#[test]
fn a_proxy_that_asks_for_a_login_nobody_configured_is_a_login_error() {
    let origin = StandInOrigin::start("x");
    let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), origin.addr);
    let route = Route::Proxy(
        Proxy::builder(ProxyScheme::Http, "127.0.0.1", proxy.addr.port())
            .build()
            .unwrap(),
    );
    let error = ProxyConnector::default()
        .connect(&route, "app.internal.test", 80)
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)), "{error}");
}

#[test]
fn a_header_the_proxy_names_goes_to_the_proxy_in_the_connect_and_never_through_the_tunnel() {
    let origin = StandInOrigin::start("tunnelled");
    let proxy = StandInProxy::start(Require::Header("X-Proxy-Token", "abc"), origin.addr);
    let built = Proxy::builder(ProxyScheme::Http, "127.0.0.1", proxy.addr.port())
        .header("X-Proxy-Token", "abc")
        .build()
        .unwrap();
    let mut connection = ProxyConnector::default()
        .connect(&Route::Proxy(built), "x.test", 80)
        .unwrap();
    let reply = get(&mut connection, "x.test");
    assert!(reply.ends_with("tunnelled"), "{reply}");
    assert_eq!(proxy.seen()[0].header("x-proxy-token"), Some("abc"));
}

#[test]
fn a_socks_proxy_is_reported_as_unsupported() {
    let route = Route::Proxy(Proxy::parse("socks5://127.0.0.1:1").unwrap());
    let error = ProxyConnector::default()
        .connect(&route, "x.test", 80)
        .unwrap_err();
    assert!(matches!(error, Error::Unsupported(_)), "{error}");
}

#[test]
fn a_direct_route_connects_to_the_server_itself() {
    let origin = StandInOrigin::start("direct");
    let mut connection = ProxyConnector::default()
        .connect(&Route::Direct, "127.0.0.1", origin.addr.port())
        .unwrap();
    assert!(get(&mut connection, "127.0.0.1").ends_with("direct"));
}

#[test]
fn the_resolver_fails_over_from_a_proxy_that_does_not_answer_and_remembers_it() {
    let origin = StandInOrigin::start("via the second");
    let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), origin.addr);
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let list = format!(
        "PROXY {dead}; PROXY ada:s3cret@127.0.0.1:{}; DIRECT",
        proxy.addr.port()
    );
    // A list in `HTTP_PROXY` is a PAC result; a login is not part of that form, so it is given
    // to the resolver instead.
    let list = list.replace("ada:s3cret@", "");
    let resolver = Resolver::builder()
        .environment(Environment::from_pairs([("HTTP_PROXY", list)]))
        .credentials(Credentials::new("ada", "s3cret"))
        .build();
    let connector = ProxyConnector::default();
    let mut connection = connector
        .connect_url(&resolver, "http://app.internal.test/")
        .unwrap();
    assert!(get(&mut connection, "app.internal.test").ends_with("via the second"));
    let routes = resolver.lookup("http://app.internal.test/").unwrap();
    assert!(matches!(routes.last(), Some(Route::Proxy(p)) if p.port() == dead.port()));
}
