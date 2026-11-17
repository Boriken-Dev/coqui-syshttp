#![cfg(all(windows, feature = "negotiate"))]

//! The Windows security package logs in to a stand-in proxy as the person running the test.

mod support;

use coqui_syshttp::{Error, Negotiate, Proxy, ProxyConnector, ProxyScheme, Route};
use support::{Require, StandInOrigin, StandInProxy, get};

fn route(proxy: &StandInProxy) -> Route {
    Route::Proxy(
        Proxy::builder(ProxyScheme::Http, "127.0.0.1", proxy.addr.port())
            .build()
            .unwrap(),
    )
}

#[test]
fn a_proxy_the_policy_names_is_logged_in_to_with_the_logon_session() {
    let origin = StandInOrigin::start("negotiated");
    let proxy = StandInProxy::start(Require::Negotiate, origin.addr);
    let policy = Negotiate::builder().proxies(["127.0.0.1"]).build().unwrap();
    let connector = ProxyConnector::builder().negotiate(policy).build();

    let mut connection = connector
        .connect(&route(&proxy), "app.internal.test", 80)
        .unwrap();
    assert!(get(&mut connection, "app.internal.test").ends_with("negotiated"));

    // The first CONNECT carried no token, the following ones carried one, all on one connection.
    let seen = proxy.seen();
    assert!(seen.len() >= 2, "{} requests", seen.len());
    assert!(seen[0].header("proxy-authorization").is_none());
    assert!(
        seen[1]
            .header("proxy-authorization")
            .is_some_and(|value| value.starts_with("Negotiate "))
    );
    // The security package on the proxy side authenticated the account that ran the test.
    let users = proxy.users();
    assert_eq!(users.len(), 1);
    let account = std::env::var("USERNAME").unwrap();
    assert!(
        users[0].to_lowercase().ends_with(&account.to_lowercase()),
        "{} vs {account}",
        users[0]
    );
}

#[test]
fn a_proxy_the_policy_does_not_name_is_not_logged_in_to() {
    let origin = StandInOrigin::start("x");
    let proxy = StandInProxy::start(Require::Negotiate, origin.addr);
    let policy = Negotiate::builder()
        .proxies(["other.example"])
        .build()
        .unwrap();
    let connector = ProxyConnector::builder().negotiate(policy).build();
    let error = connector
        .connect(&route(&proxy), "app.internal.test", 80)
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)), "{error}");
    assert_eq!(proxy.seen().len(), 1);
    assert!(proxy.users().is_empty());
}
