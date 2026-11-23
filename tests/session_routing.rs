//! Routing is asked again for every hop: two stand-in proxies see the two hosts of a redirect.
#![cfg(feature = "session")]

mod support;

use std::sync::Arc;

use coqui_syshttp::proxy::source::ProxySource;
use coqui_syshttp::session::{Client, HttpEnv};
use coqui_syshttp::{Proxy, Resolver, Route};
use support::http_server::{Reply, Server};
use support::{Require, StandInProxy};
use ureq::http::Method;

#[derive(Debug)]
struct ByHost {
    a: Proxy,
    b: Proxy,
}

impl ProxySource for ByHost {
    fn routes(&self, url: &str) -> Result<Option<Vec<Route>>, coqui_syshttp::proxy::Error> {
        let proxy = if url.contains("a.test") {
            self.a.clone()
        } else if url.contains("b.test") {
            self.b.clone()
        } else {
            return Ok(None);
        };
        Ok(Some(vec![Route::Proxy(proxy)]))
    }
}

#[test]
fn a_redirect_to_another_host_is_routed_through_the_other_proxy() {
    // The redirect target needs the origin's own port, known once it is listening.
    let port_holder = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(0));
    let origin = Server::start({
        let port_holder = Arc::clone(&port_holder);
        move |req| match req.target.as_str() {
            "/start" => Reply::redirect(
                302,
                &format!(
                    "http://b.test:{}/next",
                    port_holder.load(std::sync::atomic::Ordering::SeqCst)
                ),
            )
            .header("Set-Cookie", "k=v; Path=/"),
            _ => Reply::ok(req.header("cookie").unwrap_or("none").to_string()),
        }
    });
    port_holder.store(origin.addr.port(), std::sync::atomic::Ordering::SeqCst);
    let proxy_a = StandInProxy::start(Require::Nothing, origin.addr);
    let proxy_b = StandInProxy::start(Require::Nothing, origin.addr);
    let resolver = Resolver::builder()
        .environment(coqui_syshttp::Environment::from_pairs(Vec::<(
            String,
            String,
        )>::new()))
        .system(false)
        .source(ByHost {
            a: Proxy::parse(&proxy_a.proxy_url()).unwrap(),
            b: Proxy::parse(&proxy_b.proxy_url()).unwrap(),
        })
        .build();
    let client = Client::builder()
        .env(
            HttpEnv::builder()
                .environment([("SYSHTTP_SYSTEM_PROXY", "off")])
                .build()
                .unwrap(),
        )
        .resolver(resolver)
        .build()
        .unwrap();
    let mut response = client
        .request(
            Method::GET,
            format!("http://a.test:{}/start", origin.addr.port()),
        )
        .send()
        .unwrap();
    assert_eq!(
        response.text().unwrap(),
        "none",
        "a cookie for a.test is not sent to b.test"
    );
    let port = origin.addr.port();
    let lines = |proxy: &StandInProxy| -> Vec<String> {
        proxy
            .seen()
            .iter()
            .map(|seen| seen.request_line.clone())
            .collect()
    };
    assert_eq!(
        lines(&proxy_a),
        vec![format!("CONNECT a.test:{port} HTTP/1.1")]
    );
    assert_eq!(
        lines(&proxy_b),
        vec![format!("CONNECT b.test:{port} HTTP/1.1")]
    );
    let hosts: Vec<_> = origin
        .log()
        .iter()
        .map(|req| req.header("host").unwrap().to_string())
        .collect();
    assert_eq!(
        hosts,
        vec![format!("a.test:{port}"), format!("b.test:{port}")]
    );
}
