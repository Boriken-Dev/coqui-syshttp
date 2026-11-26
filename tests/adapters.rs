#![cfg(any(feature = "ureq", feature = "hyper", feature = "reqwest"))]

//! Each HTTP-stack adapter fetches over HTTPS from a loopback TLS origin through a loopback proxy
//! that wants Basic, and through a loopback SOCKS proxy.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(any(feature = "ureq", feature = "hyper"))]
use coqui_syshttp::tls::{ClientCertificates, Identity, Selector};
use coqui_syshttp::tls::{Tls, Trust};
use coqui_syshttp::{Credentials, Environment, Resolver};
use support::pki::Ca;
#[cfg(any(feature = "ureq", feature = "hyper"))]
use support::pki::Leaf;
use support::socks_server::SocksServer;
use support::tls_server::{ClientAuth, TlsServer};
use support::{Require, StandInOrigin, StandInProxy};

#[cfg(any(feature = "ureq", feature = "hyper"))]
fn identity(leaf: &Leaf) -> Identity {
    let key = rustls::crypto::ring::sign::any_supported_type(&leaf.key()).unwrap();
    Identity::new(leaf.chain.clone(), key, "pem").unwrap()
}

fn dead() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn resolver(variable: &str, value: String) -> Resolver {
    Resolver::builder()
        .environment(Environment::from_pairs([(variable, value)]))
        .credentials(Credentials::new("ada", "s3cret"))
        .build()
}

/// A resolver whose only source fails, with the loopback bypass off so that the lookup reaches
/// it for a loopback origin.
#[cfg(feature = "reqwest")]
fn failing_resolver() -> Resolver {
    #[derive(Debug)]
    struct Failing;
    impl coqui_syshttp::proxy::ProxySource for Failing {
        fn routes(
            &self,
            _url: &str,
        ) -> Result<Option<Vec<coqui_syshttp::Route>>, coqui_syshttp::proxy::Error> {
            Err(coqui_syshttp::proxy::Error::NoReachableProxy)
        }
    }
    Resolver::builder()
        .environment(Environment::from_pairs([("X", "y")]))
        .system(false)
        .no_proxy(coqui_syshttp::BypassRules::parse(
            "<-loopback>",
            coqui_syshttp::Dialect::NoProxy,
        ))
        .source(Failing)
        .build()
}

/// A server wanting a certificate from the corp CA, and the `Tls` that trusts it and holds one.
#[cfg(any(feature = "ureq", feature = "hyper"))]
struct Origin {
    server: TlsServer,
    tls: Tls,
    client: Leaf,
}

#[cfg(any(feature = "ureq", feature = "hyper"))]
fn origin() -> Origin {
    let server_ca = Ca::new("Server CA");
    let client_ca = Ca::new("Corp Client CA");
    let client = client_ca.issue_client("keystore-user");
    let server = TlsServer::start(
        &server_ca.issue_server_for(&["app.internal.test", "localhost"]),
        &[client_ca.der()],
        ClientAuth::Required,
    );
    let selector = Selector::builder().source(identity(&client)).build();
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![server_ca.der()]))
        .client_certificates(ClientCertificates::Selector(Arc::new(selector)))
        .build()
        .unwrap();
    Origin {
        server,
        tls,
        client,
    }
}

#[cfg(feature = "hyper")]
mod hyper_client {
    use super::*;
    use bytes::Bytes;
    use coqui_syshttp::hyper::HttpsConnector;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::client::legacy::Client;

    type Plain = Client<HttpsConnector, Empty<Bytes>>;

    async fn body(client: &Plain, url: &str) -> Result<String, String> {
        let response = client
            .get(url.parse().unwrap())
            .await
            .map_err(|error| format!("{error:?}"))?;
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|error| error.to_string())?
            .to_bytes();
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn through_a_basic_proxy_presenting_the_keystore_certificate() {
        let origin = origin();
        let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), origin.server.addr);
        let client: Plain = coqui_syshttp::hyper::builder()
            .resolver(resolver("HTTPS_PROXY", proxy.proxy_url()))
            .tls(origin.tls)
            .build()
            .unwrap();
        assert_eq!(
            body(&client, "https://app.internal.test/").await.unwrap(),
            "client certificate seen"
        );
        let seen = proxy.seen();
        assert_eq!(
            seen[0].request_line,
            "CONNECT app.internal.test:443 HTTP/1.1"
        );
        assert_eq!(
            seen[0].header("proxy-authorization"),
            Some("Basic YWRhOnMzY3JldA==")
        );
        assert_eq!(
            origin.server.presented(),
            [Some(origin.client.leaf_der().to_vec())]
        );
    }

    #[tokio::test]
    async fn through_a_socks_proxy() {
        let origin = origin();
        let socks = SocksServer::start(origin.server.addr, None);
        let client: Plain = coqui_syshttp::hyper::builder()
            .resolver(resolver("HTTPS_PROXY", format!("socks5://{}", socks.addr)))
            .tls(origin.tls)
            .build()
            .unwrap();
        assert_eq!(
            body(&client, "https://app.internal.test/").await.unwrap(),
            "client certificate seen"
        );
        let asked = socks.asked();
        assert_eq!(asked[0].destination, "app.internal.test");
        assert!(asked[0].name);
    }

    #[tokio::test]
    async fn failover_goes_on_to_the_next_route_and_can_be_turned_off() {
        let origin = origin();
        let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), origin.server.addr);
        let list = format!("PROXY {}; PROXY {}", dead(), proxy.addr);
        let client: Plain = coqui_syshttp::hyper::builder()
            .resolver(resolver("HTTPS_PROXY", list.clone()))
            .tls(origin.tls)
            .build()
            .unwrap();
        assert_eq!(
            body(&client, "https://app.internal.test/").await.unwrap(),
            "client certificate seen"
        );

        let once = Tls::builder().build().unwrap();
        let client: Plain = coqui_syshttp::hyper::builder()
            .resolver(resolver("HTTPS_PROXY", list))
            .tls(once)
            .failover(false)
            .build()
            .unwrap();
        assert!(body(&client, "https://app.internal.test/").await.is_err());
    }

    #[tokio::test]
    async fn the_connector_is_a_service_and_a_built_client_is_returned_as_given() {
        let origin = origin();
        let socks = SocksServer::start(origin.server.addr, None);
        let builder = coqui_syshttp::hyper::builder::<Empty<Bytes>>()
            .resolver(resolver("HTTPS_PROXY", format!("socks5://{}", socks.addr)))
            .tls(origin.tls);
        let connector = builder.connector_service().unwrap();
        assert!(connector.resolver().lookup("https://x.test/").is_ok());
        let own: Plain = Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector);
        let client = coqui_syshttp::hyper::builder().client(own).build().unwrap();
        assert_eq!(
            body(&client, "https://app.internal.test/").await.unwrap(),
            "client certificate seen"
        );
    }
}

#[cfg(feature = "reqwest")]
mod reqwest_client {
    use super::*;

    /// A server that asks for no client certificate, and a configuration that trusts it.
    pub(super) fn plain_origin() -> (TlsServer, Arc<rustls::ClientConfig>) {
        let ca = Ca::new("Server CA");
        let server = TlsServer::start(
            &ca.issue_server_for(&["app.internal.test", "localhost"]),
            &[],
            ClientAuth::Off,
        );
        let tls = Tls::builder()
            .trust(Trust::Roots(vec![ca.der()]))
            .build()
            .unwrap();
        (server, tls.client_config("app.internal.test").unwrap())
    }

    #[tokio::test]
    async fn through_a_basic_proxy() {
        let (server, config) = plain_origin();
        let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), server.addr);
        let client = coqui_syshttp::reqwest::builder()
            .resolver(resolver("HTTPS_PROXY", proxy.proxy_url()))
            .tls_config(config)
            .build()
            .unwrap();
        let text = client
            .get("https://app.internal.test/")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(text, "no client certificate");
        let seen = proxy.seen();
        assert_eq!(
            seen[0].request_line,
            "CONNECT app.internal.test:443 HTTP/1.1"
        );
        assert_eq!(
            seen[0].header("proxy-authorization"),
            Some("Basic YWRhOnMzY3JldA==")
        );
    }

    #[tokio::test]
    async fn through_a_socks_proxy_and_a_direct_route_and_what_it_cannot_do_is_listed() {
        let (server, config) = plain_origin();
        let socks = SocksServer::start(server.addr, None);
        let client = coqui_syshttp::reqwest::builder()
            .resolver(resolver("HTTPS_PROXY", format!("socks5://{}", socks.addr)))
            .tls_config(Arc::clone(&config))
            .build()
            .unwrap();
        let text = client
            .get("https://app.internal.test/")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(text, "no client certificate");
        assert!(socks.asked()[0].name);

        let direct = coqui_syshttp::reqwest::builder()
            .resolver(
                Resolver::builder()
                    .environment(Environment::from_pairs([("X", "y")]))
                    .system(false)
                    .build(),
            )
            .tls_config(config)
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/", server.addr.port());
        assert_eq!(
            direct.get(url).send().await.unwrap().text().await.unwrap(),
            "no client certificate"
        );
        assert!(!coqui_syshttp::reqwest::builder().not_applied().is_empty());
    }

    #[tokio::test]
    async fn a_proxy_reqwest_cannot_use_fails_the_request_instead_of_going_direct() {
        let (server, config) = plain_origin();
        let client = coqui_syshttp::reqwest::builder()
            .failover(false)
            .resolver(resolver(
                "HTTPS_PROXY",
                format!("socks4://127.0.0.1:{}", server.addr.port()),
            ))
            .tls_config(config)
            .build()
            .unwrap();
        assert!(
            client
                .get("https://app.internal.test/")
                .send()
                .await
                .is_err()
        );
        assert!(server.presented().is_empty());
    }

    #[tokio::test]
    async fn a_lookup_that_fails_fails_the_request_instead_of_going_direct() {
        let origin = StandInOrigin::start("direct");
        let (_, config) = plain_origin();
        let client = coqui_syshttp::reqwest::builder()
            .failover(false)
            .resolver(failing_resolver())
            .tls_config(config)
            .build()
            .unwrap();
        assert!(
            client
                .get(format!("http://127.0.0.1:{}/", origin.addr.port()))
                .send()
                .await
                .is_err()
        );
    }

    /// A closed port, then a live proxy.
    pub(super) fn dead_then(live: SocketAddr) -> String {
        format!("PROXY {}; PROXY {live}", dead())
    }

    async fn text(client: &::reqwest::Client, url: &str) -> Result<String, ::reqwest::Error> {
        client.get(url).send().await?.text().await
    }

    #[tokio::test]
    async fn https_and_http_fetches_fail_over_from_a_dead_proxy_to_a_live_one() {
        let (server, config) = plain_origin();
        let secure = StandInProxy::start(Require::Basic("ada", "s3cret"), server.addr);
        let client = coqui_syshttp::reqwest::builder()
            .resolver(resolver("ALL_PROXY", dead_then(secure.addr)))
            .tls_config(Arc::clone(&config))
            .build()
            .unwrap();
        assert_eq!(
            text(&client, "https://app.internal.test/").await.unwrap(),
            "no client certificate"
        );
        assert_eq!(
            secure.seen()[0].request_line,
            "CONNECT app.internal.test:443 HTTP/1.1"
        );

        let origin = StandInOrigin::start("plain http");
        let plain = StandInProxy::start(Require::Basic("ada", "s3cret"), origin.addr);
        let client = coqui_syshttp::reqwest::builder()
            .resolver(resolver("ALL_PROXY", dead_then(plain.addr)))
            .tls_config(config)
            .build()
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                text(&client, "http://app.internal.test/data")
                    .await
                    .unwrap(),
                "plain http"
            );
        }
        // The relay dials the destination through the live proxy with the system's login.
        let seen = plain.seen();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|seen| {
            seen.request_line == "CONNECT app.internal.test:80 HTTP/1.1"
                && seen.header("proxy-authorization") == Some("Basic YWRhOnMzY3JldA==")
        }));
    }

    #[tokio::test]
    async fn without_failover_the_same_fetch_fails_as_before() {
        let (server, config) = plain_origin();
        let secure = StandInProxy::start(Require::Basic("ada", "s3cret"), server.addr);
        let client = coqui_syshttp::reqwest::builder()
            .resolver(resolver("ALL_PROXY", dead_then(secure.addr)))
            .tls_config(config)
            .failover(false)
            .build()
            .unwrap();
        assert!(text(&client, "https://app.internal.test/").await.is_err());
        assert!(secure.seen().is_empty());
    }

    async fn refuses(address: SocketAddr) -> bool {
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(address).await.is_err() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    #[tokio::test]
    async fn the_relay_lives_as_long_as_the_client_and_its_clones() {
        let (server, config) = plain_origin();
        let proxy = StandInProxy::start(Require::Nothing, server.addr);
        let address = dead();
        let mut settings = coqui_syshttp::proxy::RelaySettings::default();
        settings.port = address.port();
        let builder = coqui_syshttp::reqwest::builder()
            .resolver(resolver("ALL_PROXY", dead_then(proxy.addr)))
            .tls_config(config)
            .relay_settings(settings);
        let client = builder.build().unwrap();
        // The builder is gone; the client still reaches the origin through its relay.
        assert!(tokio::net::TcpStream::connect(address).await.is_ok());
        let clone = client.clone();
        drop(client);
        assert_eq!(
            text(&clone, "https://app.internal.test/").await.unwrap(),
            "no client certificate"
        );
        drop(clone);
        assert!(refuses(address).await, "the relay outlived its client");
    }

    #[test]
    fn what_the_relay_makes_possible_is_no_longer_listed_as_a_limit() {
        let relayed = coqui_syshttp::reqwest::builder().not_applied();
        let direct = coqui_syshttp::reqwest::builder()
            .failover(false)
            .not_applied();
        let mentions = |list: &[&str], word: &str| list.iter().any(|line| line.contains(word));
        assert!(!mentions(&relayed, "failover"));
        assert!(!mentions(&relayed, "Negotiate"));
        assert!(!mentions(&relayed, "SOCKS 4"));
        assert!(mentions(&relayed, "Upgrade"));
        assert!(mentions(&direct, "failover"));
        assert!(mentions(&direct, "Negotiate"));
    }

    #[test]
    fn building_needs_a_runtime_only_for_the_relay() {
        let started = coqui_syshttp::reqwest::builder().build();
        assert!(
            matches!(started, Err(coqui_syshttp::Error::Proxy(_))),
            "{started:?}"
        );
        // The error says how to give it one.
        assert!(
            started.unwrap_err().to_string().contains("start_on"),
            "the error names start_on"
        );
        assert!(
            coqui_syshttp::reqwest::builder()
                .failover(false)
                .build()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn the_relay_runs_on_the_runtime_the_builder_names() {
        let (server, config) = plain_origin();
        let proxy = StandInProxy::start(Require::Nothing, server.addr);
        let relay_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let handle = relay_runtime.handle().clone();
        // The thread that builds is in no runtime: the relay goes to the one it is given.
        let builder = coqui_syshttp::reqwest::builder()
            .resolver(resolver("ALL_PROXY", dead_then(proxy.addr)))
            .tls_config(config)
            .runtime(handle);
        let client = std::thread::spawn(move || builder.build().unwrap())
            .join()
            .unwrap();
        assert_eq!(
            text(&client, "https://app.internal.test/").await.unwrap(),
            "no client certificate"
        );
        drop(client);
        relay_runtime.shutdown_background();
    }

    #[tokio::test]
    async fn a_relay_that_is_not_loopback_is_refused() {
        let mut settings = coqui_syshttp::proxy::RelaySettings::default();
        settings.address = "0.0.0.0".parse().unwrap();
        let built = coqui_syshttp::reqwest::builder()
            .relay_settings(settings)
            .build();
        assert!(matches!(built, Err(coqui_syshttp::Error::Proxy(_))));
    }
}

#[cfg(feature = "ureq")]
mod ureq_agent {
    use super::*;
    use coqui_syshttp::ureq::AgentBuilder;

    fn get(agent: &ureq::Agent) -> Result<String, ureq::Error> {
        agent
            .get("https://app.internal.test/")
            .call()?
            .body_mut()
            .read_to_string()
    }

    #[test]
    fn through_a_socks_proxy_with_failover_from_a_dead_one() {
        let origin = origin();
        let socks = SocksServer::start(origin.server.addr, None);
        let list = format!("SOCKS5 {}; SOCKS5 {}", dead(), socks.addr);
        let agent = AgentBuilder::new()
            .resolver(resolver("HTTPS_PROXY", list.clone()))
            .tls(origin.tls)
            .build()
            .unwrap();
        assert_eq!(get(&agent).unwrap(), "client certificate seen");
        assert!(socks.asked()[0].name);

        let once = AgentBuilder::new()
            .resolver(resolver("HTTPS_PROXY", list))
            .tls(Tls::builder().build().unwrap())
            .failover(false)
            .bad_proxy_ttl(std::time::Duration::from_secs(1));
        assert_eq!(once.non_defaults().len(), 1);
        assert!(get(&once.build().unwrap()).is_err());
    }
}

#[cfg(feature = "reqwest-blocking")]
mod reqwest_blocking {
    use super::reqwest_client::{dead_then, plain_origin};
    use super::*;

    fn text(client: &::reqwest::blocking::Client, url: &str) -> Result<String, ::reqwest::Error> {
        client.get(url).send()?.text()
    }

    #[test]
    fn https_and_http_fetches_fail_over_from_a_dead_proxy_to_a_live_one() {
        let (server, config) = plain_origin();
        let secure = StandInProxy::start(Require::Basic("ada", "s3cret"), server.addr);
        let client = coqui_syshttp::reqwest::blocking::builder()
            .resolver(resolver("ALL_PROXY", dead_then(secure.addr)))
            .tls_config(Arc::clone(&config))
            .build()
            .unwrap();
        assert_eq!(
            text(&client, "https://app.internal.test/").unwrap(),
            "no client certificate"
        );
        assert_eq!(
            secure.seen()[0].request_line,
            "CONNECT app.internal.test:443 HTTP/1.1"
        );

        let origin = StandInOrigin::start("plain http");
        let plain = StandInProxy::start(Require::Basic("ada", "s3cret"), origin.addr);
        let client = coqui_syshttp::reqwest::blocking::builder()
            .resolver(resolver("ALL_PROXY", dead_then(plain.addr)))
            .tls_config(config)
            .build()
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                text(&client, "http://app.internal.test/data").unwrap(),
                "plain http"
            );
        }
        // The relay dials the destination through the live proxy with the system's login.
        let seen = plain.seen();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|seen| {
            seen.request_line == "CONNECT app.internal.test:80 HTTP/1.1"
                && seen.header("proxy-authorization") == Some("Basic YWRhOnMzY3JldA==")
        }));
    }

    #[test]
    fn without_failover_the_same_fetch_fails_as_before() {
        let (server, config) = plain_origin();
        let secure = StandInProxy::start(Require::Basic("ada", "s3cret"), server.addr);
        let client = coqui_syshttp::reqwest::blocking::builder()
            .resolver(resolver("ALL_PROXY", dead_then(secure.addr)))
            .tls_config(config)
            .failover(false)
            .build()
            .unwrap();
        assert!(text(&client, "https://app.internal.test/").is_err());
        assert!(secure.seen().is_empty());
    }

    #[test]
    fn through_a_basic_proxy_and_a_socks_proxy() {
        let (server, config) = plain_origin();
        let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), server.addr);
        let client = coqui_syshttp::reqwest::blocking::builder()
            .resolver(resolver("HTTPS_PROXY", proxy.proxy_url()))
            .tls_config(Arc::clone(&config))
            .build()
            .unwrap();
        assert_eq!(
            text(&client, "https://app.internal.test/").unwrap(),
            "no client certificate"
        );
        let socks = SocksServer::start(server.addr, None);
        let client = coqui_syshttp::reqwest::blocking::builder()
            .resolver(resolver("HTTPS_PROXY", format!("socks5://{}", socks.addr)))
            .tls_config(config)
            .build()
            .unwrap();
        assert_eq!(
            text(&client, "https://app.internal.test/").unwrap(),
            "no client certificate"
        );
        assert!(socks.asked()[0].name);
    }

    fn refuses(address: SocketAddr) -> bool {
        for _ in 0..100 {
            if std::net::TcpStream::connect(address).is_err() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }

    #[test]
    fn the_relay_lives_as_long_as_the_client_and_its_clones() {
        let (server, config) = plain_origin();
        let proxy = StandInProxy::start(Require::Nothing, server.addr);
        let address = dead();
        let mut settings = coqui_syshttp::proxy::RelaySettings::default();
        settings.port = address.port();
        let builder = coqui_syshttp::reqwest::blocking::builder()
            .resolver(resolver("ALL_PROXY", dead_then(proxy.addr)))
            .tls_config(config)
            .relay_settings(settings);
        let client = builder.build().unwrap();
        // The builder is gone; the client still reaches the origin through its relay.
        assert!(std::net::TcpStream::connect(address).is_ok());
        let clone = client.clone();
        drop(client);
        assert_eq!(
            text(&clone, "https://app.internal.test/").unwrap(),
            "no client certificate"
        );
        drop(clone);
        assert!(refuses(address), "the relay outlived its client");
    }

    #[test]
    fn a_lookup_that_fails_fails_the_request_instead_of_going_direct() {
        let origin = StandInOrigin::start("direct");
        let (_, config) = plain_origin();
        let client = coqui_syshttp::reqwest::blocking::builder()
            .failover(false)
            .resolver(failing_resolver())
            .tls_config(config)
            .build()
            .unwrap();
        assert!(
            client
                .get(format!("http://127.0.0.1:{}/", origin.addr.port()))
                .send()
                .is_err()
        );
    }

    #[test]
    fn building_needs_no_runtime_and_the_lists_follow_the_async_adapter() {
        // A plain thread with no Tokio runtime of ours: the relay has its own threads.
        let client = coqui_syshttp::reqwest::blocking::builder().build();
        assert!(client.is_ok(), "{client:?}");
        let relayed = coqui_syshttp::reqwest::blocking::builder();
        let direct = coqui_syshttp::reqwest::blocking::builder().failover(false);
        // What the async adapter lists, but the settings that mean nothing to a relay on a Tokio
        // runtime: this relay has threads to join and to poll.
        let asynchronous = coqui_syshttp::reqwest::builder().not_applied();
        assert!(
            relayed
                .not_applied()
                .iter()
                .all(|line| asynchronous.contains(line))
        );
        assert!(
            asynchronous
                .iter()
                .any(|line| line.starts_with("shutdown_wait"))
        );
        assert!(
            !relayed
                .not_applied()
                .iter()
                .any(|line| line.starts_with("shutdown_wait"))
        );
        assert!(
            direct
                .not_applied()
                .iter()
                .any(|line| line.contains("failover"))
        );
        assert_eq!(direct.non_defaults().len(), 1);
        assert!(relayed.non_defaults().is_empty());
    }

    #[test]
    fn a_relay_that_is_not_loopback_is_refused() {
        let mut settings = coqui_syshttp::proxy::RelaySettings::default();
        settings.address = "0.0.0.0".parse().unwrap();
        let built = coqui_syshttp::reqwest::blocking::builder()
            .relay_settings(settings)
            .build();
        assert!(matches!(built, Err(coqui_syshttp::Error::Proxy(_))));
    }
}
