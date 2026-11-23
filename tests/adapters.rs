#![cfg(any(feature = "ureq", feature = "hyper", feature = "reqwest"))]

//! Each HTTP-stack adapter fetches over HTTPS from a loopback TLS origin through a loopback proxy
//! that wants Basic, and through a loopback SOCKS proxy.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use coqui_syshttp::tls::{ClientCertificates, Identity, Selector, Tls, Trust};
use coqui_syshttp::{Credentials, Environment, Resolver};
use support::pki::{Ca, Leaf};
use support::socks_server::SocksServer;
use support::tls_server::{ClientAuth, TlsServer};
use support::{Require, StandInProxy};

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

/// A server wanting a certificate from the corp CA, and the `Tls` that trusts it and holds one.
struct Origin {
    server: TlsServer,
    tls: Tls,
    client: Leaf,
}

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
    fn plain_origin() -> (TlsServer, Arc<rustls::ClientConfig>) {
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
