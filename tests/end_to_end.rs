#![cfg(all(feature = "pac", feature = "ureq"))]

//! A request through a PAC-chosen proxy that wants Basic, to a server that wants a client
//! certificate from a keystore, everything on loopback.

mod support;

use std::sync::Arc;

use coqui_syshttp::system::{SettingsSource, SettingsState, SystemSettings};
use coqui_syshttp::tls::{ClientCertificates, Identity, IdentitySource, Selector, Tls, Trust};
use coqui_syshttp::ureq::AgentBuilder;
use coqui_syshttp::{Credentials, Environment, Resolver};
use support::pki::{Ca, Leaf};
use support::tls_server::{ClientAuth, TlsServer};
use support::{Require, StandInProxy};

fn identity(leaf: &Leaf) -> Identity {
    let key = rustls::crypto::ring::sign::any_supported_type(&leaf.key()).unwrap();
    Identity::new(leaf.chain.clone(), key, "pem").unwrap()
}

/// Everything a run needs, held so that nothing is dropped while it runs.
struct World {
    server: TlsServer,
    proxy: StandInProxy,
    agent: ureq::Agent,
    client: Leaf,
    _pac: tempfile::TempDir,
}

/// A TLS server wanting a certificate from the corp CA, a proxy wanting Basic, a PAC file sending
/// `*.internal.test` to that proxy, and an agent whose keystore is `source(client certificate)`.
fn world(source: impl FnOnce(&Leaf) -> Box<dyn IdentitySource>) -> World {
    let server_ca = Ca::new("Server CA");
    let client_ca = Ca::new("Corp Client CA");
    let client = client_ca.issue_client("keystore-user");
    let server = TlsServer::start(
        &server_ca.issue_server_for(&["app.internal.test", "localhost"]),
        &[client_ca.der()],
        ClientAuth::Required,
    );
    let proxy = StandInProxy::start(Require::Basic("ada", "s3cret"), server.addr);

    let pac = tempfile::tempdir().unwrap();
    let path = pac.path().join("proxy.pac");
    std::fs::write(
        &path,
        format!(
            "function FindProxyForURL(url, host) {{
               if (dnsDomainIs(host, '.internal.test')) return 'PROXY 127.0.0.1:{}';
               return 'DIRECT';
             }}",
            proxy.addr.port()
        ),
    )
    .unwrap();
    let settings = SystemSettings::builder(SettingsSource::Windows, SettingsState::Configured)
        .pac_url(path.to_string_lossy())
        .build();
    let resolver = Resolver::builder()
        .environment(Environment::default())
        .settings(settings)
        .credentials(Credentials::new("ada", "s3cret"))
        .build();

    let selector = Selector::builder().source(Boxed(source(&client))).build();
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![server_ca.der()]))
        .client_certificates(ClientCertificates::Selector(Arc::new(selector)))
        .build()
        .unwrap();
    let agent = AgentBuilder::new()
        .resolver(resolver)
        .tls(tls)
        .build()
        .unwrap();
    World {
        server,
        proxy,
        agent,
        client,
        _pac: pac,
    }
}

#[derive(Debug)]
struct Boxed(Box<dyn IdentitySource>);

impl IdentitySource for Boxed {
    fn identities(&self) -> Result<Vec<Identity>, coqui_syshttp::tls::Error> {
        self.0.identities()
    }
}

fn body(agent: &ureq::Agent, url: &str) -> String {
    agent
        .get(url)
        .call()
        .unwrap()
        .body_mut()
        .read_to_string()
        .unwrap()
}

#[test]
fn a_request_goes_through_the_pac_chosen_proxy_with_basic_and_presents_the_certificate() {
    let world = world(|client| Box::new(identity(client)));
    let reply = body(&world.agent, "https://app.internal.test/");
    assert_eq!(reply, "client certificate seen");

    let seen = world.proxy.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].request_line,
        "CONNECT app.internal.test:443 HTTP/1.1"
    );
    assert_eq!(
        seen[0].header("proxy-authorization"),
        Some("Basic YWRhOnMzY3JldA==")
    );
    assert_eq!(
        world.server.presented(),
        [Some(world.client.leaf_der().to_vec())]
    );
}

#[test]
fn a_host_the_pac_sends_direct_never_touches_the_proxy() {
    let world = world(|client| Box::new(identity(client)));
    let url = format!("https://localhost:{}/", world.server.addr.port());
    assert_eq!(body(&world.agent, &url), "client certificate seen");
    assert!(world.proxy.seen().is_empty());
    assert_eq!(
        world.server.presented(),
        [Some(world.client.leaf_der().to_vec())]
    );
}
