//! The session layer's settings and cookie jars on a `reqwest` client.
#![cfg(feature = "session-reqwest")]

mod support;

use std::sync::{Arc, Mutex};

use coqui_syshttp::proxy::source::ProxySource;
use coqui_syshttp::reqwest::builder_from;
use coqui_syshttp::session::jar::{FileCookieJar, MemoryCookieJar};
use coqui_syshttp::session::{Client, CookieStore, HttpEnv, SessionSettings};
use coqui_syshttp::{BypassRules, Dialect, Environment, Resolver, Route};
use support::http_server::{Reply, Server};
use ureq::http::Method;

/// Records every URL the resolver is asked about, and answers direct.
#[derive(Debug, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl ProxySource for Recorder {
    fn routes(&self, url: &str) -> Result<Option<Vec<Route>>, coqui_syshttp::proxy::Error> {
        self.0.lock().unwrap().push(url.to_string());
        Ok(Some(vec![Route::Direct]))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_decision_is_asked_again_for_each_redirect_hop() {
    let origin = Server::start(|req| match req.target.as_str() {
        "/start" => Reply::redirect(
            302,
            &format!(
                "http://localhost:{}/next",
                req.header("host").unwrap().rsplit(':').next().unwrap()
            ),
        ),
        _ => Reply::ok("arrived"),
    });
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = Resolver::builder()
        .environment(Environment::from_pairs(Vec::<(String, String)>::new()))
        .system(false)
        // Loopback is proxied too, so the recorder sees it.
        .no_proxy(BypassRules::parse("<-loopback>", Dialect::NoProxy))
        .source(Recorder(Arc::clone(&asked)))
        .build();
    let client = builder_from(&SessionSettings::default())
        .resolver(resolver)
        .build()
        .unwrap();
    let response = client.get(origin.url("/start")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "arrived");
    let asked = asked.lock().unwrap().clone();
    assert!(
        asked.iter().any(|url| url.contains("127.0.0.1")),
        "{asked:?}"
    );
    assert!(
        asked.iter().any(|url| url.contains("localhost")),
        "{asked:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_jar_is_a_reqwest_cookie_store_over_the_same_files() {
    let server = Server::start(|req| match req.target.as_str() {
        "/set" => Reply::ok("").header("Set-Cookie", "r=1; Path=/; Max-Age=1000"),
        _ => Reply::ok(req.header("cookie").unwrap_or("none").to_string()),
    });
    let home = tempfile::tempdir().unwrap();
    let jar = Arc::new(FileCookieJar::new(home.path()));
    let client = builder_from(&SessionSettings::default())
        .configure({
            let jar = Arc::clone(&jar);
            move |builder| builder.cookie_provider(jar)
        })
        .build()
        .unwrap();
    client.get(server.url("/set")).send().await.unwrap();
    let text = client
        .get(server.url("/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(text, "r=1");
    let file = home.path().join("cookies").join("127.0.0.1.txt");
    assert!(std::fs::read_to_string(&file).unwrap().contains("\tr\t1"));

    // The session client reads the file the reqwest client wrote.
    let env = HttpEnv::builder()
        .environment([
            (
                "SYSHTTP_HOME".to_string(),
                home.path().to_string_lossy().to_string(),
            ),
            ("SYSHTTP_SYSTEM_PROXY".to_string(), "off".to_string()),
        ])
        .build()
        .unwrap();
    let url = server.url("/");
    let seen = tokio::task::spawn_blocking(move || {
        let session = Client::builder()
            .env(env)
            .cookies(CookieStore::PerHost)
            .build()
            .unwrap();
        session
            .request(Method::GET, url)
            .send()
            .unwrap()
            .text()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(seen, "r=1");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_memory_jar_keeps_cookies_for_a_reqwest_client() {
    let server = Server::start(|req| match req.target.as_str() {
        "/set" => Reply::ok("").header("Set-Cookie", "m=1; Path=/"),
        _ => Reply::ok(req.header("cookie").unwrap_or("none").to_string()),
    });
    let jar = Arc::new(MemoryCookieJar::new());
    let client = builder_from(&SessionSettings::default())
        .configure({
            let jar = Arc::clone(&jar);
            move |builder| builder.cookie_provider(jar)
        })
        .build()
        .unwrap();
    client.get(server.url("/set")).send().await.unwrap();
    assert_eq!(
        client
            .get(server.url("/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "m=1"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_settings_become_headers_and_a_redirect_limit() {
    let server = Server::start(|req| match req.target.as_str() {
        "/loop" => Reply::redirect(302, "/loop"),
        _ => Reply::ok(format!(
            "{}|{}",
            req.header("user-agent").unwrap_or(""),
            req.header("x-extra").unwrap_or("")
        )),
    });
    let mut settings = SessionSettings::default();
    settings.user_agent = "tool/1".into();
    settings.headers.push(("X-Extra".into(), Some("e".into())));
    settings.max_redirects = 2;
    let client = builder_from(&settings).build().unwrap();
    assert_eq!(
        client
            .get(server.url("/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "tool/1|e"
    );
    assert!(client.get(server.url("/loop")).send().await.is_err());
    assert_eq!(
        server.log().iter().filter(|r| r.target == "/loop").count(),
        3
    );
}
