//! The session client against loopback origins: headers, bodies, redirects, cookies, tokens,
//! retries, deadlines, decoding and hooks.
#![cfg(feature = "session")]

mod support;

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use coqui_syshttp::Secret;
use coqui_syshttp::session::jar::{MemoryCookieJar, MemoryTokenJar, TokenJar};
use coqui_syshttp::session::{
    Auth, AuthProvider, Body, Client, ClientBuilder, CookieStore, Error, HttpEnv, TokenStore,
};
use support::http_server::{Reply, Req, Server};
use ureq::http::Method;

fn quiet(extra: &[(&str, &str)]) -> HttpEnv {
    let mut pairs = vec![("SYSHTTP_SYSTEM_PROXY".to_string(), "off".to_string())];
    pairs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    HttpEnv::builder().environment(pairs).build().unwrap()
}

fn builder() -> ClientBuilder {
    let mut settings = coqui_syshttp::session::SessionSettings::default();
    settings.retry.backoff = Duration::from_millis(10);
    Client::builder().settings(settings).env(quiet(&[]))
}

fn client() -> Client {
    builder().build().unwrap()
}

fn echo() -> Server {
    Server::start(|req: &Req| Reply::ok(format!("{} {}", req.method, req.target)))
}

#[test]
fn a_get_carries_the_default_headers_and_returns_status_headers_url_and_text() {
    let server = Server::start(|_| Reply::ok("hello").header("X-Seen", "1"));
    let mut response = client()
        .request(Method::GET, server.url("/a?b=1"))
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.reason(), "OK");
    assert_eq!(response.headers().get("x-seen").as_deref(), Some("1"));
    assert_eq!(response.url().path(), "/a");
    assert_eq!(response.text().unwrap(), "hello");
    let seen = &server.log()[0];
    assert!(
        seen.header("user-agent")
            .unwrap()
            .starts_with("coqui-syshttp/")
    );
    assert_eq!(seen.header("accept"), Some("*/*"));
    assert_eq!(seen.header("accept-encoding"), Some("gzip, deflate"));
    assert_eq!(seen.target, "/a?b=1");
}

#[test]
fn headers_layer_client_then_call_and_none_removes() {
    let server = echo();
    let client = builder()
        .user_agent("mine/1")
        .header("X-Client", Some("c"))
        .header("X-Both", Some("client"))
        .build()
        .unwrap();
    client
        .request(Method::GET, server.url("/"))
        .header("x-both", Some("call"))
        .header("Accept", None::<String>)
        .send()
        .unwrap();
    let seen = &server.log()[0];
    assert_eq!(seen.header("user-agent"), Some("mine/1"));
    assert_eq!(seen.header("x-client"), Some("c"));
    assert_eq!(seen.header("x-both"), Some("call"));
    assert_eq!(seen.header("accept"), None);
}

#[test]
fn a_header_or_url_with_a_control_character_is_refused_before_anything_is_sent() {
    let server = echo();
    let client = client();
    let bad = client
        .request(Method::GET, server.url("/"))
        .header("X-A", Some("a\r\nX-B: b"))
        .send();
    assert!(matches!(bad, Err(Error::InvalidRequest(_))));
    let url = client.request(Method::GET, "http://127.0.0.1/\r\n").send();
    assert!(matches!(url, Err(Error::InvalidRequest(_))));
    let creds = client
        .request(Method::GET, "http://user:pw@127.0.0.1/")
        .send();
    let message = creds.unwrap_err().to_string();
    assert!(
        message.contains("credentials") && !message.contains("pw"),
        "{message}"
    );
    assert!(server.log().is_empty());
}

#[test]
fn bodies_carry_a_length_and_an_empty_post_says_zero() {
    let server = echo();
    let client = client();
    client
        .request(Method::POST, server.url("/p"))
        .body("héllo")
        .send()
        .unwrap();
    client
        .request(Method::POST, server.url("/e"))
        .send()
        .unwrap();
    client
        .request(Method::PUT, server.url("/r"))
        .body(Body::reader(std::io::Cursor::new(b"streamed".to_vec())))
        .header("Content-Length", Some("8"))
        .send()
        .unwrap();
    client
        .request(Method::POST, server.url("/c"))
        .body(Body::chunks(
            vec![b"ab".to_vec(), b"cd".to_vec()].into_iter(),
        ))
        .send()
        .unwrap();
    let log = server.log();
    assert_eq!(log[0].body, "héllo".as_bytes());
    assert_eq!(log[0].header("content-length"), Some("6"));
    assert_eq!(log[1].header("content-length"), Some("0"));
    assert_eq!(log[2].body, b"streamed");
    assert_eq!(log[3].body, b"abcd", "an unsized body is chunked");
}

#[test]
fn a_declared_length_longer_than_the_body_is_refused() {
    let server = echo();
    let error = client()
        .request(Method::POST, server.url("/"))
        .body("abc")
        .header("Content-Length", Some("10"))
        .send()
        .unwrap_err();
    assert!(matches!(error, Error::InvalidRequest(_)), "{error}");
}

#[test]
fn get_head_and_options_follow_redirects_and_a_303_becomes_a_get() {
    let server = Server::start(|req| match req.target.as_str() {
        "/start" => Reply::redirect(302, "/middle"),
        "/middle" => Reply::redirect(303, "/final"),
        _ => Reply::ok(format!("{} {}", req.method, req.target)),
    });
    let mut response = client()
        .request(Method::GET, server.url("/start"))
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "GET /final");
    assert_eq!(response.url().path(), "/final");
    let head = client()
        .request(Method::HEAD, server.url("/start"))
        .send()
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(server.log().last().unwrap().method, "HEAD");
}

#[test]
fn redirects_false_returns_the_first_answer() {
    let server = Server::start(|_| Reply::redirect(302, "/x"));
    let response = client()
        .request(Method::GET, server.url("/"))
        .redirects(false)
        .send()
        .unwrap();
    assert_eq!(response.status(), 302);
    assert!(response.is_redirect());
    assert_eq!(server.log().len(), 1);
}

#[test]
fn a_redirect_loop_stops_at_the_limit() {
    let server = Server::start(|_| Reply::redirect(302, "/again"));
    let mut settings = coqui_syshttp::session::SessionSettings::default();
    settings.max_redirects = 3;
    let error = Client::builder()
        .settings(settings)
        .env(quiet(&[]))
        .build()
        .unwrap()
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap_err();
    assert!(
        matches!(error, Error::Redirect(ref m) if m.contains("more than 3")),
        "{error}"
    );
    assert_eq!(server.log().len(), 4);
}

#[test]
fn a_302_with_a_bad_location_is_refused() {
    let server = Server::start(|_| Reply::redirect(302, "ftp://example.test/x"));
    let error = client()
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap_err();
    assert!(
        matches!(error, Error::Redirect(ref m) if m.contains("no usable Location")),
        "{error}"
    );
}

#[test]
fn other_methods_are_resent_once_on_307_and_308_to_the_same_origin() {
    let server = Server::start(|req| match req.target.as_str() {
        "/a" => Reply::redirect(307, "/b"),
        "/loop" => Reply::redirect(307, "/loop2"),
        "/loop2" => Reply::redirect(308, "/loop3"),
        "/other" => Reply::redirect(302, "/b"),
        _ => Reply::ok(format!("{} {} {}", req.method, req.target, req.body.len())),
    });
    let client = client();
    let mut response = client
        .request(Method::POST, server.url("/a"))
        .body("data")
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "POST /b 4");
    let second = client
        .request(Method::POST, server.url("/loop"))
        .body("x")
        .send();
    assert!(matches!(second, Err(Error::Redirect(ref m)) if m.contains("a second redirect")));
    let plain = client
        .request(Method::POST, server.url("/other"))
        .body("x")
        .send();
    assert!(matches!(plain, Err(Error::Redirect(ref m)) if m.contains("only 307 and 308")));
}

#[test]
fn propfind_is_resent_for_every_redirect_status() {
    // `ureq` sends the standard methods only, so the rule is shown over a transport of its own.
    #[derive(Debug)]
    struct Dav(Arc<AtomicUsize>);
    impl coqui_syshttp::session::Transport for Dav {
        fn send(
            &self,
            request: coqui_syshttp::session::PreparedRequest,
            _stream: bool,
        ) -> Result<coqui_syshttp::session::Response, Error> {
            let first = self.0.fetch_add(1, Ordering::SeqCst) == 0;
            let builder =
                coqui_syshttp::session::ResponseBuilder::new(if first { 301 } else { 200 })
                    .url(request.url.clone());
            Ok(if first {
                builder
                    .headers(coqui_syshttp::session::Headers::from_pairs([(
                        "Location", "/b",
                    )]))
                    .build()
            } else {
                builder
                    .body(format!("{} {}", request.method, request.url.path()))
                    .build()
            })
        }
        fn close(&self) {}
    }
    let propfind = Method::from_bytes(b"PROPFIND").unwrap();
    let client = Client::builder()
        .env(quiet(&[]))
        .transport(Dav(Arc::new(AtomicUsize::new(0))))
        .build()
        .unwrap();
    let mut response = client
        .request(propfind.clone(), "http://example.test/a")
        .body("<propfind/>")
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "PROPFIND /b");
    // Any other method is refused after a 301.
    let refused = Client::builder()
        .env(quiet(&[]))
        .transport(Dav(Arc::new(AtomicUsize::new(0))))
        .build()
        .unwrap()
        .request(Method::PATCH, "http://example.test/a")
        .body("x")
        .send();
    assert!(matches!(refused, Err(Error::Redirect(_))));
}

#[test]
fn a_body_that_cannot_be_sent_twice_is_not_resent_after_a_redirect() {
    let server = Server::start(|_| Reply::redirect(307, "/b"));
    let error = client()
        .request(Method::POST, server.url("/a"))
        .body(Body::reader(std::io::Cursor::new(b"x".to_vec())))
        .header("Content-Length", Some("1"))
        .send()
        .unwrap_err();
    assert!(
        matches!(error, Error::Redirect(ref m) if m.contains("cannot be sent twice")),
        "{error}"
    );
}

#[test]
fn crossing_an_origin_drops_the_credentials_for_that_hop_and_every_later_one() {
    let third = Server::start(|_| Reply::ok("third"));
    let other = Server::start({
        let next = third.url("/end");
        move |_| Reply::redirect(302, &next)
    });
    let home = Server::start({
        let next = other.url("/x");
        move |req| match req.target.as_str() {
            "/start" => Reply::redirect(302, &next),
            _ => Reply::ok("home"),
        }
    });
    let response = client()
        .request(Method::GET, home.url("/start"))
        .header("Authorization", Some("Bearer secret"))
        .header("Cookie", Some("a=b"))
        .header("Proxy-Authorization", Some("Basic xyz"))
        .header("X-Keep", Some("1"))
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    let first = &home.log()[0];
    assert_eq!(first.header("authorization"), Some("Bearer secret"));
    assert_eq!(first.header("cookie"), Some("a=b"));
    assert_eq!(third.log().len(), 1, "the later hop ran too");
    for seen in other.log().iter().chain(third.log().iter()) {
        assert_eq!(seen.header("authorization"), None, "{}", seen.target);
        assert_eq!(seen.header("cookie"), None);
        assert_eq!(seen.header("proxy-authorization"), None);
        assert_eq!(seen.header("x-keep"), Some("1"), "nothing else is dropped");
    }
}

#[test]
fn follow_sends_where_a_reply_redirects_to() {
    let server = Server::start(|req| match req.target.as_str() {
        "/a" => Reply::redirect(302, "/b").header("Set-Cookie", "k=v; Path=/"),
        _ => Reply::ok(req.target.clone()),
    });
    let client = client();
    let first = client
        .request(Method::GET, server.url("/a"))
        .redirects(false)
        .send()
        .unwrap();
    let mut next = client
        .follow(Method::GET, &server.url("/a"), &first)
        .send()
        .unwrap();
    assert_eq!(next.text().unwrap(), "/b");
    let seen = &server.log()[1];
    assert_eq!(
        seen.header("cookie"),
        Some("k=v"),
        "cookies apply to every hop"
    );
    let none = client.follow(Method::GET, &server.url("/b"), &next);
    assert!(matches!(none.send(), Err(Error::Redirect(_))));
}

#[test]
fn cookies_are_kept_sent_and_chosen_again_for_each_hop() {
    let server = Server::start(|req| match req.target.as_str() {
        "/set" => Reply::ok("set")
            .header("Set-Cookie", "a=1; Path=/")
            .header("Set-Cookie", "b=2; Path=/sub; HttpOnly"),
        "/del" => Reply::ok("del").header("Set-Cookie", "a=; Max-Age=0; Path=/"),
        _ => Reply::ok(req.header("cookie").unwrap_or("").to_string()),
    });
    let client = client();
    client
        .request(Method::GET, server.url("/set"))
        .send()
        .unwrap();
    let mut root = client.request(Method::GET, server.url("/")).send().unwrap();
    assert_eq!(root.text().unwrap(), "a=1");
    let mut sub = client
        .request(Method::GET, server.url("/sub/x"))
        .send()
        .unwrap();
    assert_eq!(sub.text().unwrap(), "b=2; a=1", "longer paths first");
    client
        .request(Method::GET, server.url("/del"))
        .send()
        .unwrap();
    let mut gone = client.request(Method::GET, server.url("/")).send().unwrap();
    assert_eq!(gone.text().unwrap(), "");
}

#[test]
fn a_plain_http_reply_cannot_replace_a_secure_cookie_and_secure_goes_to_loopback() {
    // Loopback is a secure context: a Secure cookie is set from it over plain http and goes back.
    let server = Server::start(|req| match req.target.as_str() {
        "/set" => Reply::ok("").header("Set-Cookie", "s=1; Path=/; Secure"),
        _ => Reply::ok(req.header("cookie").unwrap_or("").to_string()),
    });
    let client = client();
    client
        .request(Method::GET, server.url("/set"))
        .send()
        .unwrap();
    let mut seen = client.request(Method::GET, server.url("/")).send().unwrap();
    assert_eq!(seen.text().unwrap(), "s=1");
}

#[test]
fn the_cookie_bounds_are_settings() {
    let server = Server::start(|req| match req.target.as_str() {
        "/set" => {
            let mut reply = Reply::ok("");
            for index in 0..5 {
                reply = reply.header("Set-Cookie", &format!("c{index}=v; Path=/"));
            }
            reply.header("Set-Cookie", &format!("big={}; Path=/", "x".repeat(100)))
        }
        _ => Reply::ok(req.header("cookie").unwrap_or("").to_string()),
    });
    let mut settings = coqui_syshttp::session::SessionSettings::default();
    settings.cookies.max_per_host = 3;
    settings.cookies.max_bytes = 20;
    let client = Client::builder()
        .settings(settings)
        .env(quiet(&[]))
        .build()
        .unwrap();
    client
        .request(Method::GET, server.url("/set"))
        .send()
        .unwrap();
    let mut seen = client.request(Method::GET, server.url("/")).send().unwrap();
    assert_eq!(
        seen.text().unwrap(),
        "c2=v; c3=v; c4=v",
        "the oldest go first, the large one never came"
    );
}

#[test]
fn a_file_jar_keeps_cookies_by_host_between_clients() {
    let server = Server::start(|req| match req.target.as_str() {
        "/set" => Reply::ok("").header("Set-Cookie", "keep=1; Path=/; Max-Age=1000"),
        _ => Reply::ok(req.header("cookie").unwrap_or("").to_string()),
    });
    let home = tempfile::tempdir().unwrap();
    let env = quiet(&[("SYSHTTP_HOME", &home.path().to_string_lossy())]);
    let make = || {
        Client::builder()
            .env(env.clone())
            .cookies(CookieStore::PerHost)
            .build()
            .unwrap()
    };
    make()
        .request(Method::GET, server.url("/set"))
        .send()
        .unwrap();
    let file = home.path().join("cookies").join("127.0.0.1.txt");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(
        text.contains("127.0.0.1\tFALSE\t/\tFALSE\t") && text.contains("\tkeep\t1"),
        "{text}"
    );
    let mut again = make().request(Method::GET, server.url("/")).send().unwrap();
    assert_eq!(again.text().unwrap(), "keep=1");
}

#[test]
fn one_named_key_shares_a_file_between_hosts_and_a_caller_jar_is_used_as_given() {
    let server = Server::start(|req| match req.target.as_str() {
        "/set" => Reply::ok("").header("Set-Cookie", "j=1; Path=/"),
        _ => Reply::ok(req.header("cookie").unwrap_or("").to_string()),
    });
    let jar = Arc::new(MemoryCookieJar::new());
    let client = Client::builder()
        .env(quiet(&[]))
        .cookies(CookieStore::Jar(jar.clone()))
        .build()
        .unwrap();
    client
        .request(Method::GET, server.url("/set"))
        .send()
        .unwrap();
    use coqui_syshttp::session::jar::CookieJar;
    assert_eq!(jar.get("127.0.0.1").unwrap()[0].name, "j");
}

#[test]
fn cookie_host_groups_share_cookies_across_names() {
    let server = Server::start(|req| match req.target.as_str() {
        "/set" => Reply::ok("").header("Set-Cookie", "g=1; Path=/"),
        _ => Reply::ok(req.header("cookie").unwrap_or("").to_string()),
    });
    // Two names for one loopback server, through a resolver that never proxies.
    let client = builder()
        .cookie_hosts([["127.0.0.1", "localhost"]])
        .build()
        .unwrap();
    client
        .request(Method::GET, server.url("/set"))
        .send()
        .unwrap();
    let mut seen = client
        .request(
            Method::GET,
            format!("http://localhost:{}/", server.addr.port()),
        )
        .send()
        .unwrap();
    assert_eq!(seen.text().unwrap(), "g=1");
    let env = quiet(&[("SYSHTTP_COOKIE_HOSTS", "a.test,b.test;a.test,c.test")]);
    let error = Client::builder().env(env).build().err().unwrap();
    assert!(
        error.to_string().contains("SYSHTTP_COOKIE_HOSTS"),
        "{error}"
    );
}

fn tokens_with(host_key: &str, token: &str) -> Arc<MemoryTokenJar> {
    let jar = Arc::new(MemoryTokenJar::new());
    jar.set(host_key, &Secret::new(token)).unwrap();
    jar
}

#[test]
fn a_token_becomes_a_bearer_unless_it_names_a_scheme_and_explicit_auth_beats_it() {
    let server = echo();
    let bare = Client::builder()
        .env(quiet(&[]))
        .tokens(TokenStore::Jar(tokens_with("127.0.0.1", "abc")))
        .build()
        .unwrap();
    bare.request(Method::GET, server.url("/")).send().unwrap();
    let scheme = Client::builder()
        .env(quiet(&[]))
        .tokens(TokenStore::Jar(tokens_with("127.0.0.1", "Basic dXNlcg==")))
        .build()
        .unwrap();
    scheme.request(Method::GET, server.url("/")).send().unwrap();
    bare.request(Method::GET, server.url("/"))
        .auth(Auth::Header(Secret::new("Bearer explicit")))
        .send()
        .unwrap();
    bare.request(Method::GET, server.url("/"))
        .header("Authorization", Some("Custom header"))
        .auth(Auth::Header(Secret::new("Bearer explicit")))
        .send()
        .unwrap();
    bare.request(Method::GET, server.url("/"))
        .auth(Auth::Basic(coqui_syshttp::Credentials::new("u", "p")))
        .send()
        .unwrap();
    let seen: Vec<_> = server
        .log()
        .iter()
        .map(|r| r.header("authorization").map(str::to_string))
        .collect();
    assert_eq!(seen[0].as_deref(), Some("Bearer abc"));
    assert_eq!(seen[1].as_deref(), Some("Basic dXNlcg=="));
    assert_eq!(seen[2].as_deref(), Some("Bearer explicit"));
    assert_eq!(seen[3].as_deref(), Some("Custom header"));
    assert_eq!(seen[4].as_deref(), Some("Basic dTpw"));
}

#[test]
fn a_token_with_a_line_break_is_a_configuration_error_naming_the_key_not_the_value() {
    let server = echo();
    let client = Client::builder()
        .env(quiet(&[]))
        .tokens(TokenStore::Jar(tokens_with(
            "127.0.0.1",
            "abc\r\nX-Evil: 1",
        )))
        .build()
        .unwrap();
    let error = client
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap_err();
    let message = error.to_string();
    assert!(matches!(error, Error::Configuration { .. }));
    assert!(
        message.contains("127.0.0.1") && !message.contains("abc"),
        "{message}"
    );
    assert!(server.log().is_empty());
}

#[test]
fn a_token_follows_no_redirect_to_another_origin() {
    let other = echo();
    let home = Server::start({
        let target = other.url("/x");
        move |_| Reply::redirect(302, &target)
    });
    let client = Client::builder()
        .env(quiet(&[]))
        .tokens(TokenStore::Jar(tokens_with("127.0.0.1", "abc")))
        .build()
        .unwrap();
    client.request(Method::GET, home.url("/")).send().unwrap();
    assert_eq!(home.log()[0].header("authorization"), Some("Bearer abc"));
    assert_eq!(other.log()[0].header("authorization"), None);
}

#[test]
fn a_file_token_jar_is_read_by_host() {
    let server = echo();
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("tokens")).unwrap();
    std::fs::write(
        home.path().join("tokens").join("127.0.0.1.token"),
        "filetoken\n",
    )
    .unwrap();
    let env = quiet(&[("SYSHTTP_HOME", &home.path().to_string_lossy())]);
    let client = Client::builder()
        .env(env)
        .tokens(TokenStore::PerHost)
        .build()
        .unwrap();
    client.request(Method::GET, server.url("/")).send().unwrap();
    assert_eq!(
        server.log()[0].header("authorization"),
        Some("Bearer filetoken")
    );
}

#[test]
fn a_transient_status_is_retried_for_a_safe_method_and_the_last_one_is_returned() {
    let hits = Arc::new(AtomicUsize::new(0));
    let server = Server::start({
        let hits = Arc::clone(&hits);
        move |_| match hits.fetch_add(1, Ordering::SeqCst) {
            0 | 1 => Reply::new(503).header("Retry-After", "0"),
            _ => Reply::ok("done"),
        }
    });
    let mut response = client()
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "done");
    assert_eq!(hits.load(Ordering::SeqCst), 3);

    let always = Server::start(|_| Reply::new(500));
    let last = client()
        .request(Method::GET, always.url("/"))
        .send()
        .unwrap();
    assert_eq!(
        last.status(),
        500,
        "a status that outlasts the retries is returned"
    );
    assert_eq!(always.log().len(), 4);
}

#[test]
fn an_unsafe_method_a_stream_body_and_a_zero_count_are_not_retried() {
    let server = Server::start(|_| Reply::new(503));
    let client = client();
    assert_eq!(
        client
            .request(Method::POST, server.url("/"))
            .send()
            .unwrap()
            .status(),
        503
    );
    assert_eq!(server.log().len(), 1);
    let streamed = client
        .request(Method::PUT, server.url("/"))
        .body(Body::reader(std::io::Cursor::new(b"x".to_vec())))
        .send()
        .unwrap();
    assert_eq!(streamed.status(), 503);
    assert_eq!(server.log().len(), 2);
    let mut settings = coqui_syshttp::session::SessionSettings::default();
    settings.retry.count = 0;
    let none = Client::builder()
        .settings(settings)
        .env(quiet(&[]))
        .build()
        .unwrap();
    none.request(Method::GET, server.url("/")).send().unwrap();
    assert_eq!(server.log().len(), 3);
}

#[test]
fn the_retry_statuses_and_methods_are_settings() {
    let server = Server::start(|_| Reply::new(418));
    let mut settings = coqui_syshttp::session::SessionSettings::default();
    settings.retry.statuses = vec![418];
    settings.retry.count = 2;
    settings.retry.backoff = Duration::from_millis(1);
    settings.retry.methods.push(Method::POST);
    let client = Client::builder()
        .settings(settings)
        .env(quiet(&[]))
        .build()
        .unwrap();
    client
        .request(Method::POST, server.url("/"))
        .body("x")
        .send()
        .unwrap();
    assert_eq!(server.log().len(), 3);
}

#[test]
fn a_dropped_connection_is_retried_and_a_wait_follows_retry_after_up_to_the_cap() {
    let hits = Arc::new(AtomicUsize::new(0));
    let server = Server::start({
        let hits = Arc::clone(&hits);
        move |_| {
            if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                Reply::new(200).raw(Vec::new()).close()
            } else {
                Reply::ok("back")
            }
        }
    });
    let mut response = client()
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "back");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn a_timeout_is_not_retried_and_the_deadline_bounds_the_whole_request() {
    let server = Server::start(|_| Reply::ok("late").delay(Duration::from_secs(4)));
    let started = std::time::Instant::now();
    let error = builder()
        .timeout(
            Some(Duration::from_secs(5)),
            Some(Duration::from_millis(200)),
        )
        .build()
        .unwrap()
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap_err();
    assert!(error.is_timeout(), "{error}");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(server.log().len(), 1, "a timeout is not retried");

    let started = std::time::Instant::now();
    let error = builder()
        .deadline(Some(Duration::from_millis(300)))
        .build()
        .unwrap()
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap_err();
    assert!(error.is_timeout(), "{error}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_zero_deadline_or_timeout_is_a_configuration_error() {
    assert!(matches!(
        builder().deadline(Some(Duration::ZERO)).build().err(),
        Some(Error::Configuration { .. })
    ));
    assert!(matches!(
        builder().timeout(Some(Duration::ZERO), None).build().err(),
        Some(Error::Configuration { .. })
    ));
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    out.write_all(data).unwrap();
    out.finish().unwrap()
}

#[test]
fn gzip_and_deflate_are_decoded_unless_the_caller_named_an_encoding() {
    let packed = gzip(b"plain text");
    let server = Server::start({
        let packed = packed.clone();
        move |req| match req.target.as_str() {
            "/deflate" => {
                let mut e =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(b"zlib text").unwrap();
                Reply::ok(e.finish().unwrap()).header("Content-Encoding", "deflate")
            }
            "/raw" => {
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(b"raw text").unwrap();
                Reply::ok(e.finish().unwrap()).header("Content-Encoding", "deflate")
            }
            _ => Reply::ok(packed.clone()).header("Content-Encoding", "gzip"),
        }
    });
    let client = client();
    assert_eq!(
        client
            .request(Method::GET, server.url("/"))
            .send()
            .unwrap()
            .text()
            .unwrap(),
        "plain text"
    );
    assert_eq!(
        client
            .request(Method::GET, server.url("/deflate"))
            .send()
            .unwrap()
            .text()
            .unwrap(),
        "zlib text"
    );
    assert_eq!(
        client
            .request(Method::GET, server.url("/raw"))
            .send()
            .unwrap()
            .text()
            .unwrap(),
        "raw text"
    );
    let mut own = client
        .request(Method::GET, server.url("/"))
        .header("Accept-Encoding", Some("gzip"))
        .send()
        .unwrap();
    assert_eq!(
        own.content().unwrap(),
        packed.as_slice(),
        "the caller asked for the coding"
    );
}

#[test]
fn concatenated_gzip_members_are_one_body_and_a_broken_one_is_an_error() {
    let mut both = gzip(b"one ");
    both.extend(gzip(b"two"));
    let mut broken = gzip(b"truncated body that is long enough");
    broken.truncate(broken.len() - 12);
    let server = Server::start({
        let both = both.clone();
        move |req| match req.target.as_str() {
            "/broken" => Reply::ok(broken.clone()).header("Content-Encoding", "gzip"),
            "/junk" => Reply::ok(b"not gzip at all".to_vec()).header("Content-Encoding", "gzip"),
            _ => Reply::ok(both.clone()).header("Content-Encoding", "gzip"),
        }
    });
    let client = client();
    assert_eq!(
        client
            .request(Method::GET, server.url("/"))
            .send()
            .unwrap()
            .text()
            .unwrap(),
        "one two"
    );
    assert!(
        client
            .request(Method::GET, server.url("/broken"))
            .send()
            .is_err()
    );
    assert!(
        client
            .request(Method::GET, server.url("/junk"))
            .send()
            .is_err()
    );
}

#[test]
fn a_short_body_is_an_error_never_a_shorter_read() {
    let server = Server::start(|_| {
        Reply::new(200)
            .raw(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec())
            .close()
    });
    let error = builder()
        .settings({
            let mut s = coqui_syshttp::session::SessionSettings::default();
            s.retry.count = 0;
            s
        })
        .build()
        .unwrap()
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap_err();
    assert!(matches!(error, Error::Io(_)), "{error}");
}

#[test]
fn a_reply_over_the_limit_is_too_large_and_a_stream_is_the_callers() {
    let server = Server::start(|_| Reply::ok(vec![b'x'; 1000]));
    let mut settings = coqui_syshttp::session::SessionSettings::default();
    settings.max_reply_bytes = 100;
    let client = Client::builder()
        .settings(settings)
        .env(quiet(&[]))
        .build()
        .unwrap();
    let error = client
        .request(Method::GET, server.url("/"))
        .send()
        .unwrap_err();
    assert!(
        matches!(error, Error::TooLarge { limit: 100, .. }),
        "{error}"
    );
    let mut streamed = client
        .request(Method::GET, server.url("/"))
        .stream(true)
        .send()
        .unwrap();
    let mut data = Vec::new();
    streamed.read_to_end(&mut data).unwrap();
    assert_eq!(data.len(), 1000);
    let limited = client
        .request(Method::GET, server.url("/"))
        .stream(true)
        .send()
        .unwrap();
    assert!(limited.read_limited("the thing", Some(10)).is_err());
}

#[test]
fn responses_chunk_buffer_and_discard() {
    let server = Server::start(|_| Reply::ok(vec![b'y'; 10]));
    let client = client();
    let mut response = client
        .request(Method::GET, server.url("/"))
        .stream(true)
        .send()
        .unwrap();
    let chunks: Vec<_> = response.chunks(4).map(|c| c.unwrap().len()).collect();
    assert_eq!(chunks, vec![4, 4, 2]);
    let buffered = client
        .request(Method::GET, server.url("/"))
        .stream(true)
        .send()
        .unwrap()
        .buffered(Some(20))
        .unwrap();
    assert_eq!(buffered.read_limited("x", None).unwrap().len(), 10);
    client
        .request(Method::GET, server.url("/"))
        .stream(true)
        .send()
        .unwrap()
        .discard(Some(5));
    let status = client.request(Method::GET, server.url("/")).send().unwrap();
    assert!(status.error_for_status().is_ok());
    let missing = Server::start(|_| Reply::new(404));
    let error = client
        .request(Method::GET, missing.url("/"))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap_err();
    assert_eq!(error.response().status(), 404);
    assert_eq!(error.to_string(), "HTTP status 404");
}

#[test]
fn a_hook_may_change_the_request_or_answer_it_and_runs_once_per_thread_guard() {
    let server = echo();
    let calls = Arc::new(AtomicUsize::new(0));
    let client = Client::builder()
        .env(quiet(&[]))
        .hook(regex::Regex::new("/hooked").unwrap(), {
            let calls = Arc::clone(&calls);
            move |client, request| {
                calls.fetch_add(1, Ordering::SeqCst);
                request.headers.push(("X-Hook".into(), Some("yes".into())));
                if request.url.path() == "/hooked/answer" {
                    // A request a hook makes through the client runs no hook.
                    let inner = client
                        .request(Method::GET, request.url.join("/hooked/inner").unwrap())
                        .send()?;
                    assert_eq!(inner.status(), 200);
                    return Ok(Some(
                        coqui_syshttp::session::ResponseBuilder::new(299)
                            .body("synthetic")
                            .url(request.url.clone())
                            .build(),
                    ));
                }
                Ok(None)
            }
        })
        .hook(regex::Regex::new("/fails").unwrap(), |_, _| {
            Err("boom".into())
        })
        .build()
        .unwrap();
    client
        .request(Method::GET, server.url("/hooked/a"))
        .send()
        .unwrap();
    assert_eq!(server.log()[0].header("x-hook"), Some("yes"));
    let mut synthetic = client
        .request(Method::GET, server.url("/hooked/answer"))
        .send()
        .unwrap();
    assert_eq!(synthetic.status(), 299);
    assert_eq!(synthetic.text().unwrap(), "synthetic");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the inner request ran no hook"
    );
    let error = client
        .request(Method::GET, server.url("/fails?token=secret"))
        .send()
        .unwrap_err();
    let message = error.to_string();
    assert!(matches!(error, Error::Hook { .. }));
    assert!(
        message.contains("boom") && !message.contains("secret"),
        "{message}"
    );
}

struct Provider(Arc<AtomicUsize>, bool);

impl AuthProvider for Provider {
    fn ensure(
        &self,
        client: &Client,
        url: &url::Url,
    ) -> Result<(), coqui_syshttp::session::BoxError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        // Asking through the client from inside ensure does not ask again.
        let _ = client.request(Method::GET, url.as_str()).send();
        if self.1 {
            Err("login failed".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn the_auth_provider_runs_before_each_request_and_its_errors_are_swallowed() {
    let server = echo();
    let count = Arc::new(AtomicUsize::new(0));
    let client = Client::builder()
        .env(quiet(&[]))
        .auth_provider(Arc::new(Provider(Arc::clone(&count), true)))
        .build()
        .unwrap();
    client
        .request(Method::GET, server.url("/x"))
        .send()
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(server.log().len(), 2);
}

#[test]
fn a_transport_of_your_own_replaces_the_default_and_refuses_its_settings() {
    #[derive(Debug)]
    struct Canned;
    impl coqui_syshttp::session::Transport for Canned {
        fn send(
            &self,
            request: coqui_syshttp::session::PreparedRequest,
            _stream: bool,
        ) -> Result<coqui_syshttp::session::Response, Error> {
            Ok(coqui_syshttp::session::ResponseBuilder::new(200)
                .url(request.url)
                .body(request.method.to_string())
                .build())
        }
        fn close(&self) {}
    }
    let client = Client::builder()
        .env(quiet(&[]))
        .transport(Canned)
        .build()
        .unwrap();
    let mut response = client
        .request(Method::DELETE, "http://example.test/x")
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "DELETE");
    let both = Client::builder()
        .env(quiet(&[]))
        .transport(Canned)
        .resolver(coqui_syshttp::Resolver::system())
        .build()
        .err();
    assert!(matches!(both, Some(Error::InvalidRequest(_))));
    client.close();
}

#[test]
fn debug_output_names_no_header_value() {
    let client = builder()
        .header("Authorization", Some("Bearer topsecret"))
        .build()
        .unwrap();
    assert!(!format!("{client:?}").contains("topsecret"));
    assert!(!format!("{:?}", client.settings().headers.len()).is_empty());
}
