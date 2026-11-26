//! Headers, responses, hooks from the environment, retries' header, userinfo and `fetch`.
#![cfg(feature = "session")]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use coqui_syshttp::Secret;
use coqui_syshttp::session::hooks::{
    self, HookKind, curl_command, from_env, matching, skipped, split_command, wrapper_environment,
};
use coqui_syshttp::session::jar::{MemoryTokenJar, TokenJar};
use coqui_syshttp::session::{
    AuthProvider, Body, Client, Error, Headers, HttpEnv, ResponseBuilder, TextErrors, TokenStore,
    fetch, peer_text, retry_after, split_userinfo,
};
use support::http_server::{Reply, Req, Server};
use ureq::http::Method;

fn env(pairs: &[(&str, &str)]) -> HttpEnv {
    HttpEnv::builder()
        .environment(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
        .build()
        .unwrap()
}

fn quiet() -> HttpEnv {
    env(&[("SYSHTTP_SYSTEM_PROXY", "off")])
}

#[test]
fn headers_are_case_blind_ordered_and_show_no_value() {
    let headers = Headers::from_pairs([("Set-Cookie", "a=1"), ("X-A", "x"), ("set-cookie", "b=2")]);
    assert_eq!(headers.get("SET-COOKIE").as_deref(), Some("a=1, b=2"));
    assert_eq!(headers.get_all("set-cookie"), vec!["a=1", "b=2"]);
    assert_eq!(headers.len(), 2);
    assert_eq!(headers.keys(), vec!["Set-Cookie", "X-A"]);
    assert!(headers.contains("x-a") && !headers.contains("x-b"));
    assert_eq!(headers.get("missing"), None);
    let shown = format!("{headers:?}");
    assert!(
        shown.contains("Set-Cookie") && !shown.contains("a=1"),
        "{shown}"
    );
    let mut changed = headers.clone();
    changed.insert("x-a", "y");
    changed.remove("SET-COOKIE");
    assert_eq!(changed.iter().collect::<Vec<_>>(), vec![("x-a", "y")]);
}

#[test]
fn retry_after_reads_seconds_and_dates() {
    let now = UNIX_EPOCH + Duration::from_secs(784_111_777);
    let with = |value: &str| Headers::from_pairs([("Retry-After", value)]);
    assert_eq!(
        retry_after(&with(" 120 "), now),
        Some(Duration::from_secs(120))
    );
    assert_eq!(
        retry_after(&with("Sun, 06 Nov 1994 08:50:37 GMT"), now),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        retry_after(&with("Sun, 06 Nov 1994 08:00:00 GMT"), now),
        Some(Duration::ZERO),
        "a date in the past is no wait"
    );
    assert_eq!(retry_after(&with("soon"), now), None);
    assert_eq!(retry_after(&with("-5"), now), None);
    assert_eq!(retry_after(&Headers::new(), now), None);
}

#[test]
fn peer_text_escapes_what_a_terminal_would_act_on_and_cuts() {
    assert_eq!(
        peer_text("OK\r\nSet-Cookie: x", 120),
        "OK\\r\\nSet-Cookie: x"
    );
    assert_eq!(peer_text("a\u{1b}[31mb", 120), "a\\x1b[31mb");
    assert_eq!(peer_text("a\u{202e}b\u{2028}", 120), "a\\u202eb\\u2028");
    assert_eq!(peer_text("abcdef", 3), "abc...");
    assert_eq!(peer_text("abc", 3), "abc");
}

#[test]
fn split_userinfo_takes_credentials_out_of_the_url() {
    let (url, auth) = split_userinfo("https://us%40er:p%3Aw@host.test:8080/p?q=1#f");
    assert_eq!(url, "https://host.test:8080/p?q=1#f");
    let (user, password) = auth.unwrap();
    assert_eq!(user, "us@er");
    assert_eq!(password.expose(), "p:w");
    assert_eq!(
        split_userinfo("http://host.test/a@b").0,
        "http://host.test/a@b"
    );
    assert!(split_userinfo("http://host.test/a@b").1.is_none());
    assert!(
        split_userinfo("http://@host.test/").1.is_none(),
        "empty userinfo is none"
    );
    let (kept, none) = split_userinfo("not a url");
    assert_eq!((kept.as_str(), none.is_none()), ("not a url", true));
    assert_eq!(split_userinfo("http://u@h/").1.unwrap().0, "u");
}

#[test]
fn a_response_is_built_from_parts_and_decodes_text() {
    let latin = ResponseBuilder::new(200)
        .headers(Headers::from_pairs([(
            "Content-Type",
            "text/plain; charset=\"ISO-8859-1\"",
        )]))
        .body(vec![0x63, 0x61, 0x66, 0xe9])
        .build();
    let mut latin = latin;
    assert_eq!(latin.text().unwrap(), "café");
    let mut bad = ResponseBuilder::new(200)
        .body(vec![b'a', 0xff, b'b'])
        .build();
    assert_eq!(
        bad.text_with(None, TextErrors::Replace).unwrap(),
        "a\u{fffd}b"
    );
    assert_eq!(bad.text_with(None, TextErrors::Ignore).unwrap(), "ab");
    assert!(bad.text_with(None, TextErrors::Strict).is_err());
    assert_eq!(
        bad.text_with(Some("latin1"), TextErrors::Strict).unwrap(),
        "aÿb"
    );
    let mut unknown = ResponseBuilder::new(200)
        .headers(Headers::from_pairs([(
            "Content-Type",
            "text/plain; charset=nonsense",
        )]))
        .body("plain")
        .build();
    assert_eq!(
        unknown.text().unwrap(),
        "plain",
        "an unknown charset is UTF-8"
    );
    let mut content = ResponseBuilder::new(204).build();
    assert_eq!(content.content().unwrap(), b"");
    assert_eq!(content.status(), 204);
}

#[test]
fn a_built_response_decodes_in_bounded_steps_and_honours_its_limits() {
    use std::io::Write;
    let big = vec![b'z'; 50_000];
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&big).unwrap();
    let packed = encoder.finish().unwrap();
    assert!(packed.len() < 1000);
    let headers = Headers::from_pairs([("Content-Encoding", "gzip")]);
    let mut stepped = ResponseBuilder::new(200)
        .headers(headers.clone())
        .body(packed.clone())
        .decode_chunk(1000)
        .build();
    let sizes: Vec<usize> = stepped
        .chunks(1_000_000)
        .map(|c| c.unwrap().len())
        .collect();
    assert!(sizes.iter().all(|size| *size <= 1000), "{sizes:?}");
    assert_eq!(sizes.iter().sum::<usize>(), 50_000);
    let limited = ResponseBuilder::new(200)
        .headers(headers.clone())
        .body(packed.clone())
        .max_reply_bytes(10_000)
        .build();
    assert!(matches!(
        limited.buffered(None),
        Err(Error::TooLarge { .. })
    ));
    let raw = ResponseBuilder::new(200)
        .headers(headers)
        .body(packed.clone())
        .decode(false)
        .build();
    assert_eq!(raw.read_limited("x", None).unwrap(), packed);
}

#[cfg(feature = "json")]
#[test]
fn json_reads_a_body_and_names_the_status_when_it_is_not_json() {
    let mut good = ResponseBuilder::new(200).body(r#"{"a":[1,2]}"#).build();
    let value: serde_json::Value = good.json().unwrap();
    assert_eq!(value["a"][1], 2);
    let mut empty = ResponseBuilder::new(204).build();
    assert!(empty.json::<Option<u8>>().unwrap().is_none());
    let mut bad = ResponseBuilder::new(502).body("<html>").build();
    let error = bad.json::<serde_json::Value>().unwrap_err();
    assert!(matches!(error, Error::Response { status: 502 }));
    assert_eq!(error.to_string(), "response was not valid JSON (HTTP 502)");
    let limited = ResponseBuilder::new(200).body("[1,2,3]").build();
    assert!(
        limited
            .json_limited::<Vec<u8>>("the list", Some(3))
            .is_err()
    );
}

#[test]
fn hooks_come_from_the_environment_in_key_order_upper_cased() {
    let environment = env(&[
        ("SYSHTTP_HOOKS_b", "b\\.test"),
        ("SYSHTTP_HOOKS_b_CURL", "wrap-b --flag"),
        ("SYSHTTP_HOOKS_A", "a\\.test"),
        ("SYSHTTP_HOOKS_A_CURL", "wrap-a"),
        ("SYSHTTP_HOOKS_A_PY", "module:attr"),
        ("SYSHTTP_HOOKS_ONLYPY", "x"),
        ("SYSHTTP_HOOKS_ONLYPY_PY", "module:attr"),
        ("SYSHTTP_HOOKS_ORPHAN_CURL", "nothing"),
        ("SYSHTTP_HOOKS_BLANK", "x"),
        ("SYSHTTP_HOOKS_BLANK_CURL", "  "),
    ]);
    let found = from_env(&environment).unwrap();
    let keys: Vec<_> = found.iter().map(|hook| hook.key.as_str()).collect();
    assert_eq!(keys, ["A", "B"]);
    assert_eq!(found[1].curl.as_deref(), Some("wrap-b --flag"));
    assert_eq!(found[0].variable.as_deref(), Some("SYSHTTP_HOOKS_A"));
    assert!(found[0].matches("http://a.test/x") && !found[0].matches("http://b.test/"));
}

#[test]
fn a_pattern_that_does_not_compile_is_a_configuration_error_naming_the_variable() {
    let bad = env(&[
        ("SYSHTTP_HOOKS_X", "(unclosed"),
        ("SYSHTTP_HOOKS_X_CURL", "wrap"),
    ]);
    let error = from_env(&bad).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("SYSHTTP_HOOKS_X") && !message.contains("unclosed"),
        "{message}"
    );
}

#[test]
fn skipped_keys_and_kinds_filter_what_matches() {
    let environment = env(&[
        ("SYSHTTP_HOOKS_ONE", "example"),
        ("SYSHTTP_HOOKS_ONE_CURL", "one"),
        ("SYSHTTP_HOOKS_TWO", "example"),
        ("SYSHTTP_HOOKS_TWO_CURL", "two"),
        ("SYSHTTP_HOOK_SKIP", " one , x "),
    ]);
    assert_eq!(
        skipped(&environment).into_iter().collect::<Vec<_>>(),
        ["ONE", "X"]
    );
    let found = matching(&environment, "http://example.test/", None).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].key, "TWO");
    assert_eq!(
        matching(&environment, "http://example.test/", Some(HookKind::Curl))
            .unwrap()
            .len(),
        1
    );
    assert!(
        matching(&environment, "http://other.test/", None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_command_line_is_split_with_quotes_and_literal_backslashes() {
    assert_eq!(split_command("cmd fetch --"), ["cmd", "fetch", "--"]);
    assert_eq!(
        split_command(r#"'my prog' "two words" plain"#),
        ["my prog", "two words", "plain"]
    );
    assert_eq!(
        split_command(r"C:\Tools\wrap.exe -x"),
        [r"C:\Tools\wrap.exe", "-x"]
    );
    assert_eq!(split_command("a #not-a-comment"), ["a", "#not-a-comment"]);
    assert_eq!(split_command("a '' b"), ["a", "", "b"]);
    assert!(split_command("   ").is_empty());
}

#[test]
fn a_curl_target_is_a_program_a_path_or_a_python_file() {
    let directory = tempfile::tempdir().unwrap();
    let spaced = directory.path().join("my wrapper.py");
    std::fs::write(&spaced, "").unwrap();
    let hook = |curl: &str| {
        let environment = env(&[("SYSHTTP_HOOKS_H", "."), ("SYSHTTP_HOOKS_H_CURL", curl)]);
        from_env(&environment).unwrap().remove(0)
    };
    assert_eq!(
        curl_command(&hook("wrap run --"), None).unwrap(),
        ["wrap", "run", "--"]
    );
    let path = spaced.to_string_lossy().to_string();
    assert_eq!(
        curl_command(&hook(&path), Some(std::path::Path::new("py"))).unwrap(),
        ["py".to_string(), path.clone()]
    );
    let quoted = format!("'{path}' arg");
    assert_eq!(curl_command(&hook(&quoted), None).unwrap()[0], "python");
    let mut empty = hook("x");
    empty.curl = Some("   ".into());
    assert!(matches!(
        curl_command(&empty, None),
        Err(Error::Configuration { .. })
    ));
}

#[test]
fn a_wrapper_gets_the_url_the_key_the_front_end_and_the_skip_list_under_the_first_prefix() {
    let environment = env(&[
        ("SYSHTTP_PREFIX", "T_:"),
        ("T_SYSHTTP_HOOKS_K", "."),
        ("T_SYSHTTP_HOOKS_K_CURL", "wrap"),
        ("SYSHTTP_HOOK_SKIP", "OTHER"),
    ]);
    let hook = from_env(&environment).unwrap().remove(0);
    let given = wrapper_environment(&hook, "http://x.test/", "curl-front", &environment).unwrap();
    assert_eq!(given["T_SYSHTTP_HOOK_URL"], "http://x.test/");
    assert_eq!(given["T_SYSHTTP_HOOK_KEY"], "K");
    assert_eq!(given["T_SYSHTTP_HOOK_CURL"], "curl-front");
    assert_eq!(given["T_SYSHTTP_HOOK_SKIP"], "K,OTHER");
    assert_eq!(hooks::HOOK_URL, "SYSHTTP_HOOK_URL");
}

#[test]
fn fetch_reads_the_whole_body_whatever_the_status_and_sends_json_or_a_form() {
    let server = Server::start(|req: &Req| {
        Reply::new(if req.target == "/missing" { 404 } else { 200 }).body(format!(
            "{} {} {}",
            req.method,
            req.header("content-type").unwrap_or("-"),
            String::from_utf8_lossy(&req.body)
        ))
    });
    let options = || Client::builder().env(quiet());
    let mut missing = fetch(server.url("/missing"))
        .client_options(options())
        .send()
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert!(missing.text().unwrap().starts_with("GET"));
    let mut form = fetch(server.url("/f"))
        .method(Method::POST)
        .form([("a", "1 2"), ("b", "é")])
        .client_options(options())
        .send()
        .unwrap();
    assert_eq!(
        form.text().unwrap(),
        "POST application/x-www-form-urlencoded a=1+2&b=%C3%A9"
    );
    let mut text = fetch(server.url("/t"))
        .method(Method::PUT)
        .body("raw")
        .header("Content-Type", Some("text/plain"))
        .client_options(options())
        .send()
        .unwrap();
    assert_eq!(text.text().unwrap(), "PUT text/plain raw");
}

#[cfg(feature = "json")]
#[test]
fn fetch_json_sets_the_content_type_and_refuses_a_second_body() {
    let server = Server::start(|req| {
        Reply::ok(format!(
            "{} {}",
            req.header("content-type").unwrap_or("-"),
            String::from_utf8_lossy(&req.body)
        ))
    });
    let mut sent = fetch(server.url("/"))
        .method(Method::POST)
        .json(&serde_json::json!({"k": [1, null]}))
        .client_options(Client::builder().env(quiet()))
        .send()
        .unwrap();
    assert_eq!(sent.text().unwrap(), r#"application/json {"k":[1,null]}"#);
    let both = fetch(server.url("/"))
        .json(&1)
        .form([("a", "b")])
        .client_options(Client::builder().env(quiet()))
        .send();
    assert!(matches!(both, Err(Error::Configuration { .. })));
}

#[test]
fn fetch_refuses_a_client_beside_a_transport_or_options_and_reauth_beside_a_stream() {
    let client = Client::builder().env(quiet()).build().unwrap();
    let both = fetch("http://127.0.0.1:9/")
        .client(&client)
        .client_options(Client::builder())
        .send();
    assert!(matches!(both, Err(Error::Configuration { .. })));
    struct Nothing;
    impl AuthProvider for Nothing {
        fn ensure(&self, _: &Client, _: &url::Url) -> Result<(), coqui_syshttp::session::BoxError> {
            Ok(())
        }
    }
    let streamed = fetch("http://127.0.0.1:9/")
        .body(Body::reader(std::io::Cursor::new(vec![1])))
        .reauth(Arc::new(Nothing))
        .client(&client)
        .send();
    assert!(matches!(streamed, Err(Error::Configuration { .. })));
}

#[test]
fn reauth_runs_once_after_a_401_or_403_and_sends_again() {
    let server = Server::start(|req| {
        if req.header("authorization") == Some("Bearer fresh") {
            Reply::ok("in")
        } else {
            Reply::new(401)
        }
    });
    let tokens = Arc::new(MemoryTokenJar::new());
    let calls = Arc::new(AtomicUsize::new(0));
    struct Login(Arc<MemoryTokenJar>, Arc<AtomicUsize>);
    impl AuthProvider for Login {
        fn ensure(
            &self,
            _: &Client,
            url: &url::Url,
        ) -> Result<(), coqui_syshttp::session::BoxError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            let key = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
            self.0.set(&key, &Secret::new("fresh"))?;
            Ok(())
        }
    }
    let client = Client::builder()
        .env(quiet())
        .tokens(TokenStore::Jar(tokens.clone()))
        .build()
        .unwrap();
    let mut response = fetch(server.url("/"))
        .client(&client)
        .reauth(Arc::new(Login(tokens.clone(), calls.clone())))
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().unwrap(), "in");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.log().len(), 2);
}
