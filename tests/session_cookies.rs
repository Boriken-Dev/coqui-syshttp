//! Cookie parsing, matching and the Netscape file.
#![cfg(feature = "session")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coqui_syshttp::Secret;
use coqui_syshttp::session::cookies::{
    Cookie, CookieLike, HostAliases, SetCookieContext, domain_covers, load_netscape,
    parse_set_cookie, save_netscape,
};
use proptest::prelude::*;
use url::Url;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

const NOW: u64 = 1_700_000_000;

fn parse(headers: &[&str], host: &str) -> Vec<(Cookie, bool)> {
    parse_set_cookie(headers, host, &SetCookieContext::new().now(at(NOW)))
}

fn one(header: &str, host: &str) -> (Cookie, bool) {
    let mut found = parse(&[header], host);
    assert_eq!(found.len(), 1, "{header}");
    found.remove(0)
}

fn cookie(domain: &str, subdomains: bool, path: &str, secure: bool) -> Cookie {
    Cookie {
        domain: domain.into(),
        path: path.into(),
        secure,
        expires: None,
        name: "n".into(),
        value: Secret::new("v"),
        http_only: false,
        subdomains,
    }
}

fn url(text: &str) -> Url {
    Url::parse(text).unwrap()
}

#[test]
fn a_plain_cookie_is_host_only_with_the_directory_of_the_request() {
    let (cookie, gone) = parse_set_cookie(
        ["a=b"],
        "Www.Example.test",
        &SetCookieContext::new()
            .now(at(NOW))
            .request_path("/app/page?x=1"),
    )
    .remove(0);
    assert!(!gone);
    assert_eq!(cookie.domain, "www.example.test");
    assert!(!cookie.subdomains);
    assert_eq!(cookie.path, "/app");
    assert_eq!(cookie.value.expose(), "b");
    assert_eq!(cookie.expires, None);
}

#[test]
fn the_default_path_of_a_root_request_is_the_root() {
    assert_eq!(one("a=b", "h.test").0.path, "/");
    let nested = parse_set_cookie(
        ["a=b"],
        "h.test",
        &SetCookieContext::new().request_path("/x"),
    );
    assert_eq!(nested[0].0.path, "/");
}

#[test]
fn a_domain_attribute_covers_subdomains_when_the_host_matches_it() {
    let (cookie, _) = one(
        "a=b; Domain=.example.test; Path=/p; Secure; HttpOnly",
        "www.example.test",
    );
    assert_eq!(cookie.domain, "example.test");
    assert!(cookie.subdomains && cookie.secure && cookie.http_only);
    assert_eq!(cookie.path, "/p");
}

#[test]
fn a_domain_the_host_is_not_under_is_dropped() {
    assert!(parse(&["a=b; Domain=other.test"], "www.example.test").is_empty());
    assert!(parse(&["a=b; Domain=ample.test"], "www.example.test").is_empty());
    assert!(parse(&["a=b; Domain=a..test"], "x.a..test").is_empty());
}

#[test]
fn a_public_suffix_domain_is_refused_unless_it_is_the_host() {
    assert!(parse(&["a=b; Domain=test"], "www.example.test").is_empty());
    assert!(parse(&["a=b; Domain=co.uk"], "www.example.co.uk").is_empty());
    let (cookie, _) = one("a=b; Domain=localhost", "localhost");
    assert_eq!(cookie.domain, "localhost");
    assert!(
        !cookie.subdomains,
        "a public suffix that is the host is host-only"
    );
}

#[test]
fn an_ip_host_gets_a_host_only_cookie_and_only_its_own_domain() {
    let (cookie, _) = one("a=b", "127.0.0.1");
    assert_eq!(
        (cookie.domain.as_str(), cookie.subdomains),
        ("127.0.0.1", false)
    );
    assert!(parse(&["a=b; Domain=0.0.1"], "127.0.0.1").is_empty());
    assert_eq!(
        one("a=b; Domain=127.0.0.1", "127.0.0.1").0.domain,
        "127.0.0.1"
    );
    assert!(parse(&["a=b; Domain=10.0.0.1"], "www.example.test").is_empty());
}

#[test]
fn max_age_beats_expires_whatever_the_order() {
    let expires = "Expires=Sun, 06 Nov 2033 08:49:37 GMT";
    let (first, _) = one(&format!("a=b; Max-Age=60; {expires}"), "h.test");
    let (second, _) = one(&format!("a=b; {expires}; Max-Age=60"), "h.test");
    assert_eq!(first.expires, Some(at(NOW + 60)));
    assert_eq!(second.expires, Some(at(NOW + 60)));
}

#[test]
fn an_expiry_in_the_past_or_a_non_positive_max_age_deletes() {
    assert!(one("a=b; Max-Age=0", "h.test").1);
    assert!(one("a=b; Max-Age=-5", "h.test").1);
    assert!(one("a=b; Expires=Thu, 01 Jan 1970 00:00:01 GMT", "h.test").1);
    assert!(one("a=", "h.test").1, "an empty value deletes");
    assert!(!one("a=b; Max-Age=1", "h.test").1);
}

#[test]
fn an_expiry_beyond_the_cap_is_cut_to_it() {
    let (cookie, _) = one("a=b; Max-Age=99999999999", "h.test");
    assert_eq!(cookie.expires, Some(at(NOW + 400 * 24 * 3600)));
    let capped = parse_set_cookie(
        ["a=b; Max-Age=1000"],
        "h.test",
        &SetCookieContext::new()
            .now(at(NOW))
            .max_age(Duration::from_secs(10)),
    );
    assert_eq!(capped[0].0.expires, Some(at(NOW + 10)));
}

#[test]
fn a_header_with_a_control_character_or_no_name_is_ignored() {
    assert!(parse(&["a=b\x01c"], "h.test").is_empty());
    assert!(parse(&["a=b\nSet-Cookie: x=y"], "h.test").is_empty());
    assert!(parse(&["=value"], "h.test").is_empty());
    assert!(parse(&["novalue"], "h.test").is_empty());
    assert_eq!(parse(&["a=b\tc"], "h.test").len(), 1, "a tab is allowed");
}

#[test]
fn attribute_names_and_spaces_follow_rfc_6265() {
    let (cookie, _) = one(" a = b ;PATH=/x;  SECURE ; httponly", "h.test");
    assert_eq!((cookie.name.as_str(), cookie.value.expose()), ("a", "b"));
    assert_eq!(cookie.path, "/x");
    assert!(cookie.secure && cookie.http_only);
}

#[test]
fn a_path_that_does_not_start_with_a_slash_is_the_default() {
    let parsed = parse_set_cookie(
        ["a=b; Path=relative"],
        "h.test",
        &SetCookieContext::new().request_path("/dir/file"),
    );
    assert_eq!(parsed[0].0.path, "/dir");
}

#[test]
fn aliased_hosts_share_one_first_host() {
    let aliases = HostAliases::new([["a.test", "b.test"]]).unwrap();
    let context = SetCookieContext::new().now(at(NOW)).aliases(aliases);
    let from_b = parse_set_cookie(["x=1"], "b.test", &context);
    assert_eq!(from_b[0].0.domain, "a.test");
    let named = parse_set_cookie(["x=1; Domain=b.test"], "b.test", &context);
    assert_eq!(named[0].0.domain, "a.test");
    assert!(
        named[0].0.subdomains,
        "the group's first host as Domain covers subdomains"
    );
    let outside = parse_set_cookie(["x=1; Domain=c.test"], "b.test", &context);
    assert!(outside.is_empty(), "a foreign domain is judged on the host");
}

#[test]
fn host_aliases_refuse_what_is_not_a_host_and_a_host_in_two_groups() {
    assert!(HostAliases::new([["a.test:80", "b.test"]]).is_err());
    assert!(HostAliases::new([["a.test/path", "b.test"]]).is_err());
    assert!(HostAliases::new([["a.test", "b.test"], ["b.test", "c.test"]]).is_err());
    assert!(HostAliases::new([[" ", "b.test"]]).is_err());
    assert!(
        HostAliases::new([["a.test"]]).unwrap().is_empty(),
        "one host is no alias"
    );
    let ip = HostAliases::new([["[::1]", "Localhost."]]).unwrap();
    assert_eq!(ip.first("localhost"), Some("::1"));
    assert_eq!(
        HostAliases::parse("a.test,b.test;c.test,d.test")
            .unwrap()
            .first("d.test"),
        Some("c.test")
    );
}

#[test]
fn domain_covers_the_host_and_with_a_dot_its_subdomains() {
    assert!(domain_covers("example.test", "example.test"));
    assert!(domain_covers(".example.test", "www.example.test"));
    assert!(domain_covers(".example.test", "EXAMPLE.test"));
    assert!(!domain_covers("example.test", "www.example.test"));
    assert!(!domain_covers(".example.test", "badexample.test"));
    assert!(!domain_covers("", "x"));
}

#[test]
fn matching_follows_domain_path_scheme_and_expiry() {
    let now = at(NOW);
    let host_only = cookie("example.test", false, "/admin", false);
    assert!(host_only.applies_to(&url("http://example.test/admin"), now));
    assert!(host_only.applies_to(&url("http://example.test/admin/x"), now));
    assert!(!host_only.applies_to(&url("http://example.test/adminx"), now));
    assert!(!host_only.applies_to(&url("http://www.example.test/admin"), now));

    let wide = cookie("example.test", true, "/", false);
    assert!(wide.applies_to(&url("http://www.example.test/"), now));
    assert!(!wide.applies_to(&url("http://badexample.test/"), now));

    let secure = cookie("example.test", false, "/", true);
    assert!(!secure.applies_to(&url("http://example.test/"), now));
    assert!(secure.applies_to(&url("https://example.test/"), now));

    let mut expiring = cookie("example.test", false, "/", false);
    expiring.expires = Some(at(NOW + 5));
    assert!(expiring.applies_to(&url("http://example.test/"), now));
    assert!(!expiring.applies_to(&url("http://example.test/"), at(NOW + 5)));
}

#[test]
fn an_ip_address_matches_only_itself_and_loopback_is_a_secure_context() {
    let now = at(NOW);
    let by_ip = cookie("127.0.0.1", true, "/", true);
    assert!(
        by_ip.applies_to(&url("http://127.0.0.1:8080/"), now),
        "Secure goes to loopback over http"
    );
    assert!(!by_ip.applies_to(&url("http://127.0.0.2/"), now));
    let dotted = cookie(".10.0.0.1", false, "/", false);
    assert!(dotted.applies_to(&url("http://10.0.0.1/"), now));
    let v6 = cookie("::1", false, "/", true);
    assert!(v6.applies_to(&url("http://[::1]:9/"), now));
    let local = cookie("localhost", false, "/", true);
    assert!(local.applies_to(&url("http://localhost/"), now));
    let remote = cookie("example.test", false, "/", true);
    assert!(!remote.applies_to(&url("http://example.test/"), now));
}

#[test]
fn the_debug_form_never_shows_a_value() {
    let shown = format!("{:?}", cookie("example.test", false, "/", false));
    assert!(!shown.contains("\"v\""), "{shown}");
    assert!(shown.contains("***"));
}

fn write(directory: &tempfile::TempDir, name: &str, text: &str) -> std::path::PathBuf {
    let path = directory.path().join(name);
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn the_netscape_file_round_trips_every_field() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jar").join("host.txt");
    let mut first = cookie("example.test", true, "/p", true);
    first.expires = Some(at(NOW));
    first.http_only = true;
    let mut second = cookie(".other.test", false, "/", false);
    second.name = "s".into();
    second.value = Secret::new("");
    save_netscape([&first, &second], &path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("# Netscape HTTP Cookie File\n"));
    assert!(
        text.contains("#HttpOnly_example.test\tTRUE\t/p\tTRUE\t1700000000\tn\tv\n"),
        "{text}"
    );
    assert!(!text.contains('\r'));
    let loaded = load_netscape(&path);
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0], first);
    assert_eq!(loaded[1].domain, ".other.test");
    assert!(loaded[1].subdomains, "the leading dot says the flag");
    assert_eq!(loaded[1].value.expose(), "");
    assert_eq!(loaded[1].expires, None);
}

#[cfg(unix)]
#[test]
fn the_file_is_private_and_so_are_the_directories_it_makes() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("a").join("b").join("jar.txt");
    save_netscape([cookie("example.test", false, "/", false)], &path).unwrap();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    assert_eq!(mode(path.parent().unwrap().parent().unwrap()), 0o700);
}

#[test]
fn saving_replaces_the_file_whole_and_leaves_no_temporary_beside_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jar.txt");
    save_netscape([cookie("a.test", false, "/", false)], &path).unwrap();
    save_netscape([cookie("b.test", false, "/", false)], &path).unwrap();
    assert_eq!(load_netscape(&path)[0].domain, "b.test");
    let entries: Vec<_> = std::fs::read_dir(directory.path()).unwrap().collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn a_row_that_would_split_is_not_written() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jar.txt");
    let mut tabbed = cookie("a.test", false, "/", false);
    tabbed.value = Secret::new("x\ty");
    let mut broken = cookie("a.test", false, "/", false);
    broken.value = Secret::new("x\ny");
    let mut nameless = cookie("a.test", false, "/", false);
    nameless.name = String::new();
    let good = cookie("a.test", false, "/", false);
    save_netscape([&tabbed, &broken, &nameless, &good], &path).unwrap();
    let loaded = load_netscape(&path);
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].name, "n");
}

#[test]
fn loading_reads_what_curl_and_editors_leave() {
    let directory = tempfile::tempdir().unwrap();
    let text = "# comment\r\n\r\n  \r\n#HttpOnly_h.test\tFALSE\t/\tFALSE\t0\ta\tb\r\n\
                h.test\tFALSE\t/\tFALSE\t0\ttrimmed\r\n\
                h.test\tFALSE\t\tFALSE\t0\tnopath\tv\n\
                h.test\tFALSE\t/\tFALSE\t0\tbad\x01name\tv\n\
                h.test\tFALSE\t/\tFALSE\t0\tshort\n\
                h.test\tTRUE\t/\tTRUE\t99\tdated\ts p a c e\n\
                h.test\tFALSE\t/\tFALSE\t-5\tnegative\tv\n   spaced.test\tFALSE\t/\tFALSE\t0\tlead\tv\n\
                h.test\tFALSE\t/\tFALSE\t0\tvt\tone\x0btwo\n";
    let path = write(&directory, "jar.txt", text);
    let loaded = load_netscape(&path);
    let names: Vec<_> = loaded.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "a", "trimmed", "nopath", "short", "dated", "negative", "lead"
        ]
    );
    assert!(loaded[0].http_only);
    assert_eq!(loaded[1].value.expose(), "");
    assert_eq!(loaded[2].path, "/");
    assert_eq!(loaded[3].value.expose(), "");
    assert_eq!(loaded[4].expires, Some(at(99)));
    assert!(loaded[4].secure && loaded[4].subdomains);
    assert_eq!(loaded[4].value.expose(), "s p a c e");
    assert_eq!(
        loaded[5].expires, None,
        "a negative expiry is not a number of seconds"
    );
    assert_eq!(loaded[6].domain, "spaced.test");
    assert!(
        names.iter().all(|name| *name != "vt"),
        "a row with a vertical tab is skipped, not split"
    );
    assert!(load_netscape(&directory.path().join("missing.txt")).is_empty());
}

#[test]
fn loading_drops_undecodable_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jar.txt");
    std::fs::write(&path, b"h.test\tFALSE\t/\tFALSE\t0\ta\tb\xffc\n").unwrap();
    assert_eq!(load_netscape(&path)[0].value.expose(), "bc");
}

#[test]
fn a_cookie_like_of_another_shape_is_saved_too() {
    struct Mine;
    impl CookieLike for Mine {
        fn domain(&self) -> &str {
            "mine.test"
        }
        fn path(&self) -> &str {
            ""
        }
        fn secure(&self) -> bool {
            false
        }
        fn expires(&self) -> Option<SystemTime> {
            None
        }
        fn name(&self) -> &str {
            "m"
        }
        fn value(&self) -> &str {
            "1"
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jar.txt");
    save_netscape([Mine], &path).unwrap();
    let loaded = load_netscape(&path);
    assert_eq!(
        (loaded[0].domain.as_str(), loaded[0].path.as_str()),
        ("mine.test", "/")
    );
}

proptest! {
    #[test]
    fn parsing_any_header_never_panics_and_yields_usable_cookies(
        header in "\\PC{0,120}",
        host in "[a-z0-9.\\-:\\[\\]]{0,30}",
        path in "\\PC{0,30}",
    ) {
        let found = parse_set_cookie([header], &host, &SetCookieContext::new().now(at(NOW)).request_path(path));
        for (cookie, _) in found {
            prop_assert!(!cookie.name.is_empty());
            prop_assert!(cookie.path.starts_with('/'));
            prop_assert!(!cookie.name.contains(|c: char| c.is_control() && c != '\t'));
        }
    }

    #[test]
    fn loading_any_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("jar.txt");
        std::fs::write(&path, &bytes).unwrap();
        for cookie in load_netscape(&path) {
            prop_assert!(!cookie.value.expose().contains(['\n', '\0']));
        }
    }

    #[test]
    fn what_is_saved_loads_back(
        name in "[A-Za-z0-9_]{1,12}",
        value in "[ -~]{0,20}",
        path in "/[a-z/]{0,10}",
        secure in any::<bool>(),
        expires in proptest::option::of(1u64..4_000_000_000),
    ) {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("jar.txt");
        let mut original = cookie("host.test", false, &path, secure);
        original.name = name;
        original.value = Secret::new(value);
        original.expires = expires.map(at);
        save_netscape([&original], &file).unwrap();
        let loaded = load_netscape(&file);
        prop_assert_eq!(loaded.len(), 1);
        prop_assert_eq!(&loaded[0], &original);
    }
}
