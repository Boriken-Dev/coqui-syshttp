//! `HttpEnv`: prefixes, lookups and the proxy settings as a resolver.
#![cfg(feature = "session")]

use coqui_syshttp::Route;
use coqui_syshttp::session::{HttpEnv, ProxyOverrides};

fn env(pairs: &[(&str, &str)]) -> HttpEnv {
    HttpEnv::builder()
        .environment(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
        .build()
        .unwrap()
}

fn routes(env: &HttpEnv, overrides: ProxyOverrides, url: &str) -> Vec<Route> {
    env.resolver(overrides).lookup(url).unwrap()
}

fn proxy_of(routes: &[Route]) -> Option<String> {
    match routes.first() {
        Some(Route::Proxy(proxy)) => Some(proxy.to_string()),
        _ => None,
    }
}

#[test]
fn names_are_read_as_written_without_a_prefix() {
    let env = env(&[("SYSHTTP_HOME", " /x "), ("OTHER", "")]);
    assert_eq!(env.prefixes().unwrap(), vec![String::new()]);
    assert_eq!(env.get(&["SYSHTTP_HOME"]).unwrap().as_deref(), Some("/x"));
    assert_eq!(env.get(&["OTHER"]).unwrap(), None, "a blank value is unset");
    assert_eq!(env.name("SYSHTTP_HOME").unwrap(), "SYSHTTP_HOME");
}

#[test]
fn the_prefix_variable_lists_prefixes_and_the_first_set_wins() {
    let env = env(&[
        ("SYSHTTP_PREFIX", "agents_ : mine_"),
        ("MINE_TOKEN", "m"),
        ("AGENTS_TOKEN", "a"),
        ("MINE_ONLY", "o"),
    ]);
    assert_eq!(env.prefixes().unwrap(), vec!["AGENTS_", "MINE_"]);
    assert_eq!(
        env.find(&["TOKEN"]).unwrap(),
        Some(("AGENTS_TOKEN".into(), "a".into()))
    );
    assert_eq!(env.get(&["ONLY"]).unwrap().as_deref(), Some("o"));
    assert_eq!(env.name("TOKEN").unwrap(), "AGENTS_TOKEN");
}

#[test]
fn an_empty_entry_layers_the_names_as_written_last() {
    let env = env(&[("SYSHTTP_PREFIX", "MINE_:"), ("HTTPS_PROXY", "plain")]);
    assert_eq!(env.prefixes().unwrap(), vec!["MINE_", ""]);
    assert_eq!(env.get(&["HTTPS_PROXY"]).unwrap().as_deref(), Some("plain"));
}

#[test]
fn a_malformed_prefix_is_a_configuration_error_naming_the_variable() {
    let bad = env(&[("SYSHTTP_PREFIX", "A-B")]);
    let error = bad.prefixes().unwrap_err();
    assert!(error.to_string().contains("SYSHTTP_PREFIX"), "{error}");
    let argument = HttpEnv::builder().prefixes(["a b"]).build().unwrap_err();
    assert!(argument.to_string().contains("prefixes"));
}

#[test]
fn an_argument_prefix_list_beats_the_variable() {
    let env = HttpEnv::builder()
        .prefixes(["x_"])
        .environment([("SYSHTTP_PREFIX", "Y_"), ("X_A", "1"), ("Y_A", "2")])
        .build()
        .unwrap();
    assert_eq!(env.get(&["A"]).unwrap().as_deref(), Some("1"));
    let none = HttpEnv::builder()
        .prefixes(Vec::<String>::new())
        .environment([("A", "1")])
        .build()
        .unwrap();
    assert_eq!(none.get(&["A"]).unwrap(), None, "no prefixes read nothing");
}

#[test]
fn a_family_lists_variables_by_stem_and_the_first_prefix_wins_a_rest() {
    let env = env(&[
        ("SYSHTTP_PREFIX", "A_:"),
        ("A_SYSHTTP_HOOKS_ONE", "1"),
        ("SYSHTTP_HOOKS_ONE", "shadowed"),
        ("SYSHTTP_HOOKS_two", "2"),
        ("SYSHTTP_HOOKS_", "no rest"),
        ("SYSHTTP_HOOKS_BLANK", "  "),
    ]);
    let found = env.family("SYSHTTP_HOOKS_").unwrap();
    let rests: Vec<_> = found.iter().map(|(rest, _, _)| rest.as_str()).collect();
    assert_eq!(rests, vec!["ONE", "two"]);
    assert_eq!(found[0].2, "A_SYSHTTP_HOOKS_ONE");
}

#[test]
fn the_process_view_reads_the_variable_at_each_lookup() {
    let env = HttpEnv::process();
    assert_eq!(env.get(&["COQUI_SYSHTTP_NO_SUCH_SETTING"]).unwrap(), None);
}

#[test]
fn system_proxy_is_a_boolean_that_defaults_on() {
    assert!(env(&[]).system_proxy_enabled().unwrap());
    for value in ["0", "false", "No", "OFF"] {
        assert!(
            !env(&[("SYSHTTP_SYSTEM_PROXY", value)])
                .system_proxy_enabled()
                .unwrap()
        );
    }
    for value in ["1", "true", "YES", "on"] {
        assert!(
            env(&[("SYSHTTP_SYSTEM_PROXY", value)])
                .system_proxy_enabled()
                .unwrap()
        );
    }
    let error = env(&[("SYSHTTP_SYSTEM_PROXY", "maybe")])
        .system_proxy_enabled()
        .unwrap_err();
    assert!(error.to_string().contains("SYSHTTP_SYSTEM_PROXY"));
    assert!(!error.to_string().contains("maybe"));
}

#[test]
fn proxy_auth_header_defaults_and_refuses_a_value_that_is_not_a_name() {
    assert_eq!(env(&[]).proxy_auth_header().unwrap(), "Proxy-Authorization");
    assert_eq!(
        env(&[("SYSHTTP_PROXY_AUTH_HEADER", "X-Proxy-Token")])
            .proxy_auth_header()
            .unwrap(),
        "X-Proxy-Token"
    );
    assert!(
        env(&[("SYSHTTP_PROXY_AUTH_HEADER", "A: b")])
            .proxy_auth_header()
            .is_err()
    );
    assert!(
        env(&[("SYSHTTP_PROXY_AUTH_HEADER", "A B")])
            .proxy_auth_header()
            .is_err()
    );
}

#[test]
fn proxy_type_reads_connect_and_prefix_with_an_endpoint() {
    assert_eq!(env(&[]).proxy_type().unwrap(), ("connect".into(), None));
    assert_eq!(
        env(&[("SYSHTTP_PROXY_TYPE", "Prefix")])
            .proxy_type()
            .unwrap(),
        ("prefix".into(), Some("/".into()))
    );
    assert_eq!(
        env(&[("SYSHTTP_PROXY_TYPE", "prefix:fetch/")])
            .proxy_type()
            .unwrap(),
        ("prefix".into(), Some("/fetch/".into()))
    );
    assert!(
        env(&[("SYSHTTP_PROXY_TYPE", "tunnel")])
            .proxy_type()
            .is_err()
    );
}

#[test]
fn configured_proxy_carries_its_credential_and_kind() {
    assert!(env(&[]).configured_proxy().unwrap().is_none());
    let plain = env(&[("SYSHTTP_PROXY", "http://user:pw@gw.test:3128")])
        .configured_proxy()
        .unwrap()
        .unwrap();
    assert_eq!(plain.host(), "gw.test");
    assert_eq!(plain.credentials().unwrap().username(), "user");

    let header = env(&[
        ("SYSHTTP_PROXY", "http://user:pw@gw.test:3128"),
        ("SYSHTTP_PROXY_AUTH", "Bearer abc"),
        ("SYSHTTP_PROXY_AUTH_HEADER", "X-Proxy-Token"),
    ])
    .configured_proxy()
    .unwrap()
    .unwrap();
    let headers: Vec<_> = header.headers().collect();
    assert_eq!(headers, vec![("X-Proxy-Token", "Bearer abc")]);

    let gateway = env(&[
        ("SYSHTTP_PROXY", "https://gw.test"),
        ("SYSHTTP_PROXY_TYPE", "prefix:/go/"),
    ])
    .configured_proxy()
    .unwrap()
    .unwrap();
    assert!(gateway.is_gateway());
    assert_eq!(
        gateway.gateway_url("https://api.test/x").unwrap(),
        "https://gw.test:443/go/https://api.test/x"
    );
}

#[test]
fn a_gateway_needs_an_http_proxy_and_a_credential_may_not_hold_a_line_break() {
    let error = env(&[
        ("SYSHTTP_PROXY", "socks5://gw.test:1080"),
        ("SYSHTTP_PROXY_TYPE", "prefix"),
    ])
    .configured_proxy()
    .unwrap_err();
    assert!(error.to_string().contains("SYSHTTP_PROXY_TYPE"));
    let error = env(&[
        ("SYSHTTP_PROXY", "http://gw.test:3128"),
        ("SYSHTTP_PROXY_AUTH", "Bearer a\r\nX: y"),
    ])
    .configured_proxy()
    .unwrap_err();
    assert!(error.to_string().contains("SYSHTTP_PROXY_AUTH"));
    assert!(!error.to_string().contains("Bearer"));
}

#[test]
fn the_configured_proxy_decides_before_the_machines() {
    let env = env(&[
        ("SYSHTTP_PROXY", "http://mine.test:3128"),
        ("HTTP_PROXY", "http://machine.test:3128"),
    ]);
    let answer = routes(&env, ProxyOverrides::default(), "http://origin.test/");
    assert_eq!(proxy_of(&answer).as_deref(), Some("http://mine.test:3128"));
}

#[test]
fn proxy_variables_alone_decide_and_the_lowercase_spelling_wins() {
    let env = env(&[
        ("https_proxy", "http://lower.test:3128"),
        ("HTTPS_PROXY", "http://upper.test:3128"),
        ("HTTP_PROXY", "http://plain.test:3128"),
    ]);
    let secure = routes(&env, ProxyOverrides::default(), "https://origin.test/");
    assert_eq!(proxy_of(&secure).as_deref(), Some("http://lower.test:3128"));
    let plain = routes(&env, ProxyOverrides::default(), "http://origin.test/");
    assert_eq!(proxy_of(&plain).as_deref(), Some("http://plain.test:3128"));
}

#[test]
fn a_switched_off_system_proxy_with_no_variables_is_direct() {
    let env = env(&[("SYSHTTP_SYSTEM_PROXY", "off")]);
    let answer = routes(&env, ProxyOverrides::default(), "http://origin.test/");
    assert!(matches!(answer.as_slice(), [Route::Direct]));
}

#[test]
fn no_proxy_sends_matching_hosts_direct_before_anything_else() {
    let env = env(&[
        ("SYSHTTP_PROXY", "http://mine.test:3128"),
        ("NO_PROXY", ".internal.test"),
    ]);
    assert!(matches!(
        routes(&env, ProxyOverrides::default(), "http://app.internal.test/").as_slice(),
        [Route::Direct]
    ));
    assert!(
        proxy_of(&routes(
            &env,
            ProxyOverrides::default(),
            "http://other.test/"
        ))
        .is_some()
    );
}

#[test]
fn loopback_goes_direct_unless_the_rules_switch_that_off() {
    let env = env(&[("SYSHTTP_PROXY", "http://mine.test:3128")]);
    assert!(matches!(
        routes(&env, ProxyOverrides::default(), "http://127.0.0.1:9/").as_slice(),
        [Route::Direct]
    ));
    let mut overrides = ProxyOverrides::default();
    overrides.no_proxy = Some("<-loopback>".into());
    assert!(proxy_of(&routes(&env, overrides, "http://127.0.0.1:9/")).is_some());
}

#[test]
fn overrides_replace_the_settings_as_curls_options_do() {
    let env = env(&[
        ("SYSHTTP_PROXY", "http://mine.test:3128"),
        ("SYSHTTP_PROXY_AUTH", "Bearer abc"),
        ("NO_PROXY", "skip.test"),
    ]);
    let mut overrides = ProxyOverrides::default();
    overrides.proxy = Some("http://given:pw@other.test:8080".into());
    let answer = routes(&env, overrides, "http://origin.test/");
    let Route::Proxy(proxy) = &answer[0] else {
        panic!()
    };
    assert_eq!(proxy.host(), "other.test");
    assert_eq!(
        proxy.headers().count(),
        0,
        "the configured credential is not its"
    );

    let mut direct = ProxyOverrides::default();
    direct.proxy = Some(String::new());
    assert!(matches!(
        routes(&env, direct, "http://origin.test/").as_slice(),
        [Route::Direct]
    ));

    let mut noproxy = ProxyOverrides::default();
    noproxy.no_proxy = Some("origin.test".into());
    assert!(matches!(
        routes(&env, noproxy, "http://origin.test/").as_slice(),
        [Route::Direct]
    ));
    // --noproxy replaces NO_PROXY: skip.test is no longer excluded.
    let mut replaced = ProxyOverrides::default();
    replaced.no_proxy = Some("elsewhere.test".into());
    assert!(proxy_of(&routes(&env, replaced, "http://skip.test/")).is_some());

    let mut user = ProxyOverrides::default();
    user.proxy_user = Some(coqui_syshttp::Secret::new("bob:hunter2"));
    let answer = routes(&env, user, "http://origin.test/");
    let Route::Proxy(proxy) = &answer[0] else {
        panic!()
    };
    assert_eq!(proxy.credentials().unwrap().username(), "bob");
    assert_eq!(proxy.credentials().unwrap().password(), "hunter2");
}

#[test]
fn the_machine_credential_rides_every_http_proxy_but_not_socks() {
    let env = env(&[
        ("HTTP_PROXY", "http://m.test:3128"),
        ("ALL_PROXY", "socks5://s.test:1080"),
        ("HTTP_PROXY_AUTH", "Basic abc"),
    ]);
    let answer = routes(&env, ProxyOverrides::default(), "http://origin.test/");
    let Route::Proxy(proxy) = &answer[0] else {
        panic!()
    };
    assert_eq!(
        proxy.headers().collect::<Vec<_>>(),
        vec![("Proxy-Authorization", "Basic abc")]
    );
    let socks = routes(&env, ProxyOverrides::default(), "https://origin.test/");
    let Route::Proxy(proxy) = &socks[0] else {
        panic!()
    };
    assert_eq!(proxy.headers().count(), 0);
}

#[test]
fn settings_are_read_at_each_lookup() {
    // A mapping cannot change, so two views over the process stand for "later".
    let one = env(&[("SYSHTTP_PROXY", "http://one.test:1")]);
    let two = env(&[("SYSHTTP_PROXY", "http://two.test:2")]);
    let answer =
        |view: &HttpEnv| proxy_of(&routes(view, ProxyOverrides::default(), "http://o.test/"));
    assert_eq!(answer(&one).as_deref(), Some("http://one.test:1"));
    assert_eq!(answer(&two).as_deref(), Some("http://two.test:2"));
}

#[test]
fn a_malformed_proxy_setting_is_an_error_of_the_lookup_and_of_the_check() {
    let bad = env(&[
        ("SYSHTTP_PROXY", "http://gw.test"),
        ("SYSHTTP_PROXY_TYPE", "tunnel"),
    ]);
    assert!(bad.check_proxy_settings().is_err());
    assert!(
        bad.resolver(ProxyOverrides::default())
            .lookup("http://o.test/")
            .is_err()
    );
    assert!(env(&[]).check_proxy_settings().is_ok());
}

#[test]
fn the_unprefixed_ca_bundle_variables_of_other_tools_are_not_read() {
    // The settings this layer reads are CA_BUNDLE and its own; curl's and requests' are not.
    let env = env(&[
        ("CURL_CA_BUNDLE", "/curl.pem"),
        ("REQUESTS_CA_BUNDLE", "/requests.pem"),
    ]);
    assert_eq!(
        env.get(&[coqui_syshttp::session::env::CA_BUNDLE]).unwrap(),
        None
    );
}
