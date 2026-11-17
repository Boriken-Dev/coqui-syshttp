use super::*;
use crate::bypass::Dialect;
use crate::system::{SettingsSource, SettingsState};

fn proxy(text: &str) -> Proxy {
    Proxy::parse(text).unwrap()
}

fn hosts(routes: &[Route]) -> Vec<String> {
    routes
        .iter()
        .map(|route| match route {
            Route::Proxy(proxy) => proxy.host().to_string(),
            Route::Direct => "direct".to_string(),
        })
        .collect()
}

fn isolated() -> ResolverBuilder {
    Resolver::builder()
        .environment(Environment::from_pairs([("PATH", "x")]))
        .settings(SystemSettings::default())
}

fn manual(proxies: &str) -> SystemSettings {
    SystemSettings {
        source: SettingsSource::Windows,
        state: SettingsState::Configured,
        proxies: crate::system::parse_proxy_list(proxies, ProxyScheme::Socks4),
        ..SystemSettings::default()
    }
}

#[test]
fn with_no_environment_and_no_settings_everything_goes_direct() {
    let resolver = isolated().build();
    assert_eq!(
        resolver.lookup("https://example.com/").unwrap(),
        [Route::Direct]
    );
}

#[test]
fn an_explicit_proxy_replaces_the_environment_and_the_system_but_not_no_proxy() {
    let environment = Environment::from_pairs([
        ("HTTPS_PROXY", "http://env:1"),
        ("NO_PROXY", "internal.example"),
    ]);
    let resolver = Resolver::builder()
        .environment(environment)
        .settings(manual("sys:2"))
        .proxy(ProxySetting::Proxy(proxy("http://chosen:3")))
        .build();
    assert_eq!(
        hosts(&resolver.lookup("https://example.com/").unwrap()),
        ["chosen"]
    );
    assert_eq!(
        resolver.lookup("https://a.internal.example/").unwrap(),
        [Route::Direct]
    );
}

#[test]
fn a_bypass_list_given_to_the_builder_replaces_no_proxy_from_the_environment() {
    let environment = Environment::from_pairs([
        ("HTTPS_PROXY", "http://env:1"),
        ("NO_PROXY", "env-bypass.example"),
    ]);
    let resolver = Resolver::builder()
        .environment(environment)
        .no_proxy(BypassRules::parse("given.example", Dialect::NoProxy))
        .build();
    assert_eq!(
        resolver.lookup("https://given.example/").unwrap(),
        [Route::Direct]
    );
    assert_eq!(
        hosts(&resolver.lookup("https://env-bypass.example/").unwrap()),
        ["env"]
    );
}

#[test]
fn proxy_variables_decide_alone_and_a_scheme_without_one_goes_direct() {
    let environment = Environment::from_pairs([("https_proxy", "http://secure:1")]);
    let resolver = Resolver::builder()
        .environment(environment)
        .settings(manual("sys:2"))
        .build();
    assert_eq!(
        hosts(&resolver.lookup("https://example.com/").unwrap()),
        ["secure"]
    );
    assert_eq!(
        resolver.lookup("http://example.com/").unwrap(),
        [Route::Direct]
    );
}

#[test]
fn a_variable_may_hold_a_pac_result_with_failover() {
    let environment = Environment::from_pairs([("HTTP_PROXY", "PROXY a:1; PROXY b:2; DIRECT")]);
    let resolver = Resolver::builder().environment(environment).build();
    assert_eq!(
        hosts(&resolver.lookup("http://example.com/").unwrap()),
        ["a", "b", "direct"]
    );
}

#[test]
fn the_systems_manual_proxies_answer_by_scheme_with_its_bypass_list() {
    let mut settings = manual("http=plain:80;https=secure:443");
    settings.bypass = BypassRules::parse("corp.example", Dialect::WinInet);
    let resolver = Resolver::builder()
        .environment(Environment::default())
        .settings(settings)
        .build();
    assert_eq!(
        hosts(&resolver.lookup("https://example.com/").unwrap()),
        ["secure"]
    );
    assert_eq!(
        hosts(&resolver.lookup("http://example.com/").unwrap()),
        ["plain"]
    );
    assert_eq!(
        resolver.lookup("https://corp.example/").unwrap(),
        [Route::Direct]
    );
    assert_eq!(
        resolver.lookup("https://localhost/").unwrap(),
        [Route::Direct]
    );
}

#[test]
fn settings_that_say_direct_send_everything_direct_even_with_a_pac_url() {
    let mut settings = manual("sys:2");
    settings.state = SettingsState::Direct;
    settings.pac_url = Some("file:///nowhere.pac".into());
    let resolver = Resolver::builder()
        .environment(Environment::default())
        .settings(settings)
        .build();
    assert_eq!(
        resolver.lookup("https://example.com/").unwrap(),
        [Route::Direct]
    );
}

#[test]
fn credentials_are_given_to_http_proxies_without_their_own_and_never_to_socks() {
    let environment =
        Environment::from_pairs([("ALL_PROXY", "PROXY a:1; PROXY u:p@b:2; SOCKS5 s:3")]);
    let resolver = Resolver::builder()
        .environment(environment)
        .credentials(Credentials::new("user", "secret"))
        .build();
    let routes = resolver.lookup("http://example.com/").unwrap();
    let login = |index: usize| match &routes[index] {
        Route::Proxy(proxy) => proxy.credentials().map(|c| c.username().to_string()),
        Route::Direct => None,
    };
    assert_eq!(login(0).as_deref(), Some("user"));
    assert_eq!(login(1).as_deref(), Some("u"));
    assert_eq!(login(2), None);
}

#[test]
fn a_proxy_that_refused_a_connection_is_tried_last() {
    let environment = Environment::from_pairs([("HTTP_PROXY", "PROXY a:1; PROXY b:2; DIRECT")]);
    let resolver = Resolver::builder().environment(environment).build();
    resolver.report_failure(&proxy("a:1"));
    assert_eq!(
        hosts(&resolver.lookup("http://example.com/").unwrap()),
        ["b", "direct", "a"]
    );
    resolver.clear();
    assert_eq!(
        hosts(&resolver.lookup("http://example.com/").unwrap()),
        ["a", "b", "direct"]
    );
}

#[test]
fn a_url_without_a_host_is_an_error() {
    assert!(isolated().build().lookup("not a url").is_err());
}

#[cfg(feature = "pac")]
mod with_pac {
    use super::*;

    const PAC: &str = "function FindProxyForURL(url, host) {
        if (shExpMatch(host, '*.corp.example')) return 'PROXY gateway.corp:3128';
        return 'DIRECT';
    }";

    #[test]
    fn a_pac_file_in_the_systems_settings_chooses_per_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.pac");
        std::fs::write(&path, PAC).unwrap();
        let mut settings = manual("fallback:9");
        settings.pac_url = Some(path.to_string_lossy().into_owned());
        let resolver = Resolver::builder()
            .environment(Environment::default())
            .settings(settings)
            .build();
        assert_eq!(
            hosts(&resolver.lookup("https://wiki.corp.example/").unwrap()),
            ["gateway.corp"]
        );
        assert_eq!(
            resolver.lookup("https://example.org/").unwrap(),
            [Route::Direct]
        );
    }

    #[test]
    fn a_pac_that_cannot_be_loaded_passes_to_the_manual_proxies() {
        let mut settings = manual("fallback:9");
        settings.pac_url = Some("file:///no/such/proxy.pac".into());
        let resolver = Resolver::builder()
            .environment(Environment::default())
            .settings(settings)
            .build();
        assert_eq!(
            hosts(&resolver.lookup("https://example.org/").unwrap()),
            ["fallback"]
        );
    }

    #[test]
    fn an_explicit_pac_script_text_in_a_variable_is_run() {
        let environment = Environment::from_pairs([("HTTPS_PROXY", PAC)]);
        let resolver = Resolver::builder().environment(environment).build();
        assert_eq!(
            hosts(&resolver.lookup("https://wiki.corp.example/").unwrap()),
            ["gateway.corp"]
        );
    }

    #[test]
    fn a_pac_location_in_a_variable_is_loaded_on_first_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.pac");
        std::fs::write(&path, PAC).unwrap();
        let location = alloc::format!("file:{}", path.to_string_lossy().replace('\\', "/"));
        let environment = Environment::from_pairs([("HTTPS_PROXY", location)]);
        let resolver = Resolver::builder().environment(environment).build();
        assert_eq!(
            hosts(&resolver.lookup("https://wiki.corp.example/").unwrap()),
            ["gateway.corp"]
        );
    }
}

#[cfg(not(feature = "pac"))]
mod without_pac {
    use super::*;

    #[test]
    fn a_pac_location_without_an_engine_is_an_error_or_direct_by_setting() {
        let environment = Environment::from_pairs([("HTTPS_PROXY", "http://wpad.corp/wpad.dat")]);
        let resolver = Resolver::builder().environment(environment.clone()).build();
        assert!(matches!(
            resolver.lookup("https://example.com/"),
            Err(Error::MissingEngine)
        ));
        let resolver = Resolver::builder()
            .environment(environment)
            .on_missing_engine(OnMissingEngine::Direct)
            .build();
        assert_eq!(
            resolver.lookup("https://example.com/").unwrap(),
            [Route::Direct]
        );
    }
}
