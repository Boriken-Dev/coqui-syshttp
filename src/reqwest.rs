//! `reqwest` sending through the system's proxy and verifying with the system's TLS.
//!
//! The client is a plain [`::reqwest::Client`]: TLS is the family's rustls configuration
//! (`use_preconfigured_tls`), and the proxy for each connection is the first usable route of the
//! [`Resolver`] for that URL, asked again for every new connection, so a redirect to another host
//! is routed afresh (`reqwest` asks its `Proxy::custom` for every request it sends, each redirect
//! hop included: a test follows a redirect to another host name and sees both asked).
//! `reqwest` makes the connection itself, so what its connector cannot do is
//! listed by [`Builder::not_applied`] rather than left out silently.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use ::reqwest::{ClientBuilder, Proxy as ReqwestProxy, Url};
use coqui_proxy::{Proxy, ProxyConnector, ProxyScheme, Resolver, Route};

use crate::{AdapterSettings, Error};

type Configure = Box<dyn FnOnce(ClientBuilder) -> ClientBuilder + Send>;

/// The URL a proxy that `reqwest` cannot use is replaced by, so a request fails instead of going
/// direct past the proxy the system asked for.
const UNUSABLE: &str = "http://unsupported-proxy.invalid/";

/// Builds a `reqwest` client that follows the system.
#[must_use]
pub struct Builder {
    resolver: Option<Resolver>,
    tls: Option<Arc<rustls::ClientConfig>>,
    connector: Option<ProxyConnector>,
    adapter: AdapterSettings,
    configure: Vec<Configure>,
}

impl core::fmt::Debug for Builder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Builder")
            .field("adapter", &self.adapter)
            .finish_non_exhaustive()
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// Starts a client that follows the system: [`Resolver::system`] and the operating system's
    /// TLS verification.
    pub fn new() -> Self {
        Self {
            resolver: None,
            tls: None,
            connector: None,
            adapter: AdapterSettings::default(),
            configure: Vec::new(),
        }
    }

    /// Who decides the proxy (default: [`Resolver::system`]).
    pub fn resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// The TLS configuration (default: [`coqui_sslcontext::client_config`], verified by the
    /// operating system). It is not told the host it will be used for.
    pub fn tls_config(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.tls = Some(config);
        self
    }

    /// The connector whose settings (a proxy's reply limits, the user agent of a `CONNECT`) a
    /// client of this crate shares. `reqwest` makes its own connections, so only its failover
    /// settings are read here.
    pub fn connector(mut self, connector: ProxyConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    /// Try the next route when connecting through one fails (default true). `reqwest` cannot
    /// retry inside a request: see [`Builder::not_applied`].
    pub fn failover(mut self, failover: bool) -> Self {
        self.adapter.failover = failover;
        self
    }

    /// How long a proxy that failed to connect is tried after the others (default 300 s).
    pub fn bad_proxy_ttl(mut self, ttl: Duration) -> Self {
        self.adapter.bad_proxy_ttl = ttl;
        self
    }

    /// Both settings of [`Builder::failover`] and [`Builder::bad_proxy_ttl`] at once.
    pub fn adapter_settings(mut self, settings: AdapterSettings) -> Self {
        self.adapter = settings;
        self
    }

    /// Changes the `reqwest` client builder before the client is made (timeouts, pool, headers,
    /// cookies, redirects). Its proxy and TLS settings are replaced by this builder's.
    pub fn configure(
        mut self,
        configure: impl FnOnce(ClientBuilder) -> ClientBuilder + Send + 'static,
    ) -> Self {
        self.configure.push(Box::new(configure));
        self
    }

    /// What this builder does that is looser than the defaults.
    #[must_use]
    pub fn non_defaults(&self) -> Vec<String> {
        self.adapter.non_defaults()
    }

    /// What this adapter cannot do, because `reqwest` makes the connection itself.
    #[must_use]
    pub fn not_applied(&self) -> Vec<&'static str> {
        alloc::vec![
            "per-host certificate memory: the TLS configuration is chosen without the host name",
            "Negotiate and NTLM proxy login, and the connector's reply limits and user agent",
            "SOCKS 4 and 4a, URL-prefix gateways and proxies with extra headers: skipped to the next route",
            "failover and bad_proxy_ttl: reqwest's connector cannot be replaced or retried, so a route that fails to connect fails the request",
            "retries, token jars, hooks, the deadline across redirect hops and the per-hop Proxy-Authorization rules of the session client",
            "the session reply limit, decode chunk and interim-reply bounds: a reqwest body is the caller's to bound",
        ]
    }

    /// The `reqwest` client builder, with this builder's proxy and TLS set, to add what else a
    /// client needs before building it.
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] when the operating system's verifier cannot start.
    pub fn client_builder(self) -> Result<ClientBuilder, Error> {
        let config = match self.tls {
            Some(config) => config,
            None => coqui_sslcontext::client_config()?,
        };
        let resolver = self.resolver.unwrap_or_else(Resolver::system);
        let mut builder = ClientBuilder::new()
            .use_preconfigured_tls((*config).clone())
            .proxy(system_proxy(resolver));
        for configure in self.configure {
            builder = configure(builder);
        }
        Ok(builder)
    }

    /// The client.
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] when the operating system's verifier cannot start, [`Error::Http`] when
    /// `reqwest` refuses its configuration.
    pub fn build(self) -> Result<::reqwest::Client, Error> {
        self.client_builder()?
            .build()
            .map_err(|error| Error::Http(crate::Reason::new(error.without_url().to_string())))
    }
}

/// A client that follows the system, with the defaults of [`Builder`].
///
/// # Errors
///
/// As [`Builder::build`].
pub fn client() -> Result<::reqwest::Client, Error> {
    Builder::new().build()
}

/// Shorthand for `Builder::new()`.
pub fn builder() -> Builder {
    Builder::new()
}

/// A `reqwest` proxy that answers each URL with the first usable route of `resolver`.
fn system_proxy(resolver: Resolver) -> ReqwestProxy {
    ReqwestProxy::custom(move |url: &Url| -> Option<Url> {
        let routes = match resolver.lookup(url.as_str()) {
            Ok(routes) => routes,
            Err(error) => {
                tracing::warn!(target: "coqui_syshttp", %error, "no route for a request; it goes direct");
                return None;
            }
        };
        let mut refused = Vec::new();
        for route in &routes {
            match route {
                Route::Direct => return None,
                Route::Proxy(proxy) => match usable(proxy) {
                    Ok(address) => return Some(address),
                    Err(reason) => refused.push((proxy.to_string(), reason)),
                },
                _ => {}
            }
        }
        tracing::warn!(target: "coqui_syshttp", refused = ?refused, "reqwest cannot use any proxy offered; the request fails");
        Url::parse(UNUSABLE).ok()
    })
}

/// A proxy as the URL `reqwest` reads, or why it cannot be used.
fn usable(proxy: &Proxy) -> Result<Url, &'static str> {
    if proxy.is_gateway() {
        return Err("a URL-prefix gateway");
    }
    if proxy.headers().next().is_some() {
        return Err("a proxy with extra headers");
    }
    let scheme = match proxy.scheme() {
        ProxyScheme::Http => "http",
        ProxyScheme::Https => "https",
        // The proxy resolves the name, as the connectors of this family do.
        ProxyScheme::Socks5 => "socks5h",
        ProxyScheme::Socks4 => return Err("SOCKS 4"),
        _ => return Err("a proxy scheme reqwest does not speak"),
    };
    let text = proxy.url_with_credentials();
    let rest = text
        .split_once("://")
        .map_or(text.as_str(), |(_, rest)| rest);
    Url::parse(&alloc::format!("{scheme}://{rest}")).map_err(|_| "an address reqwest cannot read")
}

/// A builder with the settings of a session [`SessionSettings`](crate::session::SessionSettings)
/// that `reqwest` can honour: the connect and read timeouts, the deadline as the timeout of a
/// whole request, the user agent and default headers, the idle connections kept per host and for
/// how long, and a redirect policy that follows up to `max_redirects`. A cookie jar of the session
/// layer plugs in with `reqwest::ClientBuilder::cookie_provider` through
/// [`Builder::configure`]. Retries, token jars, hooks, the reply limit and decoding bounds belong
/// to the session client: [`Builder::not_applied`] lists them.
#[cfg(feature = "session-reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "session-reqwest")))]
pub fn builder_from(settings: &crate::session::SessionSettings) -> Builder {
    use ::reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    let mut headers = HeaderMap::new();
    for (name, value) in &settings.headers {
        let (Ok(name), Some(Ok(value))) = (
            HeaderName::from_bytes(name.as_bytes()),
            value.as_ref().map(|text| HeaderValue::from_str(text)),
        ) else {
            continue;
        };
        headers.insert(name, value);
    }
    let (connect, read, deadline) = (
        settings.connect_timeout,
        settings.read_timeout,
        settings.deadline,
    );
    let user_agent = settings.user_agent.clone();
    let per_host = settings.pool.max_idle_per_route;
    let idle = settings.pool.idle_timeout;
    let max_redirects = settings.max_redirects as usize;
    Builder::new().configure(move |mut builder| {
        if let Some(connect) = connect {
            builder = builder.connect_timeout(connect);
        }
        if let Some(read) = read {
            builder = builder.read_timeout(read);
        }
        if let Some(deadline) = deadline {
            builder = builder.timeout(deadline);
        }
        builder
            .user_agent(user_agent)
            .default_headers(headers)
            .pool_max_idle_per_host(per_host)
            .pool_idle_timeout(idle)
            .redirect(::reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() > max_redirects {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
    })
}
