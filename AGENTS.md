# `coqui-syshttp` — API header

Header-file-style reference for the `coqui-syshttp` crate: what it re-exports, where each item is
documented, and what it adds. It ships inside the package and is self-contained. Development
documentation lives with the source at <https://github.com/Boriken-Dev/coqui-syshttp>.

The crate holds no proxy or TLS logic of its own. Two crates do the work and are documented in their
own `AGENTS.md`:

- [coqui-proxy](https://github.com/Boriken-Dev/coqui-proxy): which proxy a request uses and a
  connection through it (resolver, PAC, WPAD, bypass rules, login, CONNECT and SOCKS connectors).
- [coqui-sslcontext](https://github.com/Boriken-Dev/coqui-sslcontext): rustls configurations that
  follow the system (trust, keystore client certificates, pins).

| Feature | Turns on | Needed for | Default |
| --- | --- | --- | --- |
| `pac` | `coqui-proxy/pac` | PAC scripts and WPAD on macOS and Unix | off |
| `negotiate` | `coqui-proxy/negotiate` | Negotiate and NTLM login (SSPI on Windows, GSSAPI on Unix) | off |
| `tls` | `coqui-sslcontext` with `system`, `coqui-proxy/tls` | the `tls` module; `https:` proxies and PAC locations | off |
| `pkcs11` | `tls`, `coqui-sslcontext/pkcs11` | client certificates on PKCS #11 tokens | off |
| `ureq` | `tls`, `ureq` 3.5, `rustls` | the `ureq` module and `agent()` | off |
| `hyper` | `tls`, `coqui-proxy/hyper`, `hyper`, `hyper-util`, `tokio`, `tokio-rustls`, `tower-service` | the `hyper` module: `client()` | off |
| `reqwest` | `tls`, `reqwest` 0.13 (no TLS backend of its own, `socks`), `rustls`, `tracing` | the `reqwest` module: `client()` | off |

MSRV Rust 1.89, edition 2024. `#![forbid(unsafe_code)]`; no process-wide state; prints nothing.

## Re-exports (same names and paths as before the split)

From coqui-proxy at the root: `Resolver`, `ResolverBuilder`, `ChildEnvironment`, `ProxySetting`,
`OnMissingEngine`, `Route`, `Proxy`, `ProxyBuilder`, `ProxyScheme`, `Credentials`, `Secret`,
`BypassRules`, `Dialect`, `Environment`, `ProxyVariables`, `ProxyConnector`,
`ProxyConnectorBuilder`, `Connection`, `Negotiate`, `NegotiateBuilder`, `OriginAuth`,
`OriginAuthBuilder`, `OriginLogin`. Modules: `auth`, `system`, `pac` (feature `pac`), and
`proxy` (the whole crate). Feature `tls`: `tls` is the whole of coqui-sslcontext (`tls::Tls`,
`tls::TlsBuilder`, `tls::Trust`, `tls::Selector`, `tls::Identity`, ...).

## Root items of this crate

```rust
pub fn agent() -> Result<ureq::Agent, Error>;   // feature `ureq`; ureq::AgentBuilder::new().build()

#[non_exhaustive]
pub enum Error {
    Proxy(coqui_proxy::Error),            // From; source() is the inner error
    Tls(coqui_sslcontext::Error),         // feature `tls`; From
    Http(Reason),
}                                         // also From<std::io::Error> (as Proxy(Io))
pub struct Reason;                        // Display; Reason::new(text)
```

## Module `ureq` (feature `ureq`)

```rust
impl AgentBuilder {
    pub fn new() -> Self;
    pub fn resolver(self, resolver: Resolver) -> Self;        // default Resolver::system()
    pub fn tls(self, tls: coqui_sslcontext::Tls) -> Self;     // default: the system's
    pub fn connector(self, connector: ProxyConnector) -> Self;
    pub fn config(self, config: ureq::config::Config) -> Self; // its own proxy and TLS settings are unused
    pub fn failover(self, failover: bool) -> Self;            // default true: next route on a connect failure
    pub fn bad_proxy_ttl(self, ttl: Duration) -> Self;        // default 300 s: a failed proxy is tried last
    pub fn adapter_settings(self, settings: AdapterSettings) -> Self;
    pub fn non_defaults(&self) -> Vec<String>;
    pub fn build(self) -> Result<ureq::Agent, Error>;
}
impl OriginAgent {                                            // answers an origin's 401
    pub fn new(agent: ureq::Agent, auth: OriginAuth) -> Self;
    pub fn agent(&self) -> &ureq::Agent;
    pub fn run(&self, request: ureq::http::Request<impl AsRef<[u8]>>)
        -> Result<ureq::http::Response<ureq::Body>, ureq::Error>;
}
```

The agent resolves no name itself: every request asks the resolver for its routes and tries them in
order. A plain `http:` URL through a proxy is tunnelled with `CONNECT`. A failed origin login is an
I/O error of kind `PermissionDenied`.

## Adapter settings (`coqui_syshttp::AdapterSettings`)

`AdapterSettings { failover: bool = true, bad_proxy_ttl: Duration = 300 s }` (non_exhaustive, `Default`,
`non_defaults()`), taken by the builders of all three adapters as `failover(bool)`, `bad_proxy_ttl(Duration)`
and `adapter_settings(AdapterSettings)`. Failover is only for connecting: once a request is sent, a failure is
the caller's.

## Module `hyper` (feature `hyper`)

```rust
pub fn client<B>() -> Result<Client<HttpsConnector, B>, Error>;   // hyper_util legacy client, Builder::new().build()
pub fn builder<B>() -> Builder<B>;
impl<B> Builder<B> {
    pub fn new() -> Self;
    pub fn resolver(self, resolver: Resolver) -> Self;            // default Resolver::system()
    pub fn tls(self, tls: coqui_sslcontext::Tls) -> Self;         // default: the system's, ALPN h2 and http/1.1
    pub fn connector(self, connector: ProxyConnector) -> Self;
    pub fn failover(self, bool) -> Self; pub fn bad_proxy_ttl(self, Duration) -> Self; pub fn adapter_settings(self, AdapterSettings) -> Self;
    pub fn configure(self, f: impl FnOnce(&mut hyper_util::client::legacy::Builder) + Send + 'static) -> Self;
    pub fn client(self, client: Client<HttpsConnector, B>) -> Self;   // build() returns a client you made
    pub fn connector_service(&self) -> Result<HttpsConnector, Error>; // the service alone, for your own client
    pub fn non_defaults(&self) -> Vec<String>;
    pub fn build(self) -> Result<Client<HttpsConnector, B>, Error>;  // B: hyper Body + Send + Unpin + 'static
}
HttpsConnector::new(ProxyConnector, Resolver, impl Into<Arc<Tls>>) -> Self; .resolver() -> &Resolver
// impl tower_service::Service<hyper::Uri> { Response = Stream (hyper Read + Write + Connection), Error = Error }
```

Every URI asks the resolver for its routes, connects through the first that works (coqui-proxy's
asynchronous connector: `CONNECT` or SOCKS, a plain `http:` URI too) and, for `https:`, speaks TLS over the
tunnel with `Tls::client_config(host)` (so the keystore's per-host certificate memory applies; the
configuration is made on `spawn_blocking` because a keystore may ask for a PIN). Needs a Tokio runtime.

## Module `reqwest` (feature `reqwest`)

```rust
pub fn client() -> Result<reqwest::Client, Error>;
pub fn builder() -> Builder;
impl Builder {
    pub fn new() -> Self;
    pub fn resolver(self, resolver: Resolver) -> Self;
    pub fn tls_config(self, config: Arc<rustls::ClientConfig>) -> Self;  // default coqui_sslcontext::client_config()
    pub fn connector(self, connector: ProxyConnector) -> Self;
    pub fn failover(self, bool) -> Self; pub fn bad_proxy_ttl(self, Duration) -> Self; pub fn adapter_settings(self, AdapterSettings) -> Self;
    pub fn configure(self, f: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder + Send + 'static) -> Self;
    pub fn client_builder(self) -> Result<reqwest::ClientBuilder, Error>;  // proxy and TLS set; add more, then build
    pub fn build(self) -> Result<reqwest::Client, Error>;
    pub fn non_defaults(&self) -> Vec<String>;
    pub fn not_applied(&self) -> Vec<&'static str>;                       // what reqwest's own connector cannot do
}
```

`reqwest` makes its own connections: its TLS is `use_preconfigured_tls` (the system's verification, no host
name, so no per-host certificate memory) and its proxy for each connection is `Proxy::custom` answering the
first usable route of the resolver for that URL (HTTP, HTTPS, SOCKS 5 with the proxy resolving the name).
SOCKS 4/4a, gateways and proxies with extra headers are skipped to the next route; when none is usable the
request fails (it never goes direct past the proxy the system asked for). `reqwest`'s connector layer is
sealed (`Conn` and `Unnameable` cannot be named, a request cannot be offered to it twice), so a route that
fails to connect fails the request: `failover` and `bad_proxy_ttl` are accepted for symmetry and listed by
`not_applied()`. Negotiate and NTLM proxy login is likewise not available.

## Errors

`Error` wraps the two crates' errors; a message names what failed and never quotes input.

## Environment variables

None read by this crate; coqui-proxy reads the proxy variables (`*_PROXY`, `ALL_PROXY`,
`NO_PROXY`, `REQUEST_METHOD`, `XDG_CONFIG_HOME`, `HOME`).

## Gotchas

- `ureq` 3 middleware cannot send a request twice, so an origin login is `OriginAgent::run`, not a
  middleware. A body-less POST needs an empty `Vec<u8>` body: `()` makes `ureq` send it chunked.
- `tls::Error` and `proxy::Error` are different types; `Error` converts both with `?`.
