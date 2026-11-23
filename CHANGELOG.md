# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The proxy half moved to [coqui-proxy](https://github.com/Boriken-Dev/coqui-proxy) and the TLS half to
  [coqui-sslcontext](https://github.com/Boriken-Dev/coqui-sslcontext). Both are re-exported at the
  paths they had (root items, `auth`, `system`, `pac`, and `tls`), and as `proxy` and `tls`.
- The `client` module is now `ureq`.
- `Error` wraps the two crates' errors (`Proxy`, `Tls`) and has an `Http` variant.

### Added

- `hyper` and `reqwest` modules (features of the same names): a `hyper-util` client and a `reqwest` client
  that follow the system's proxy, proxy login and TLS; `AdapterSettings` (`failover`, `bad_proxy_ttl`) on the
  three adapters' builders, `ureq::AgentBuilder::{failover, bad_proxy_ttl}`.
- `agent()`: a `ureq` agent that follows the system, in one call.
