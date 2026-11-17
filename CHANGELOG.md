# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `Resolver`: the proxy for a URL, from `NO_PROXY`, an explicit setting, the proxy environment
  variables, and the operating system (WinHTTP on Windows; Internet Options, `scutil --proxy`, GNOME,
  MATE, KDE and NetworkManager settings elsewhere), with PAC, WPAD, per-proxy failure memory and a
  login for proxies that have none.
- Bypass lists in the `NO_PROXY`, WinINet, macOS, GNOME and KDE dialects (`BypassRules`).
- `pac::PacScript` (feature `pac`): PAC scripts run in the Boa engine with the Netscape and
  Microsoft `*Ex` builtins, a time limit per call and WPAD discovery.
- `ProxyConnector`: a direct connection or an HTTP `CONNECT` tunnel through an `http:` or
  `https:` proxy, logged in with Basic credentials, a proxy's extra headers, or Negotiate and NTLM
  (SSPI on Windows, GSSAPI elsewhere; feature `negotiate`).
- `tls::Tls` (feature `tls`): `rustls` client configurations verified by the operating system, with
  client certificates chosen by the CAs a server names, from `Selector`s over Windows CNG stores,
  the macOS Keychain and PKCS #11 modules (feature `pkcs11`), with the `AutoSelectCertificateForUrls`
  policy of Chrome and Edge.
- `client::AgentBuilder` (feature `ureq`): a `ureq` agent that follows the system's proxy, proxy
  login and TLS.
