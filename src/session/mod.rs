//! A client above [`ureq`](::ureq) that owns redirects, cookies, tokens, hooks, retries and a
//! deadline, with every setting read through prefixed environment variables.
//!
//! It is a port of the Python library `syshttp`: the same settings, the same environment variable
//! names and the same file formats, so a Python and a Rust program in one environment share them.

pub mod cookies;
pub mod env;
mod error;
mod fileio;
mod httpdate;
pub mod jar;
mod settings;

pub use env::{HttpEnv, HttpEnvBuilder, ProxyOverrides};
pub use error::{BoxError, Error};
pub use jar::{CookieJar, TokenJar};
pub use settings::{
    CookieSettings, CookieStore, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, PoolSettings,
    RetrySettings, SessionSettings, TokenSettings, TokenStore,
};
