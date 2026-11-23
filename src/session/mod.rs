//! A client above [`ureq`](::ureq) that owns redirects, cookies, tokens, hooks, retries and a
//! deadline, with every setting read through prefixed environment variables.
//!
//! It is a port of the Python library `syshttp`: the same settings, the same environment variable
//! names and the same file formats, so a Python and a Rust program in one environment share them.

pub mod env;
mod error;

pub use env::{HttpEnv, HttpEnvBuilder, ProxyOverrides};
pub use error::{BoxError, Error};
