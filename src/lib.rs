#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

extern crate alloc;

mod bypass;
mod env;
mod error;
mod netutil;
#[cfg(feature = "pac")]
pub mod pac;
mod proxy;
mod resolver;
pub mod system;

pub use bypass::{BypassRules, Dialect};
pub use env::{Environment, ProxyVariables};
pub use error::{Error, Reason};
pub use proxy::{Credentials, Proxy, ProxyBuilder, ProxyScheme, Route, Secret};
pub use resolver::{OnMissingEngine, ProxySetting, Resolver, ResolverBuilder};
