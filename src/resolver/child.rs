//! The proxy variables a child process needs, from what the resolver decides.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{Inner, Resolver, Slot};
use crate::bypass::{BypassRules, Dialect};
use crate::env::Source;
use crate::error::Error;
use crate::proxy::{Proxy, ProxyScheme, Route, Target};
use crate::system::SettingsState;

/// The proxy environment variables for a child process, with what they cannot say.
///
/// `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` name one proxy for every host of a scheme, so a
/// proxy chosen per URL (a PAC script, WPAD) cannot be written in full. See
/// [`Resolver::child_environment`] for how the endpoints a caller names fill the gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildEnvironment {
    http: Option<Proxy>,
    https: Option<Proxy>,
    no_proxy: Vec<String>,
    per_endpoint: bool,
    unexpressed: Vec<String>,
}

impl ChildEnvironment {
    /// The variables to set, as `(name, value)`: `HTTP_PROXY` and `HTTPS_PROXY` for the proxies
    /// the resolver chose, with their credentials in the URL, and `NO_PROXY` when a proxy is set.
    /// Where names are case-sensitive each is given in upper and lower case, because some
    /// programs read only the lowercase `http_proxy`. Nothing when everything goes direct.
    pub fn pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        if let Some(proxy) = &self.http {
            pairs.push(("HTTP_PROXY".to_string(), proxy.url_with_credentials()));
        }
        if let Some(proxy) = &self.https {
            pairs.push(("HTTPS_PROXY".to_string(), proxy.url_with_credentials()));
        }
        if !pairs.is_empty() && !self.no_proxy.is_empty() {
            pairs.push(("NO_PROXY".to_string(), self.no_proxy.join(",")));
        }
        if cfg!(windows) {
            return pairs;
        }
        let lowercase: Vec<_> = pairs
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        pairs.extend(lowercase);
        pairs
    }

    /// The proxy for `http:` URLs, when there is one.
    pub fn http_proxy(&self) -> Option<&Proxy> {
        self.http.as_ref()
    }

    /// The proxy for `https:` URLs, when there is one.
    pub fn https_proxy(&self) -> Option<&Proxy> {
        self.https.as_ref()
    }

    /// The `NO_PROXY` entries, loopback and the hosts that were resolved direct included.
    pub fn no_proxy(&self) -> &[String] {
        &self.no_proxy
    }

    /// Whether any proxy was chosen by asking about the endpoints, not read from a setting: the
    /// system's PAC script or WPAD, or a list that names the hosts that use the proxy. The
    /// variables are then right for the endpoints named and a guess for any other host.
    pub fn per_endpoint(&self) -> bool {
        self.per_endpoint
    }

    /// What the variables cannot say, one text each: a bypass entry `NO_PROXY` has no form for
    /// (`<local>`, a glob, a network with a port), or an endpoint that goes through another
    /// proxy than the one set for its scheme, or through SOCKS.
    pub fn unexpressed(&self) -> &[String] {
        &self.unexpressed
    }
}

/// What the first usable route of an answer asks for.
enum Wanted {
    Direct,
    Proxy(Proxy),
    /// Nothing but SOCKS, which the variables are not used for.
    Unsupported,
}

fn wanted(routes: &[Route]) -> Wanted {
    for route in routes {
        match route {
            Route::Direct => return Wanted::Direct,
            Route::Proxy(proxy)
                if matches!(proxy.scheme(), ProxyScheme::Http | ProxyScheme::Https) =>
            {
                return Wanted::Proxy(proxy.clone());
            }
            Route::Proxy(_) => {}
        }
    }
    Wanted::Unsupported
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Http,
    Https,
}

impl Class {
    fn of(target: &Target) -> Option<Self> {
        match target.scheme.as_str() {
            "http" | "ws" => Some(Self::Http),
            "https" | "wss" => Some(Self::Https),
            _ => None,
        }
    }

    fn probe(self) -> Target {
        let (scheme, port) = match self {
            Self::Http => ("http", 80),
            Self::Https => ("https", 443),
        };
        Target {
            scheme: scheme.to_string(),
            host: "child-probe.invalid".to_string(),
            port,
        }
    }
}

/// The settings a resolver holds, before any endpoint is asked about.
#[derive(Default)]
struct Plan {
    http: Option<Proxy>,
    https: Option<Proxy>,
    per_endpoint: bool,
    unexpressed: Vec<String>,
    bypass: Vec<BypassRules>,
}

impl Plan {
    fn slot(&mut self, class: Class) -> &mut Option<Proxy> {
        match class {
            Class::Http => &mut self.http,
            Class::Https => &mut self.https,
        }
    }

    fn set(&mut self, class: Class, routes: &[Route]) {
        match wanted(routes) {
            Wanted::Proxy(proxy) => *self.slot(class) = Some(proxy),
            Wanted::Direct => {}
            Wanted::Unsupported => self.unexpressed.push(alloc::format!(
                "{} proxies: only SOCKS",
                if class == Class::Http {
                    "http"
                } else {
                    "https"
                }
            )),
        }
    }
}

impl Resolver {
    /// The proxy variables for a child process, from what this resolver decides.
    ///
    /// A proxy that a setting names for every host (an explicit proxy, the proxy variables, the
    /// system's manual proxies) becomes `HTTP_PROXY` or `HTTPS_PROXY`, and its bypass list and
    /// loopback become `NO_PROXY`. A proxy chosen per URL (a PAC script, WPAD, a list naming the
    /// hosts that use the proxy) cannot be written that way, so it is asked about `endpoints`
    /// (the URLs the child will use): the first proxy answered for a scheme is set for it, an
    /// endpoint answered direct goes in `NO_PROXY`, and an endpoint answered with another proxy
    /// is listed in [`ChildEnvironment::unexpressed`]. Endpoints are also checked against a
    /// proxy that every host uses, so a bypass `NO_PROXY` has no form for (`<local>`, a glob)
    /// still reaches the child as the endpoint's host.
    ///
    /// # Errors
    ///
    /// An endpoint that is not a URL with a scheme and host, and anything [`Resolver::lookup`]
    /// reports for one.
    pub fn child_environment<S: AsRef<str>>(
        &self,
        endpoints: impl IntoIterator<Item = S>,
    ) -> Result<ChildEnvironment, Error> {
        let inner = &*self.inner;
        let mut plan = plan(inner);

        // Pass 1: what each endpoint is told.
        let mut asked = Vec::new();
        for endpoint in endpoints {
            let url = endpoint.as_ref();
            let target = Target::parse(url)?;
            let Some(class) = Class::of(&target) else {
                plan.unexpressed
                    .push(alloc::format!("{url}: not http or https"));
                continue;
            };
            asked.push((url.to_string(), target, class, wanted(&self.lookup(url)?)));
        }

        // Pass 2: a scheme nobody named a proxy for takes the first one its endpoints got.
        if plan.per_endpoint {
            for class in [Class::Http, Class::Https] {
                if plan.slot(class).is_none() {
                    let first = asked.iter().find_map(|(_, _, c, wanted)| match wanted {
                        Wanted::Proxy(proxy) if *c == class => Some(proxy.clone()),
                        _ => None,
                    });
                    *plan.slot(class) = first;
                }
            }
        }

        // Pass 3: the bypass list, then what the endpoints need beyond it.
        let mut no_proxy = Vec::new();
        for rules in &plan.bypass {
            let list = rules.to_no_proxy();
            for entry in list.entries {
                if !no_proxy.contains(&entry) {
                    no_proxy.push(entry);
                }
            }
            plan.unexpressed.extend(list.unexpressed);
        }
        for (url, target, class, wanted) in asked {
            let set = plan.slot(class).clone();
            match wanted {
                Wanted::Direct => {
                    let covered = BypassRules::from_entries(
                        no_proxy.iter().map(String::as_str),
                        Dialect::NoProxy,
                    )
                    .matches(&url);
                    if set.is_some() && !covered {
                        no_proxy.push(target.host);
                    }
                }
                Wanted::Proxy(proxy) if set.as_ref() == Some(&proxy) => {}
                Wanted::Proxy(_) | Wanted::Unsupported => plan.unexpressed.push(url),
            }
        }
        Ok(ChildEnvironment {
            http: plan.http,
            https: plan.https,
            no_proxy,
            per_endpoint: plan.per_endpoint,
            unexpressed: plan.unexpressed,
        })
    }
}

/// The proxies and bypass lists the resolver's settings name for every host.
fn plan(inner: &Inner) -> Plan {
    let mut plan = Plan {
        bypass: alloc::vec![inner.no_proxy.clone()],
        ..Plan::default()
    };
    let classes = [Class::Http, Class::Https];
    if let Some(setting) = &inner.setting {
        match setting {
            Slot::Routes(routes) => {
                for class in classes {
                    plan.set(class, &inner.finish(routes.clone()));
                }
            }
            Slot::Pac(_) => plan.per_endpoint = true,
        }
    } else if let Some(variables) = &inner.variables {
        for class in classes {
            match variables.source_for(&class.probe()) {
                Some(Source::Routes(routes)) => plan.set(class, &inner.finish(routes)),
                Some(_) => plan.per_endpoint = true,
                None => {}
            }
        }
    } else if let Some(system) = &inner.system {
        let (settings, slots) = system.settings();
        if settings.state == SettingsState::Direct {
            return plan;
        }
        if !slots.is_empty() || settings.bypass.is_reversed() {
            plan.per_endpoint = true;
        } else {
            for class in classes {
                plan.set(class, &inner.finish(settings.manual_routes(&class.probe())));
            }
            plan.bypass.push(settings.bypass.clone());
        }
    }
    plan
}
