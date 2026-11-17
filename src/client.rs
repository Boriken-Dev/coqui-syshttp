//! `ureq` that sends through the system's proxy, logs in to it, and verifies and authenticates
//! with the system's TLS.
//!
//! Every request asks the [`Resolver`] for its routes, connects through the first that works with
//! a [`ProxyConnector`] and, for `https:`, speaks TLS with a [`Tls`]. A plain `http:` URL through
//! a proxy is tunnelled with `CONNECT`, as `ureq` does for every proxy.

use alloc::string::ToString;
use alloc::sync::Arc;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use std::io::{self, Read, Write};
use std::net::TcpStream;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use ureq::config::Config;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver as UreqResolver};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
};

use crate::connect::{Connection, ProxyConnector};
use crate::error::Error;
use crate::resolver::Resolver;
use crate::tls::Tls;

/// Builds a `ureq` agent that follows the system.
#[derive(Debug)]
#[must_use]
pub struct AgentBuilder {
    resolver: Option<Resolver>,
    tls: Option<Tls>,
    connector: Option<ProxyConnector>,
    config: Option<Config>,
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentBuilder {
    /// Starts an agent that follows the system: [`Resolver::system`], a browser's TLS, a plain
    /// connector.
    pub fn new() -> Self {
        Self {
            resolver: None,
            tls: None,
            connector: None,
            config: None,
        }
    }

    /// Who decides the proxy (default: [`Resolver::system`]).
    pub fn resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// How servers are verified and client certificates chosen (default: the system's).
    pub fn tls(mut self, tls: Tls) -> Self {
        self.tls = Some(tls);
        self
    }

    /// How connections and proxy logins are made.
    pub fn connector(mut self, connector: ProxyConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    /// The `ureq` settings: timeouts, redirects, the user agent. Its own proxy and TLS settings are
    /// not used.
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// The agent.
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] when the operating system's verifier cannot start.
    pub fn build(self) -> Result<ureq::Agent, Error> {
        let tls = match self.tls {
            Some(tls) => tls,
            None => Tls::builder().build()?,
        };
        let connector = SystemConnector {
            resolver: self.resolver.unwrap_or_else(Resolver::system),
            connector: self.connector.unwrap_or_default(),
            tls: Arc::new(tls),
        };
        Ok(ureq::Agent::with_parts(
            self.config.unwrap_or_default(),
            connector,
            NoLookup,
        ))
    }
}

/// A name resolver that resolves nothing: the connector reaches the host itself, directly or
/// through a proxy, and a host behind a proxy may have no address where this client runs.
#[derive(Debug)]
struct NoLookup;

impl UreqResolver for NoLookup {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let mut addresses = self.empty();
        addresses.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        Ok(addresses)
    }
}

#[derive(Debug)]
struct SystemConnector {
    resolver: Resolver,
    connector: ProxyConnector,
    tls: Arc<Tls>,
}

fn to_ureq(error: Error) -> ureq::Error {
    match error {
        Error::Io(error) => ureq::Error::Io(error),
        Error::Login(reason) => ureq::Error::ConnectProxyFailed(alloc::format!("login: {reason}")),
        Error::Refused(reason) => ureq::Error::ConnectProxyFailed(reason.to_string()),
        other => ureq::Error::Io(io::Error::other(other.to_string())),
    }
}

impl Connector<()> for SystemConnector {
    type Out = StreamTransport;

    fn connect(
        &self,
        details: &ConnectionDetails,
        _chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let uri = details.uri;
        let host = uri
            .host()
            .ok_or(ureq::Error::HostNotFound)?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let mut connector = self.connector.clone();
        if let Some(limit) = limit(details.timeout) {
            connector = connector.with_timeout(limit);
        }
        let connection = connector
            .connect_url(&self.resolver, &uri.to_string())
            .map_err(to_ureq)?;
        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );
        if !details.needs_tls() {
            return Ok(Some(StreamTransport {
                io: Io::Plain(connection),
                buffers,
            }));
        }
        let config = self.tls.client_config(&host).map_err(to_ureq)?;
        let name = ServerName::try_from(host)
            .map_err(|_| ureq::Error::Tls("the host is not a valid server name"))?;
        let session = ClientConnection::new(config, name)
            .map_err(|error| ureq::Error::Io(io::Error::other(error)))?;
        let mut stream = StreamOwned::new(session, connection);
        // Finish the handshake here, so a verification failure is reported as one.
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(ureq::Error::Io)?;
        }
        Ok(Some(StreamTransport {
            io: Io::Tls(Box::new(stream)),
            buffers,
        }))
    }
}

enum Io {
    Plain(Connection),
    Tls(Box<StreamOwned<ClientConnection, Connection>>),
}

impl Io {
    fn socket(&self) -> &TcpStream {
        match self {
            Self::Plain(connection) => connection.socket(),
            Self::Tls(stream) => stream.sock.socket(),
        }
    }
}

impl Read for Io {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(connection) => connection.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Io {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(connection) => connection.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(connection) => connection.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// A connection, however it was made, as `ureq` reads and writes it.
struct StreamTransport {
    io: Io,
    buffers: LazyBuffers,
}

impl core::fmt::Debug for StreamTransport {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StreamTransport")
            .field("tls", &matches!(self.io, Io::Tls(_)))
            .finish_non_exhaustive()
    }
}

fn limit(timeout: NextTimeout) -> Option<Duration> {
    timeout.not_zero().map(|duration| *duration)
}

/// The time left, or the timeout error when none is.
fn left(timeout: NextTimeout) -> Result<NextTimeout, ureq::Error> {
    if timeout.after.is_zero() {
        Err(ureq::Error::Timeout(timeout.reason))
    } else {
        Ok(timeout)
    }
}

impl Transport for StreamTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let timeout = left(timeout.for_write())?;
        self.io.socket().set_write_timeout(limit(timeout))?;
        let output = &self.buffers.output()[..amount];
        match self.io.write_all(output) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Err(ureq::Error::Timeout(timeout.reason))
            }
            other => other.map_err(ureq::Error::Io),
        }
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let timeout = left(timeout.for_read())?;
        self.io.socket().set_read_timeout(limit(timeout))?;
        let input = self.buffers.input_append_buf();
        let amount = match self.io.read(input) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(ureq::Error::Timeout(timeout.reason));
            }
            // A server that closes TLS without a close_notify has still sent what it sent.
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => 0,
            other => other.map_err(ureq::Error::Io)?,
        };
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        let socket = self.io.socket();
        if socket.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8];
        let open = matches!((&*socket).read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock);
        socket.set_nonblocking(false).is_ok() && open
    }

    fn is_tls(&self) -> bool {
        matches!(self.io, Io::Tls(_))
    }
}
