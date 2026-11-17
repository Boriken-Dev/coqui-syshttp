//! A loopback TLS server that asks for a client certificate and records what it was sent.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

use super::pki::Leaf;

/// How the server treats client certificates.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// Never asks.
    Off,
    /// Asks, and lets a client with none through.
    Optional,
    /// Asks, and refuses a client with none.
    Required,
}

pub struct TlsServer {
    pub addr: SocketAddr,
    /// The leaf certificate each connection presented, if any, in connection order.
    pub presented: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TlsServer {
    pub fn start(
        server: &Leaf,
        client_roots: &[CertificateDer<'static>],
        auth: ClientAuth,
    ) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = match auth {
            ClientAuth::Off => builder.with_no_client_auth(),
            ClientAuth::Optional | ClientAuth::Required => {
                let mut roots = RootCertStore::empty();
                for root in client_roots {
                    roots.add(root.clone()).unwrap();
                }
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
                let verifier = if auth == ClientAuth::Optional {
                    verifier.allow_unauthenticated()
                } else {
                    verifier
                };
                builder.with_client_cert_verifier(verifier.build().unwrap())
            }
        };
        let config = Arc::new(
            builder
                .with_single_cert(server.chain.clone(), server.key())
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let presented = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (presented_in, stop_in) = (Arc::clone(&presented), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_in.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (config, presented) = (Arc::clone(&config), Arc::clone(&presented_in));
                thread::spawn(move || serve(stream, config, &presented));
            }
        });
        Self {
            addr,
            presented,
            stop,
            thread: Some(thread),
        }
    }

    pub fn presented(&self) -> Vec<Option<Vec<u8>>> {
        self.presented.lock().unwrap().clone()
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(stream: TcpStream, config: Arc<ServerConfig>, presented: &Mutex<Vec<Option<Vec<u8>>>>) {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let Ok(connection) = ServerConnection::new(config) else {
        return;
    };
    let mut tls = StreamOwned::new(connection, stream);
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let certificate = tls
        .conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|der| der.as_ref().to_vec());
    let reply = if certificate.is_some() {
        "client certificate seen"
    } else {
        "no client certificate"
    };
    presented.lock().unwrap().push(certificate);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
    let _ = tls.write_all(response.as_bytes());
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// A `GET /` over TLS to `addr` for `host`, using `config`; the reply text, or the failure.
pub fn https_get(
    config: Arc<ClientConfig>,
    addr: SocketAddr,
    host: &str,
) -> Result<String, String> {
    let name = ServerName::try_from(host.to_string()).unwrap();
    let connection = ClientConnection::new(config, name).map_err(|error| error.to_string())?;
    let tcp = TcpStream::connect(addr).map_err(|error| error.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut tls = StreamOwned::new(connection, tcp);
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let mut reply = String::new();
    match tls.read_to_string(&mut reply) {
        Ok(_) => Ok(reply),
        Err(error) if !reply.is_empty() && error.kind() == std::io::ErrorKind::UnexpectedEof => {
            Ok(reply)
        }
        Err(error) => Err(error.to_string()),
    }
}
