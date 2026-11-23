//! Loopback stand-ins: a proxy that requires a login, and an origin server.

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// What a request to the stand-in proxy carried.
#[derive(Debug, Clone)]
pub struct Seen {
    pub request_line: String,
    pub headers: Vec<(String, String)>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The login the stand-in proxy demands.
#[derive(Debug, Clone)]
pub enum Require {
    Nothing,
    /// `Proxy-Authorization: Basic base64(user:password)`.
    Basic(&'static str, &'static str),
    /// A header, exactly: `(name, value)`.
    Header(&'static str, &'static str),
    /// A Negotiate challenge that is never satisfied.
    Negotiate,
}

/// A loopback HTTP proxy that tunnels every `CONNECT` to one fixed origin, after the login.
pub struct StandInProxy {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    users: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl StandInProxy {
    pub fn start(require: Require, origin: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let users = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen_in, users_in, stop_in) =
            (Arc::clone(&seen), Arc::clone(&users), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_in.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (seen, users, require) =
                    (Arc::clone(&seen_in), Arc::clone(&users_in), require.clone());
                thread::spawn(move || serve(stream, &require, origin, &seen, &users));
            }
        });
        Self {
            addr,
            seen,
            users,
            stop,
            thread: Some(thread),
        }
    }

    /// The accounts a Negotiate handshake authenticated.
    pub fn users(&self) -> Vec<String> {
        self.users.lock().unwrap().clone()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for StandInProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_head(stream: &mut TcpStream) -> Option<Seen> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?.to_string();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    Some(Seen {
        request_line,
        headers,
    })
}

fn allowed(require: &Require, seen: &Seen) -> bool {
    match require {
        Require::Nothing => true,
        Require::Basic(user, password) => {
            use base64::Engine as _;
            let expected = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
            );
            seen.header("proxy-authorization") == Some(expected.as_str())
        }
        Require::Header(name, value) => seen.header(name) == Some(*value),
        Require::Negotiate => false,
    }
}

fn serve(
    mut client: TcpStream,
    require: &Require,
    origin: SocketAddr,
    log: &Mutex<Vec<Seen>>,
    users: &Mutex<Vec<String>>,
) {
    client.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let _ = users;
    loop {
        let Some(seen) = read_head(&mut client) else {
            return;
        };
        log.lock().unwrap().push(seen.clone());
        let challenge = match require {
            Require::Negotiate => Some("Negotiate".to_string()),
            other => (!allowed(other, &seen)).then(|| "Basic realm=\"stand-in\"".to_string()),
        };
        if let Some(challenge) = challenge {
            let reply = format!(
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n"
            );
            if client.write_all(reply.as_bytes()).is_err() {
                return;
            }
            continue;
        }
        if !seen.request_line.starts_with("CONNECT ") {
            let _ =
                client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        let Ok(upstream) = TcpStream::connect(origin) else {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        pipe(client, upstream);
        return;
    }
}

fn pipe(client: TcpStream, upstream: TcpStream) {
    let (mut client_read, mut upstream_write) =
        (client.try_clone().unwrap(), upstream.try_clone().unwrap());
    let forward = thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let (mut upstream_read, mut client_write) = (upstream, client);
    let _ = std::io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = forward.join();
}

/// A loopback HTTP origin that answers every request with `body`.
pub struct StandInOrigin {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl StandInOrigin {
    pub fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_in = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_in.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream else { continue };
                thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    if read_head(&mut stream).is_some() {
                        let reply = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(reply.as_bytes());
                    }
                });
            }
        });
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for StandInOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Sends a `GET` over `stream` and returns the whole reply as text.
pub fn get(stream: &mut (impl Read + Write), host: &str) -> String {
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    reply
}

#[cfg(feature = "ureq")]
pub mod login_origin;
#[cfg(feature = "tls")]
pub mod pki;
pub mod socks_server;
#[cfg(feature = "tls")]
pub mod tls_server;
