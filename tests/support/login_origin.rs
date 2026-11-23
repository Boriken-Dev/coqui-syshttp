//! A loopback HTTP origin that keeps connections alive and demands a login.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// What the origin demands.
#[derive(Debug, Clone)]
pub enum Demand {
    Nothing,
    /// `Authorization: Basic base64(user:password)`.
    Basic(&'static str, &'static str),
    /// Redirect every request to this URL.
    Redirect(String),
}

/// One request the origin received.
#[derive(Debug, Clone)]
pub struct Logged {
    pub connection: usize,
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body_length: usize,
}

pub struct LoginOrigin {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<Logged>>>,
    users: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl LoginOrigin {
    pub fn start(demand: Demand) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let users = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log_in, users_in, stop_in) = (Arc::clone(&log), Arc::clone(&users), Arc::clone(&stop));
        let counter = Arc::new(AtomicUsize::new(0));
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_in.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let id = counter.fetch_add(1, Ordering::SeqCst);
                let (demand, log, users) =
                    (demand.clone(), Arc::clone(&log_in), Arc::clone(&users_in));
                thread::spawn(move || serve(stream, id, &demand, &log, &users));
            }
        });
        Self {
            addr,
            log,
            users,
            stop,
            thread: Some(thread),
        }
    }

    pub fn url(&self, host: &str, path: &str) -> String {
        format!("http://{host}:{}{path}", self.addr.port())
    }

    pub fn log(&self) -> Vec<Logged> {
        self.log.lock().unwrap().clone()
    }

    /// The accounts a security-package exchange authenticated.
    pub fn users(&self) -> Vec<String> {
        self.users.lock().unwrap().clone()
    }
}

impl Drop for LoginOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The request line, the headers and the length of the body read.
type Request = (String, Vec<(String, String)>, usize);

fn read_request(stream: &mut TcpStream) -> Option<Request> {
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
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).ok()?;
    Some((request_line, headers, length))
}

fn reply(stream: &mut TcpStream, status: &str, headers: &[String], body: &str) -> bool {
    let mut text = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for header in headers {
        text.push_str(header);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    text.push_str(body);
    stream.write_all(text.as_bytes()).is_ok()
}

fn serve(
    mut stream: TcpStream,
    connection: usize,
    demand: &Demand,
    log: &Mutex<Vec<Logged>>,
    users: &Mutex<Vec<String>>,
) {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let _ = users;
    while let Some((request_line, headers, body_length)) = read_request(&mut stream) {
        let mut words = request_line.split(' ');
        let method = words.next().unwrap_or("").to_string();
        let path = words.next().unwrap_or("").to_string();
        let authorization = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone());
        log.lock().unwrap().push(Logged {
            connection,
            method,
            path,
            authorization: authorization.clone(),
            body_length,
        });
        let sent = match demand {
            Demand::Nothing => reply(&mut stream, "200 OK", &[], "ok"),
            Demand::Basic(user, password) => {
                let expected = format!("Basic {}", STANDARD.encode(format!("{user}:{password}")));
                if authorization.as_deref() == Some(expected.as_str()) {
                    reply(&mut stream, "200 OK", &[], "welcome")
                } else {
                    reply(
                        &mut stream,
                        "401 Unauthorized",
                        &["WWW-Authenticate: Basic realm=\"stand-in\"".to_string()],
                        "denied",
                    )
                }
            }
            Demand::Redirect(url) => {
                reply(&mut stream, "302 Found", &[format!("Location: {url}")], "")
            }
        };
        if !sent {
            return;
        }
    }
}
