//! A programmable loopback HTTP/1.1 origin: every request is passed to a handler, and logged.

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// What the origin received.
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Which connection (0, 1, ...) carried it.
    pub connection: usize,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What the origin answers.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Close the connection after this reply.
    pub close: bool,
    /// Write these bytes instead of a reply built from the fields above.
    pub raw: Option<Vec<u8>>,
    /// Stop answering for this long before writing.
    pub delay: Duration,
}

impl Reply {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            close: false,
            raw: None,
            delay: Duration::ZERO,
        }
    }

    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self::new(200).body(body)
    }

    pub fn redirect(status: u16, location: &str) -> Self {
        Self::new(status).header("Location", location)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    pub fn raw(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.raw = Some(bytes.into());
        self
    }

    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

type Handler = dyn Fn(&Req) -> Reply + Send + Sync;

pub struct Server {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<Req>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

fn read_request(reader: &mut BufReader<TcpStream>, connection: usize) -> Option<Req> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    let mut body = Vec::new();
    if find("transfer-encoding").is_some_and(|value| value.contains("chunked")) {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).ok()?;
            let size = usize::from_str_radix(size.trim(), 16).ok()?;
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk).ok()?;
            body.extend(chunk);
            let mut end = String::new();
            reader.read_line(&mut end).ok()?;
            if size == 0 {
                break;
            }
        }
    } else if let Some(length) =
        find("content-length").and_then(|value| value.parse::<usize>().ok())
    {
        body = vec![0; length];
        reader.read_exact(&mut body).ok()?;
    }
    Some(Req {
        method,
        target,
        headers,
        body,
        connection,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn serve(mut stream: TcpStream, connection: usize, handler: &Handler, log: &Mutex<Vec<Req>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone);
    while let Some(request) = read_request(&mut reader, connection) {
        log.lock().unwrap().push(request.clone());
        let reply = handler(&request);
        if !reply.delay.is_zero() {
            thread::sleep(reply.delay);
        }
        let close = reply.close
            || request
                .header("connection")
                .is_some_and(|value| value.eq_ignore_ascii_case("close"));
        let bytes = match reply.raw {
            Some(raw) => raw,
            None => {
                let mut out =
                    format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status)).into_bytes();
                let has_length = reply
                    .headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
                for (name, value) in &reply.headers {
                    out.extend(format!("{name}: {value}\r\n").bytes());
                }
                if !has_length && !matches!(reply.status, 204 | 304) && request.method != "HEAD" {
                    out.extend(format!("Content-Length: {}\r\n", reply.body.len()).bytes());
                }
                if close {
                    out.extend(b"Connection: close\r\n");
                }
                out.extend(b"\r\n");
                if request.method != "HEAD" {
                    out.extend(&reply.body);
                }
                out
            }
        };
        if stream.write_all(&bytes).is_err() || stream.flush().is_err() {
            return;
        }
        if close {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    }
}

impl Server {
    pub fn start(handler: impl Fn(&Req) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handler: Arc<Handler> = Arc::new(handler);
        let log = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (handler_in, log_in, connections_in, stop_in) = (
            Arc::clone(&handler),
            Arc::clone(&log),
            Arc::clone(&connections),
            Arc::clone(&stop),
        );
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_in.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let connection = connections_in.fetch_add(1, Ordering::SeqCst);
                let (handler, log) = (Arc::clone(&handler_in), Arc::clone(&log_in));
                thread::spawn(move || serve(stream, connection, &*handler, &log));
            }
        });
        Self {
            addr,
            log,
            connections,
            stop,
            thread: Some(thread),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }

    /// The same server under another host name (for a proxy or a cookie domain); the name does
    /// not resolve, so only a proxy or a resolver that maps it reaches the server.
    pub fn url_for(&self, host: &str, path: &str) -> String {
        format!("http://{host}:{}{path}", self.addr.port())
    }

    pub fn log(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
