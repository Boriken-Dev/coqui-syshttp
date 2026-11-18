//! A loopback SOCKS 4, 4a and 5 proxy that tunnels every request to one fixed origin.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// What the stand-in saw in one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub version: u8,
    /// The destination as written: a name, or an address in text.
    pub destination: String,
    /// Whether the destination was written as a name (SOCKS 5 domain, SOCKS 4a).
    pub name: bool,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

pub struct SocksServer {
    pub addr: SocketAddr,
    asked: Arc<Mutex<Vec<Asked>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SocksServer {
    /// `login` is the user and password SOCKS 5 demands; none demands nothing.
    pub fn start(origin: SocketAddr, login: Option<(&'static str, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (asked_in, stop_in) = (Arc::clone(&asked), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_in.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let asked = Arc::clone(&asked_in);
                thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    serve(stream, origin, login, &asked);
                });
            }
        });
        Self {
            addr,
            asked,
            stop,
            thread: Some(thread),
        }
    }

    pub fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }
}

impl Drop for SocksServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn byte(stream: &mut TcpStream) -> Option<u8> {
    let mut one = [0u8; 1];
    stream.read_exact(&mut one).ok()?;
    Some(one[0])
}

fn bytes(stream: &mut TcpStream, count: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; count];
    stream.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

fn until_nul(stream: &mut TcpStream) -> Option<String> {
    let mut text = Vec::new();
    loop {
        match byte(stream)? {
            0 => return Some(String::from_utf8_lossy(&text).into_owned()),
            other => text.push(other),
        }
    }
}

fn serve(
    mut stream: TcpStream,
    origin: SocketAddr,
    login: Option<(&'static str, &'static str)>,
    log: &Mutex<Vec<Asked>>,
) {
    let Some(version) = byte(&mut stream) else {
        return;
    };
    let asked = match version {
        4 => socks4(&mut stream),
        5 => socks5(&mut stream, login),
        _ => None,
    };
    let Some((asked, ok)) = asked else { return };
    log.lock().unwrap().push(asked);
    if !ok {
        return;
    }
    let Ok(upstream) = TcpStream::connect(origin) else {
        return;
    };
    pipe(stream, upstream);
}

fn socks4(stream: &mut TcpStream) -> Option<(Asked, bool)> {
    let command = byte(stream)?;
    let port = u16::from_be_bytes(bytes(stream, 2)?.try_into().ok()?);
    let address: [u8; 4] = bytes(stream, 4)?.try_into().ok()?;
    let user = until_nul(stream)?;
    let (destination, name) = if address[..3] == [0, 0, 0] && address[3] != 0 {
        (until_nul(stream)?, true)
    } else {
        (std::net::Ipv4Addr::from(address).to_string(), false)
    };
    let granted = command == 1;
    stream
        .write_all(&[0, if granted { 0x5a } else { 0x5b }, 0, 0, 0, 0, 0, 0])
        .ok()?;
    Some((
        Asked {
            version: 4,
            destination,
            name,
            port,
            user: (!user.is_empty()).then_some(user),
            password: None,
        },
        granted,
    ))
}

fn socks5(
    stream: &mut TcpStream,
    login: Option<(&'static str, &'static str)>,
) -> Option<(Asked, bool)> {
    let count = byte(stream)?;
    let methods = bytes(stream, count as usize)?;
    let mut user = None;
    let mut password = None;
    match login {
        Some((expected_user, expected_password)) => {
            if !methods.contains(&2) {
                stream.write_all(&[5, 0xff]).ok()?;
                return None;
            }
            stream.write_all(&[5, 2]).ok()?;
            byte(stream)?;
            let user_length = byte(stream)? as usize;
            let got_user = String::from_utf8_lossy(&bytes(stream, user_length)?).into_owned();
            let password_length = byte(stream)? as usize;
            let got_password =
                String::from_utf8_lossy(&bytes(stream, password_length)?).into_owned();
            let good = got_user == expected_user && got_password == expected_password;
            stream.write_all(&[1, u8::from(!good)]).ok()?;
            if !good {
                return None;
            }
            user = Some(got_user);
            password = Some(got_password);
        }
        None => stream.write_all(&[5, 0]).ok()?,
    }
    let head = bytes(stream, 4)?;
    let (destination, name) = match head[3] {
        1 => (
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes(stream, 4)?).ok()?).to_string(),
            false,
        ),
        4 => (
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes(stream, 16)?).ok()?).to_string(),
            false,
        ),
        3 => {
            let length = byte(stream)? as usize;
            (
                String::from_utf8_lossy(&bytes(stream, length)?).into_owned(),
                true,
            )
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(bytes(stream, 2)?.try_into().ok()?);
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).ok()?;
    Some((
        Asked {
            version: 5,
            destination,
            name,
            port,
            user,
            password,
        },
        true,
    ))
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
