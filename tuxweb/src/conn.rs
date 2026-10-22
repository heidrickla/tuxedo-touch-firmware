//! Accepted connections: a thread each, a cap on how many at once, and a
//! deadline on the request.
//!
//! Every listener here (`serve`'s push + API, its `80 -> 301` leg, the bench
//! `shim`) goes through [`serve`], so a client that connects and stalls holds
//! only its own thread, never the accept loop. [`Conn`] bounds the whole
//! request (TLS handshake, head and body) by one deadline, so a client that
//! trickles a byte just inside the per-read timeout still runs out of time.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Longest one read may block.
pub const IDLE: Duration = Duration::from_secs(10);

/// Budget for the TLS handshake, the request head and its body together.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(15);

/// A socket whose reads fail with `TimedOut` once its deadline has passed.
pub struct Conn {
    sock: TcpStream,
    deadline: Option<Instant>,
}

impl Conn {
    pub fn new(sock: TcpStream, deadline: Option<Instant>) -> Conn {
        let _ = sock.set_read_timeout(Some(IDLE));
        Conn { sock, deadline }
    }

    /// A connection whose request must be complete within [`REQUEST_DEADLINE`].
    pub fn for_request(sock: TcpStream) -> Conn {
        Conn::new(sock, Some(Instant::now() + REQUEST_DEADLINE))
    }

    /// End the request deadline; reads go back to the plain [`IDLE`] timeout.
    pub fn clear_deadline(&mut self) {
        self.deadline = None;
        let _ = self.sock.set_read_timeout(Some(IDLE));
    }

    pub fn get_ref(&self) -> &TcpStream {
        &self.sock
    }
}

impl Read for Conn {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if let Some(d) = self.deadline {
            let left = d.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "request deadline passed",
                ));
            }
            self.sock.set_read_timeout(Some(left.min(IDLE)))?;
        }
        self.sock.read(b)
    }
}

impl Write for Conn {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.sock.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

/// One of `max` concurrent connections; gives its place back on drop.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(busy: &Arc<AtomicUsize>, max: usize) -> Option<Slot> {
        busy.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < max).then_some(n + 1)
        })
        .ok()
        .map(|_| Slot(Arc::clone(busy)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Accept forever, running `handle(socket, peer)` on a thread per connection,
/// at most `max` at once. A connection over the cap is closed at once.
pub fn serve<F>(listener: TcpListener, max: usize, name: &'static str, handle: F)
where
    F: Fn(TcpStream, String) + Send + Sync + 'static,
{
    let handle = Arc::new(handle);
    let busy = Arc::new(AtomicUsize::new(0));
    for s in listener.incoming() {
        let sock = match s {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{name}: accept: {e}");
                continue;
            }
        };
        let peer = sock.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        let Some(slot) = Slot::take(&busy, max) else {
            eprintln!("{name}: {peer}: refused, {max} connections already open");
            continue;
        };
        let h = Arc::clone(&handle);
        let spawned = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let _slot = slot;
                h(sock, peer);
            });
        if let Err(e) = spawned {
            eprintln!("{name}: thread: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        (c, s)
    }

    #[test]
    fn a_trickled_head_stops_at_the_deadline() {
        let (mut client, server) = pair();
        // One byte every 200 ms for 5 s: each read returns long before the
        // per-read timeout, so only the deadline can end it.
        let feeder = std::thread::spawn(move || {
            for _ in 0..25 {
                if client.write_all(b"G").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let mut c = Conn::new(server, Some(Instant::now() + Duration::from_millis(700)));
        let t0 = Instant::now();
        let r = crate::proxy::read_head(&mut c, 16 * 1024);
        let took = t0.elapsed();
        assert!(r.is_err(), "a head that never completes must fail");
        assert!(took < Duration::from_secs(2), "took {took:?}");
        drop(c);
        let _ = feeder.join();
    }

    #[test]
    fn a_head_inside_the_deadline_is_read() {
        let (mut client, server) = pair();
        client.write_all(b"GET /x HTTP/1.1\r\n\r\nbody").unwrap();
        let mut c = Conn::for_request(server);
        let (head, rest) = crate::proxy::read_head(&mut c, 16 * 1024).unwrap();
        assert_eq!(head, "GET /x HTTP/1.1\r\n\r\n");
        assert_eq!(rest, b"body");
    }

    fn start(max: usize) -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            serve(l, max, "conn-test", |sock, _peer| {
                let mut c = Conn::new(sock, Some(Instant::now() + Duration::from_secs(5)));
                if crate::proxy::read_head(&mut c, 1024).is_ok() {
                    let _ = c.write_all(b"ok");
                }
            })
        });
        addr
    }

    fn ask(addr: std::net::SocketAddr) -> Vec<u8> {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let _ = s.write_all(b"GET / HTTP/1.1\r\n\r\n");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }

    #[test]
    fn a_silent_client_does_not_hold_the_listener() {
        let addr = start(4);
        let _silent = TcpStream::connect(addr).unwrap();
        let t0 = Instant::now();
        assert_eq!(ask(addr), b"ok");
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    }

    #[test]
    fn connections_over_the_cap_are_closed_and_slots_come_back() {
        let addr = start(1);
        let silent = TcpStream::connect(addr).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(ask(addr), b"", "over the cap: closed without an answer");
        drop(silent);
        let t0 = Instant::now();
        loop {
            if ask(addr) == b"ok" {
                break;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(3),
                "slot never came back"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
