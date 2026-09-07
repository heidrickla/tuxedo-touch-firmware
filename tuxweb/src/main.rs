// tuxweb -- stage 3: a modern TLS listener for the Tuxedo Touch.
//
// This runs ALONGSIDE Barracuda on a spare port. It replaces nothing yet, so a
// failure here cannot take the panel's web interface down. That is the point of
// the stage: prove rustls serves a real owner-CA certificate on this hardware
// before anything depends on it.
//
//   tuxweb <bind-addr> <chain.pem> <server.key>
//   tuxweb 0.0.0.0:8443 /opt/tuxedo/configuration/tls/chain.pem \
//                       /opt/tuxedo/configuration/tls/server.key
//
// Deliberately single-threaded: available_parallelism() reports 1 on this panel,
// so a thread pool sized by CPU count would be one thread pretending to be many.
// Connections are handled in sequence with a short read timeout.

mod frame;
mod ipc;
mod login;
mod proxy;
mod shim;

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

fn load_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut rd = BufReader::new(File::open(path).map_err(|e| format!("{path}: {e}"))?);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut rd).collect();
    let certs = certs.map_err(|e| format!("{path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{path}: no certificates found"));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let mut rd = BufReader::new(File::open(path).map_err(|e| format!("{path}: {e}"))?);
    // The CA emits PKCS#8. Accept the other shapes too rather than failing
    // obscurely if someone hands us an openssl-generated key.
    rustls_pemfile::private_key(&mut rd)
        .map_err(|e| format!("{path}: {e}"))?
        .ok_or_else(|| format!("{path}: no private key found"))
}

/// Build a TLS config from TUXWEB_CHAIN and TUXWEB_KEY, or None for plaintext.
/// Exits rather than silently serving in the clear if one is set and unusable:
/// a listener that was meant to be encrypted and is not should not start.
fn tls_from_env() -> Option<Arc<ServerConfig>> {
    let (chain_p, key_p) = (std::env::var("TUXWEB_CHAIN").ok()?, std::env::var("TUXWEB_KEY").ok()?);
    let build = || -> Result<Arc<ServerConfig>, String> {
        let chain = load_chain(&chain_p)?;
        let key = load_key(&key_p)?;
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map(Arc::new)
            .map_err(|e| format!("bad certificate/key pair: {e}"))
    };
    match build() {
        Ok(c) => { println!("tuxweb: serving TLS from {chain_p}"); Some(c) }
        Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // stage 3 shim: re-serve the vendor push stream byte for byte.
    //   tuxweb --shim <upstream host:port> <cookie> <bind-addr>
    // The cookie is passed in; this binary never handles the panel password.
    // Log in from HERE and shim: the session must be created by the host that
    // will use it, because panel sessions are bound to the source address.
    //   tuxweb --shim-login <host:port> <user> <password-file> <bind-addr>
    // The password comes from a file so it never appears in `ps`.
    if args.len() == 6 && args[1] == "--shim-login" {
        let pw = match std::fs::read_to_string(&args[4]) {
            Ok(p) => p.lines().next().unwrap_or("").to_string(),
            Err(e) => { eprintln!("tuxweb: {}: {e}", args[4]); std::process::exit(1); }
        };
        let pw = pw.split_once(':').map(|(_, p)| p.to_string()).unwrap_or(pw);
        let cookie = match login::login(&args[2], &args[3], &pw) {
            Ok(c) => c,
            Err(e) => { eprintln!("tuxweb: login: {e}"); std::process::exit(1); }
        };
        println!("tuxweb: logged in, session acquired from this host");
        let s = shim::Shim {
            upstream: args[2].clone(),
            cookie: std::cell::RefCell::new(cookie),
            bind: args[5].clone(),
            token: std::env::var("TUXWEB_TOKEN").ok().filter(|t| !t.is_empty()),
            // keep the credentials so the session can be renewed when it expires
            creds: Some(shim::Creds { user: args[3].clone(), password: pw }),
            // TUXWEB_CHAIN + TUXWEB_KEY turn the listener into a TLS one. The
            // upstream hop stays plaintext on loopback: the vendor certificate
            // is expired and its key is public, so this end is where TLS is
            // worth terminating.
            tls: tls_from_env(),
        };
        if let Err(e) = s.run() {
            eprintln!("tuxweb: {e}");
            std::process::exit(1);
        }
        return;
    }

    if args.len() == 5 && args[1] == "--shim" {
        let s = shim::Shim {
            upstream: args[2].clone(),
            cookie: std::cell::RefCell::new(args[3].clone()),
            bind: args[4].clone(),
            token: std::env::var("TUXWEB_TOKEN").ok().filter(|t| !t.is_empty()),
            // a bare cookie cannot be renewed; expiry is fatal and says so
            creds: None,
            tls: tls_from_env(),
        };
        if let Err(e) = s.run() {
            eprintln!("tuxweb: {e}");
            std::process::exit(1);
        }
        return;
    }

    if args.len() != 4 {
        eprintln!("usage: {} <bind-addr> <chain.pem> <server.key>", args[0]);
        eprintln!("       {} --shim <host:port> <cookie> <bind-addr>", args[0]);
        eprintln!("       {} --shim-login <host:port> <user> <pwfile> <bind-addr>", args[0]);
        std::process::exit(2);
    }
    let (addr, chain_path, key_path) = (&args[1], &args[2], &args[3]);

    let chain = match load_chain(chain_path) {
        Ok(c) => c,
        Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
    };
    let key = match load_key(key_path) {
        Ok(k) => k,
        Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
    };
    println!("tuxweb: {} certificate(s) from {}", chain.len(), chain_path);

    let config = match ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
    {
        Ok(c) => Arc::new(c),
        Err(e) => { eprintln!("tuxweb: bad certificate/key pair: {e}"); std::process::exit(1); }
    };

    let listener = match TcpListener::bind(addr.as_str()) {
        Ok(l) => l,
        Err(e) => { eprintln!("tuxweb: bind {addr}: {e}"); std::process::exit(1); }
    };
    println!("tuxweb: listening on {addr}");
    println!("tuxweb: ready");

    for stream in listener.incoming() {
        let sock = match stream {
            Ok(s) => s,
            Err(e) => { eprintln!("tuxweb: accept: {e}"); continue; }
        };
        let peer = sock.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));

        let conn = match ServerConnection::new(config.clone()) {
            Ok(c) => c,
            Err(e) => { eprintln!("tuxweb: {peer}: session: {e}"); continue; }
        };
        let mut tls = StreamOwned::new(conn, sock);

        // Read whatever the client sends, up to the end of the request head.
        let mut buf = [0u8; 2048];
        let n = match tls.read(&mut buf) {
            Ok(n) => n,
            Err(e) => { eprintln!("tuxweb: {peer}: handshake/read: {e}"); continue; }
        };
        let req = String::from_utf8_lossy(&buf[..n]);
        let line = req.lines().next().unwrap_or("");
        let proto = tls.conn.protocol_version()
            .map(|v| format!("{v:?}")).unwrap_or_else(|| "?".into());
        let suite = tls.conn.negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite())).unwrap_or_else(|| "?".into());
        println!("tuxweb: {peer} {proto} {suite} -- {line}");

        let body = format!(
            "tuxweb stage 3\nprotocol {proto}\ncipher {suite}\npeer {peer}\n"
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        );
        if let Err(e) = tls.write_all(resp.as_bytes()) {
            eprintln!("tuxweb: {peer}: write: {e}");
        }
        let _ = tls.flush();
    }
}
