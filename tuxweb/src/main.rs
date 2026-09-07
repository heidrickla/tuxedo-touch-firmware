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

mod accounts;
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

/// May a password cross an unencrypted client connection?
///
/// Default no. `tls/THREAT-MODEL.md` section 5 is about a login that succeeds
/// over plain HTTP and then cannot use the session it was given, which is worse
/// than a refusal because nothing reports it. Only an explicit `1` turns it back
/// on, so a stray empty variable does not.
fn plaintext_login_allowed() -> bool {
    std::env::var("TUXWEB_ALLOW_PLAINTEXT_LOGIN").ok().as_deref() == Some("1")
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

/// Stage 5: stand where Barracuda stands and do nothing but hand over.
///
/// `supervis` relaunches whatever lives at `/opt/webserver/Barracuda`, and
/// whether it accepts a different binary there is the riskiest unknown in the
/// whole replacement plan. This isolates that question from every other one:
/// the vendor moves to `vendor/Barracuda`, `tuxweb` takes its place, and all
/// `tuxweb` does is `execve` the vendor with the original argv. The vendor
/// still does 100% of the work, so if `supervis` objects we learn it while
/// nothing depends on us.
///
/// `execve` and not fork: the pid must not change, because `supervis` is
/// watching it. §5.4 measured that `comm` follows the new basename, and the
/// basename is still `Barracuda`, so the check it does still matches.
///
/// The target is verified before the exec. A missing target here would exit,
/// `supervis` would relaunch, and a relaunch loop reboots the panel via the
/// watchdog (threat model §8) -- so the failure has to be loud and it has to
/// happen before anything is disturbed, not after.
fn passthrough(argv0: &str, forward: &[String]) -> ! {
    use std::os::unix::process::CommandExt;

    let target = std::env::var("TUXWEB_EXEC")
        .unwrap_or_else(|_| "/opt/webserver/vendor/Barracuda".to_string());

    match std::fs::metadata(&target) {
        Ok(m) => {
            if !m.is_file() {
                eprintln!("tuxweb passthrough: {target} is not a file; REFUSING to exec");
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("tuxweb passthrough: {target}: {e}");
            eprintln!("tuxweb passthrough: the vendor binary is not where it was \
                       expected. Put it back at /opt/webserver/Barracuda.");
            std::process::exit(2);
        }
    }

    eprintln!("tuxweb passthrough: exec {target} (pid {} kept)", std::process::id());
    let err = std::process::Command::new(&target)
        .args(forward)
        .arg0(argv0)             // keep the basename supervis matches on
        .exec();
    eprintln!("tuxweb passthrough: exec {target} failed: {err}");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Invoked under the vendor's own name, or told to explicitly: hand over.
    // Checked before anything else so no other argument parsing can shadow it.
    let called_as = std::path::Path::new(&args[0])
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if called_as == "Barracuda" {
        passthrough(&args[0], &args[1..]);
    }
    if args.get(1).map(String::as_str) == Some("--passthrough") {
        // explicit form, for testing off the panel: the name to exec under is
        // still the vendor's, because that is what supervis matches
        passthrough("Barracuda", &args[2..]);
    }

    // The vendor account store, §1.6 decision (a).
    //   tuxweb --accounts <tuxedo-binary> [store-path]
    // Reports the slots and whether each is internally consistent. It does NOT
    // print passwords or digests: this is a tool for checking that the file we
    // maintain is still coherent, not a credential dumper, and the difference
    // is worth keeping even though anyone holding the firmware could write the
    // dumper in ten minutes.
    if args.len() >= 3 && args[1] == "--accounts" {
        let store_path = args.get(3).map(String::as_str).unwrap_or(accounts::STORE_PATH);
        let env = match accounts::key_from_binary(&args[2]) {
            Ok(e) => e,
            Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
        };
        let blob = match std::fs::read(store_path) {
            Ok(b) => b,
            Err(e) => { eprintln!("tuxweb: {store_path}: {e}"); std::process::exit(1); }
        };
        let store = match accounts::Store::decode(&env, &blob) {
            Ok(s) => s,
            Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
        };
        println!("{store_path}: {} bytes, {} slots", blob.len(), store.users.len());
        for u in &store.users {
            println!(
                "  slot {} {:<16} status={} locked={} sealed={}",
                u.user_id,
                u.user_name,
                u.status,
                u.account_locked,
                if u.is_sealed() { "yes" } else { "NO" },
            );
        }
        match store.validate() {
            Ok(()) => println!("store is consistent"),
            Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
        }
        return;
    }

    // Decode and re-encode the store with our own writer, to a NEW path.
    //   tuxweb --accounts-rewrite <tuxedo-binary> <in> <out>
    // Never writes over its input and never touches the live store: proving
    // the writer produces something the vendor can read is a separate act from
    // replacing an alarm panel's account file, and conflating them is how a
    // verification step locks everyone out of the web UI.
    if args.len() == 5 && args[1] == "--accounts-rewrite" {
        let env = match accounts::key_from_binary(&args[2]) {
            Ok(e) => e,
            Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
        };
        let blob = match std::fs::read(&args[3]) {
            Ok(b) => b,
            Err(e) => { eprintln!("tuxweb: {}: {e}", args[3]); std::process::exit(1); }
        };
        let store = match accounts::Store::decode(&env, &blob) {
            Ok(s) => s,
            Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
        };
        if let Err(e) = store.validate() {
            eprintln!("tuxweb: refusing to rewrite an inconsistent store: {e}");
            std::process::exit(1);
        }
        if std::path::Path::new(&args[4]).exists() {
            eprintln!("tuxweb: {} exists; refusing to overwrite", args[4]);
            std::process::exit(1);
        }
        match store.encode(&env).and_then(|out| {
            std::fs::write(&args[4], &out).map_err(|e| format!("{}: {e}", args[4]))?;
            Ok(out.len())
        }) {
            Ok(n) => println!("wrote {} ({n} bytes, in was {} bytes)", args[4], blob.len()),
            Err(e) => { eprintln!("tuxweb: {e}"); std::process::exit(1); }
        }
        return;
    }

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
            allow_plaintext_login: plaintext_login_allowed(),
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
            allow_plaintext_login: plaintext_login_allowed(),
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
