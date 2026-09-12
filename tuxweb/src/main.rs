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
mod api;
mod auth;
mod cutover;
mod deadman;
mod frame;
mod ipc;
mod login;
mod mq;
mod proxy;
mod push;
mod redirect;
mod register;
mod serve;
mod session;
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

/// Write a panic's message and location to a file before the process aborts.
///
/// `supervis` launches us with `system("/opt/webserver/Barracuda &")`, so stdout and
/// stderr go nowhere reachable. With `panic = "abort"` a panic is therefore a bare
/// `SIGABRT` line in `SupervisionLog.txt` and nothing else: the 2026-09-11 stage-6
/// window died exactly that way and left no file, line or message behind, which is
/// why its cause is still open. The hook is installed before ANY other work in
/// `main`, so it covers argument parsing, the marker, the queue open and the receive
/// loop alike.
///
/// Best-effort by construction: a panic handler that can itself panic, or that
/// blocks, is worse than none. Nothing here unwraps, and the file is truncated on
/// open so one window's evidence can never be read as another's.
fn install_panic_log(path: &str) {
    let path = path.to_string();
    std::panic::set_hook(Box::new(move |info| {
        use std::io::Write;
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<no location>".into());
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".into()
        };
        let line = format!("tuxweb PANIC at {loc}: {msg}\n");
        eprint!("{line}");
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }));
}

/// Parse a stage-7 request out of the arm marker.
///
///     7a            register, watch, unregister
///     7b            plus the four read-only queries
///     7c            console mode, then BACK after the watch
///     7d <code>     ONE arming command: 1, 2, 3 or 4
///
/// An optional trailing `s<secs>` sets the watch. Anything unrecognised returns
/// None and the caller hands the panel back without sending -- a marker typo must
/// not become a different, more consequential stage than the one intended.
fn stage7_from_marker(request: &str) -> Option<register::Config> {
    let mut parts = request.split_whitespace();
    let stage = parts.next()?;
    let rest: Vec<&str> = parts.collect();

    let secs = rest
        .iter()
        .find_map(|t| t.strip_prefix('s').and_then(|n| n.parse::<u64>().ok()))
        .unwrap_or(120);

    let (queries, after_watch) = match stage {
        "7a" => (Vec::new(), Vec::new()),
        "7b" => (
            vec![
                ipc::cmd::PARTITION_STATUS,
                ipc::cmd::ALL_ZONE_STATUS,
                ipc::cmd::HOME_PART_DETAILS,
                ipc::cmd::EVENT_LOG_UPLOAD,
            ],
            Vec::new(),
        ),
        "7c" => (vec![ipc::cmd::CONSOLE_MODE], vec![ipc::cmd::BACK]),
        "7d" => {
            // The arming code is required and must be one of the four. A marker
            // reading "7d" alone, or "7d 19", must not arm anything.
            let code: u32 = rest.iter().find_map(|t| t.parse::<u32>().ok())?;
            let known = [
                ipc::cmd::ARM_AWAY,
                ipc::cmd::ARM_STAY,
                ipc::cmd::DISARM,
                ipc::cmd::ARM_NIGHT,
            ];
            if !known.contains(&code) {
                return None;
            }
            (vec![code], Vec::new())
        }
        _ => return None,
    };

    // The session must be non-zero, and it is not worth putting in the marker: any
    // non-zero value does, and one fewer field is one fewer thing to mistype at the
    // moment the panel is about to be taken over.
    Some(register::Config {
        session: 4242,
        watch: std::time::Duration::from_secs(secs),
        log: format!("/tmp/stage{stage}.tsv"),
        label: format!("stage{stage}"),
        queries,
        after_watch,
        user_code: register::user_code().unwrap_or(0),
    })
}

fn main() {
    // The first statement in the program: a panic before this point is invisible.
    install_panic_log("/tmp/tuxweb-panic.txt");

    let args: Vec<String> = std::env::args().collect();

    // Prove the panic log works, on the machine that will have to rely on it.
    // A diagnostic nobody has seen fire is not a diagnostic -- the stage-6 window
    // was lost precisely because the failure left no message, and shipping an
    // unverified replacement for that would repeat the mistake with more steps.
    // Deliberately not behind a cfg: the check is worth having on the panel.
    if args.get(1).map(String::as_str) == Some("--panic-test") {
        panic!("deliberate panic to verify /tmp/tuxweb-panic.txt is written");
    }

    // Stage 7a: the first stage that writes to the alarm bus.
    //   tuxweb --stage7a <session> [watch-secs]
    // Not reachable from the supervis launch path -- that branch is keyed on argv[0]
    // being "Barracuda" and is handled below -- so this can only be run deliberately.
    let stage = args.get(1).map(String::as_str);
    if matches!(stage, Some("--stage7a" | "--stage7b" | "--stage7c" | "--stage7d")) {
        let session: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
        // Every stage goes through one register/watch/unregister path, so there is
        // no route that sends something and then skips the 501.
        let (name, queries, after_watch) = match stage {
            // 7a: nothing but the register pair.
            Some("--stage7a") => ("stage7a", Vec::new(), Vec::new()),
            // 7b: the four read-only queries.
            Some("--stage7b") => (
                "stage7b",
                vec![
                    ipc::cmd::PARTITION_STATUS,
                    ipc::cmd::ALL_ZONE_STATUS,
                    ipc::cmd::HOME_PART_DETAILS,
                    ipc::cmd::EVENT_LOG_UPLOAD,
                ],
                Vec::new(),
            ),
            // 7c: console mode during the watch, then BACK -- which ends the
            // broadcast, so it goes after. HOME is NOT sent: 503 returns the panel
            // to the home screen, which is a visible change to make deliberately
            // and one at a time, not as a side effect of a console test.
            Some("--stage7c") => (
                "stage7c",
                vec![ipc::cmd::CONSOLE_MODE],
                vec![ipc::cmd::BACK],
            ),
            // 7d: ONE arming command per invocation, named on the command line.
            // The stage plan is explicit -- "one command per attempt, verified on
            // the touchscreen and in the push stream before the next" -- so there
            // is deliberately no way to ask for the whole sequence at once.
            Some("--stage7d") => {
                let code: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
                let known = [
                    ipc::cmd::ARM_AWAY,
                    ipc::cmd::ARM_STAY,
                    ipc::cmd::DISARM,
                    ipc::cmd::ARM_NIGHT,
                ];
                if !known.contains(&code) {
                    eprintln!(
                        "stage7d: needs ONE arming command as the 4th argument: \
                         {} ARM_AWAY, {} ARM_STAY, {} DISARM, {} ARM_NIGHT",
                        ipc::cmd::ARM_AWAY, ipc::cmd::ARM_STAY,
                        ipc::cmd::DISARM, ipc::cmd::ARM_NIGHT
                    );
                    eprintln!("stage7d: usage: tuxweb --stage7d <session> <secs> <code>");
                    std::process::exit(2);
                }
                ("stage7d", vec![code], Vec::new())
            }
            _ => unreachable!(),
        };
        let cfg = register::Config {
            session,
            watch: std::time::Duration::from_secs(secs),
            log: format!("/tmp/{name}.tsv"),
            label: name.to_string(),
            after_watch,
            user_code: register::user_code().unwrap_or(0),
            queries,
        };
        match register::run(&cfg) {
            Ok(o) => {
                println!(
                    "{name}: register={} queries={} after={} received={} decoded={} saw504={} unregister={}",
                    o.sent_register, o.queries_sent, o.after_sent, o.received, o.decoded,
                    o.saw_504, o.sent_unregister
                );
                let types: Vec<String> =
                    o.types.iter().map(|(t, n)| format!("{t}x{n}")).collect();
                println!("{name}: msgTypes {}", types.join(" "));
                // The unregister is what leaves the panel as it was found, so a run
                // that could not send it is a failure even if it received plenty.
                std::process::exit(if o.sent_unregister { 0 } else { 1 });
            }
            Err(e) => {
                eprintln!("{name}: {e}");
                std::process::exit(2);
            }
        }
    }

    // Invoked under the vendor's own name, or told to explicitly: hand over.
    // Checked before anything else so no other argument parsing can shadow it.
    let called_as = std::path::Path::new(&args[0])
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if called_as == "Barracuda" {
        // Launched by supervis under the vendor's name. Almost always this is
        // a passthrough; exactly once, when a window has been armed, it is the
        // cutover. Taking the marker CONSUMES it, so a crash during the window
        // is relaunched as a passthrough rather than as another window.
        if let Some(request) = cutover::take_arm_marker(cutover::ARM_MARKER) {
            // A non-empty marker names a stage-7 run. Empty stays the read-only
            // stage-6 cutover, so an operator who arms the marker the old way gets
            // the old, least consequential behaviour.
            if !request.is_empty() {
                match stage7_from_marker(&request) {
                    Some(cfg) => {
                        let o = register::run(&cfg);
                        // Hand the panel back either way: the window owns the web
                        // server, and leaving it owned is worse than any result.
                        match o {
                            Ok(o) => println!(
                                "{}: register={} queries={} after={} received={} \
                                 decoded={} saw504={} unregister={}",
                                cfg.label, o.sent_register, o.queries_sent, o.after_sent,
                                o.received, o.decoded, o.saw_504, o.sent_unregister
                            ),
                            Err(e) => eprintln!("{}: {e}", cfg.label),
                        }
                    }
                    None => eprintln!(
                        "tuxweb cutover: marker said {request:?}, which is not a stage \
                         I know; handing back without sending anything"
                    ),
                }
                // Whatever happened, give the panel back rather than sitting on it.
                deadman::hand_back_to_vendor(
                    &std::env::var("TUXWEB_EXEC")
                        .unwrap_or_else(|_| "/opt/webserver/vendor/Barracuda".to_string()),
                );
            }
            let vendor = std::env::var("TUXWEB_EXEC")
                .unwrap_or_else(|_| "/opt/webserver/vendor/Barracuda".to_string());
            let window = std::env::var("TUXWEB_CUTOVER_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .map(std::time::Duration::from_secs)
                .unwrap_or(deadman::DEFAULT_WINDOW);
            cutover::run(cutover::Config {
                vendor,
                log: "/tmp/cutover.tsv".into(),
                window,
            });
        }
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
        // The vendor keeps a byte-identical mirror. Nothing on the read paths
        // opens it, so a divergence is silent -- which is exactly why it is
        // worth reporting: it means something wrote one file and not the other.
        if store_path == accounts::STORE_PATH {
            match std::fs::read(accounts::MIRROR_PATH) {
                Ok(m) if m == blob => println!("mirror matches"),
                Ok(m) => println!(
                    "mirror DIFFERS ({} bytes vs {}) -- something wrote one file and not the other",
                    m.len(),
                    blob.len()
                ),
                Err(e) => println!("mirror unreadable: {e}"),
            }
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

    // Stage 8b: token admin. Tokens gate the push stream and the write API
    // (§4.10.1); stored hashed on mtd17, individually revocable (§2.5).
    //   tuxweb --issue-token <label> [store]
    //   tuxweb --revoke-token <label> [store]
    //   tuxweb --list-tokens [store]
    let tok_cmd = args.get(1).map(String::as_str);
    if matches!(tok_cmd, Some("--issue-token" | "--revoke-token" | "--list-tokens")) {
        let cmd = tok_cmd.unwrap();
        let is_list = cmd == "--list-tokens";
        let store_idx = if is_list { 2 } else { 3 };
        let store_path = args
            .get(store_idx)
            .cloned()
            .unwrap_or_else(|| auth::TOKEN_STORE.to_string());
        let mut store = match auth::TokenStore::load(&store_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tuxweb: {e}");
                std::process::exit(1);
            }
        };
        match cmd {
            "--list-tokens" => {
                if store.tokens.is_empty() {
                    println!("no tokens in {store_path}");
                }
                for e in &store.tokens {
                    println!("  {:<20} {}…", e.label, &e.sha256[..e.sha256.len().min(16)]);
                }
            }
            "--issue-token" | "--revoke-token" => {
                let label = match args.get(2) {
                    Some(l) => l.clone(),
                    None => {
                        eprintln!("usage: {} {cmd} <label> [store]", args[0]);
                        std::process::exit(2);
                    }
                };
                if cmd == "--issue-token" {
                    match store.issue(&label) {
                        Ok(token) => {
                            if let Err(e) = store.save(&store_path) {
                                eprintln!("tuxweb: {e}");
                                std::process::exit(1);
                            }
                            println!("issued token for {label:?}, stored hashed in {store_path}:");
                            println!("{token}");
                            println!(
                                "Shown ONCE -- configure the consumer with it now; it cannot be recovered."
                            );
                        }
                        Err(e) => {
                            eprintln!("tuxweb: {e}");
                            std::process::exit(1);
                        }
                    }
                } else if store.revoke(&label) {
                    if let Err(e) = store.save(&store_path) {
                        eprintln!("tuxweb: {e}");
                        std::process::exit(1);
                    }
                    println!("revoked {label:?}");
                } else {
                    println!("no token labelled {label:?} in {store_path}");
                }
            }
            _ => unreachable!(),
        }
        return;
    }

    // Stage 6, the IPC cutover. Read-only, bounded, hands the panel back.
    //   tuxweb --cutover <vendor-binary> [seconds] [logfile]
    if args.len() >= 3 && args[1] == "--cutover" {
        let window = args
            .get(3)
            .and_then(|s| s.parse::<u64>().ok())
            .map(std::time::Duration::from_secs)
            .unwrap_or(deadman::DEFAULT_WINDOW);
        cutover::run(cutover::Config {
            vendor: args[2].clone(),
            log: args.get(4).cloned().unwrap_or_else(|| "/tmp/cutover.tsv".into()),
            window,
        });
    }

    // Stage 8a: register, receive, and GENERATE the push stream from IPC replies
    // (no Barracuda). Writes the multipart stream to a file so a bench run can be
    // compared to the expected frames. The serving form is stage 8c.
    //   tuxweb --push-capture <session> <secs> <outfile> [quickarm-path]
    if args.len() >= 5 && args[1] == "--push-capture" {
        let session: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);
        let cfg = session::Config {
            session,
            window: std::time::Duration::from_secs(secs),
            out: args[4].clone(),
            quickarm: args.get(5).cloned().unwrap_or_else(|| session::QUICKARM_STATE.to_string()),
        };
        match session::run_capture(&cfg) {
            Ok(o) => {
                println!(
                    "push-capture: register={} received={} decoded={} emitted_parts={} \
                     undecoded={} saw504={} unregister={}",
                    o.sent_register, o.received, o.decoded, o.emitted_parts,
                    o.undecoded, o.saw_504, o.sent_unregister
                );
                std::process::exit(if o.sent_unregister { 0 } else { 1 });
            }
            Err(e) => {
                eprintln!("push-capture: {e}");
                std::process::exit(2);
            }
        }
    }

    // Stage 8c: the production serve mode -- serve the push stream from IPC.
    // Plaintext this cut (TLS/80/API/auth layer on); the window is for the bench,
    // 0 or absent runs until killed (the permanent server).
    //   tuxweb --serve <session> <bind> [window-secs] [quickarm-path]
    if args.len() >= 4 && args[1] == "--serve" {
        let session: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        let window = args
            .get(4)
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .map(std::time::Duration::from_secs);
        let cfg = serve::Config {
            session,
            bind: args[3].clone(),
            quickarm: args.get(5).cloned().unwrap_or_else(|| session::QUICKARM_STATE.to_string()),
            window,
            // On the panel this is 0.0.0.0:80; a bench uses a high port. Env so
            // the positional args stay stable. 6280/9443 are never bound (§1.5).
            redirect_bind: std::env::var("TUXWEB_REDIRECT_BIND").ok().filter(|s| !s.is_empty()),
            token_store: std::env::var("TUXWEB_TOKEN_STORE")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| auth::TOKEN_STORE.to_string()),
            // TUXWEB_CHAIN + TUXWEB_KEY -> TLS; exits if set but unusable.
            tls: tls_from_env(),
        };
        match serve::run(cfg) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("serve: {e}");
                std::process::exit(2);
            }
        }
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
        // Every mode, including the ones reached by argv[0] or a marker file.
        // The list used to stop after --shim-login, so a reader could not tell
        // from the binary that --cutover existed at all -- and that is the one
        // someone looks up during a booked window.
        eprintln!("usage: {0} <bind-addr> <chain.pem> <server.key>", args[0]);
        eprintln!("       {0} --shim <host:port> <cookie> <bind-addr>", args[0]);
        eprintln!("       {0} --shim-login <host:port> <user> <pwfile> <bind-addr>", args[0]);
        eprintln!("       {0} --accounts <tuxedo-binary> [store-path]", args[0]);
        eprintln!("       {0} --accounts-rewrite <tuxedo-binary> <in> <out>", args[0]);
        eprintln!("       {0} --cutover <vendor-path> [window-secs] [log]", args[0]);
        eprintln!("       {0} --push-capture <session> <secs> <out> [quickarm]", args[0]);
        eprintln!("       {0} --serve <session> <bind> [window-secs] [quickarm]", args[0]);
        eprintln!("       {0} --issue-token <label> [store]", args[0]);
        eprintln!("       {0} --revoke-token <label> [store] | --list-tokens [store]", args[0]);
        eprintln!("       {0} --passthrough <args...>", args[0]);
        eprintln!();
        eprintln!("Installed as .../Barracuda it execs the vendor (passthrough),");
        eprintln!("except for ONE relaunch after {} exists,", cutover::ARM_MARKER);
        eprintln!("which it consumes and runs the cutover instead.");
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
