//! `InstallCertificate`: replace the serving certificate and key over the
//! authenticated API and serve them from the next connection on, with no
//! process restart.
//!
//! A restart would spend `supervis`'s relaunch budget (24 per boot, then a
//! hardware reset; `TRAPS.md` §6), so the install swaps the live
//! `ServerConfig` in memory instead. Every accepted connection reads the
//! current config once ([`LiveTls::current`]) and keeps that `Arc` for its
//! lifetime, so a push subscriber connected before the install keeps its
//! session and only new connections see the new pair.
//!
//! The pair is validated in full before anything touches the disk, written
//! key first (mode 0600) with the previous pair kept as `<path>.prev`, and the
//! in-memory config changes only after both files are in place. A failed write
//! puts back whatever it had already replaced and leaves the config unchanged.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// The capability string, declared only when this server serves TLS from a
/// configured chain/key pair.
pub const CAPABILITY: &str = "certificate_install";

/// Largest request body accepted, judged by `Content-Length` before reading.
pub const MAX_BODY: usize = 16 * 1024;

/// Most certificates a chain may hold: the leaf and up to three issuers.
pub const MAX_CHAIN: usize = 4;

/// Why a body was refused with `400`; the string is the `error` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    BadJson,
    BadChain,
    BadKey,
    KeyMismatch,
    NotYetValid,
    Expired,
    NoSan,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::BadJson => "bad_json",
            Reason::BadChain => "bad_chain",
            Reason::BadKey => "bad_key",
            Reason::KeyMismatch => "key_mismatch",
            Reason::NotYetValid => "not_yet_valid",
            Reason::Expired => "expired",
            Reason::NoSan => "no_san",
        }
    }
}

/// The ServerConfig every TLS listener in serve mode uses. One function, so a
/// config built at launch and one built by an install are the same shape.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
}

/// A pair that passed every check, ready to write and serve.
pub struct Validated {
    config: Arc<ServerConfig>,
    chain_pem: Vec<u8>,
    key_pem: Vec<u8>,
    /// SHA-256 of the leaf's DER, lowercase hex.
    pub sha256: String,
    /// The leaf's `notAfter`, RFC 3339 UTC.
    pub not_after: String,
}

#[derive(serde::Deserialize)]
struct Body {
    chain: String,
    key: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of `der`, lowercase hex with no separators.
pub fn sha256_hex(der: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, der).as_ref())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// PEM armour around `der`, 64 columns, the form `load_chain`/`load_key` read.
pub fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let mut b64 = Vec::with_capacity(der.len().div_ceil(3) * 4);
    for c in der.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        b64.push(B64[(n >> 18) as usize & 63]);
        b64.push(B64[(n >> 12) as usize & 63]);
        b64.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63]
        } else {
            b'='
        });
        b64.push(if c.len() > 2 {
            B64[n as usize & 63]
        } else {
            b'='
        });
    }
    let mut out = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in b64.chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    out
}

/// Check a request body and build the config it would serve. `now` is Unix
/// seconds. Nothing is written and nothing changes in memory.
///
/// The files are re-encoded from the parsed DER rather than copied from the
/// request, so what lands on disk is exactly what was checked and nothing else
/// that happened to share the PEM text.
pub fn validate(body: &[u8], now: i64) -> Result<Validated, Reason> {
    let req: Body = serde_json::from_slice(body).map_err(|_| Reason::BadJson)?;

    let chain = CertificateDer::pem_slice_iter(req.chain.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Reason::BadChain)?;
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err(Reason::BadChain);
    }
    if chain
        .iter()
        .any(|c| crate::x509::parse(c.as_ref()).is_none())
    {
        return Err(Reason::BadChain);
    }
    let leaf_der = chain[0].as_ref();
    let leaf = crate::x509::parse(leaf_der).ok_or(Reason::BadChain)?;

    let key = PrivateKeyDer::from_pem_slice(req.key.as_bytes()).map_err(|_| Reason::BadKey)?;
    let signer =
        rustls::crypto::ring::sign::any_supported_type(&key).map_err(|_| Reason::BadKey)?;
    // The explicit match: the public half of the private key must be the
    // leaf's SubjectPublicKeyInfo, byte for byte.
    let key_spki = signer.public_key().ok_or(Reason::BadKey)?;
    if key_spki.as_ref() != leaf.spki {
        return Err(Reason::KeyMismatch);
    }

    if now < leaf.not_before {
        return Err(Reason::NotYetValid);
    }
    if now > leaf.not_after {
        return Err(Reason::Expired);
    }
    if leaf.san_entries == 0 {
        return Err(Reason::NoSan);
    }

    let sha256 = sha256_hex(leaf_der);
    let not_after = leaf.not_after_rfc3339.clone();
    let mut chain_pem = Vec::new();
    for c in &chain {
        chain_pem.extend_from_slice(&pem("CERTIFICATE", c.as_ref()));
    }
    let key_label = match &key {
        PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
        PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
        _ => "PRIVATE KEY",
    };
    let key_pem = pem(key_label, key.secret_der());
    let config = server_config(chain, key).map_err(|e| match e {
        rustls::Error::InconsistentKeys(_) => Reason::KeyMismatch,
        _ => Reason::BadKey,
    })?;
    Ok(Validated {
        config: Arc::new(config),
        chain_pem,
        key_pem,
        sha256,
        not_after,
    })
}

fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    s.into()
}

/// Replace `path` with `data` so a power cut leaves the old file or the new
/// one, never a mix: write `<path>.new`, fsync, rename over, fsync the
/// directory where the filesystem allows it. The rename is the commit point;
/// an `Err` means `path` was not replaced.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = with_suffix(path, ".new");
    let _ = std::fs::remove_file(&tmp);
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        // `mode` applies only to a file the open created; make it certain.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The current contents of `path`, `None` if it does not exist.
fn read_existing(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

const KEY_MODE: u32 = 0o600;
const CHAIN_MODE: u32 = 0o644;

/// Put back a file the install had already replaced. Returns what went wrong
/// if the restore itself failed.
fn restore(path: &Path, old: Option<&[u8]>, mode: u32) -> Option<String> {
    let r = match old {
        Some(b) => write_atomic(path, b, mode),
        None => std::fs::remove_file(path),
    };
    r.err()
        .map(|e| format!("{}: restore failed: {e}", path.display()))
}

/// Write the pair: the current pair to `.prev` first, then the key, then the
/// chain. On failure, whatever was replaced is put back and the error names
/// the step; the paths in it carry no key material.
fn write_pair(chain_path: &Path, key_path: &Path, v: &Validated) -> Result<(), String> {
    let at = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let old_key = read_existing(key_path).map_err(|e| at(key_path, e))?;
    let old_chain = read_existing(chain_path).map_err(|e| at(chain_path, e))?;

    // Rotation of one: the pair being replaced becomes `.prev`.
    if let Some(k) = &old_key {
        let p = with_suffix(key_path, ".prev");
        write_atomic(&p, k, KEY_MODE).map_err(|e| at(&p, e))?;
    }
    if let Some(c) = &old_chain {
        let p = with_suffix(chain_path, ".prev");
        write_atomic(&p, c, CHAIN_MODE).map_err(|e| at(&p, e))?;
    }

    write_atomic(key_path, &v.key_pem, KEY_MODE).map_err(|e| at(key_path, e))?;
    if let Err(e) = write_atomic(chain_path, &v.chain_pem, CHAIN_MODE) {
        let mut msg = at(chain_path, e);
        if let Some(r) = restore(key_path, old_key.as_deref(), KEY_MODE) {
            msg.push_str("; ");
            msg.push_str(&r);
        }
        return Err(msg);
    }
    Ok(())
}

/// What a successful install reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub sha256: String,
    pub not_after: String,
}

/// Why an install did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The body was refused; nothing was written.
    Invalid(Reason),
    /// A write failed; replaced files were put back and the config is unchanged.
    /// `sha256` names the leaf that was refused.
    WriteFailed { detail: String, sha256: String },
}

/// The serving TLS config, swappable while the server runs, and the files it
/// came from.
pub struct LiveTls {
    live: RwLock<Arc<ServerConfig>>,
    chain_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    /// One install at a time.
    one: Mutex<()>,
}

impl LiveTls {
    pub fn new(config: Arc<ServerConfig>, chain_path: &str, key_path: &str) -> LiveTls {
        LiveTls {
            live: RwLock::new(config),
            chain_path: chain_path.into(),
            key_path: key_path.into(),
            one: Mutex::new(()),
        }
    }

    /// The config a connection accepted now should use. Read once per accept;
    /// the connection keeps this `Arc` for its whole life.
    pub fn current(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.live.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// The served leaf's `notAfter`, RFC 3339 UTC, read from the chain file.
    /// An install writes the files before it swaps the config, so the file is
    /// the pair being served. `None` if the file cannot be read or parsed.
    pub fn not_after(&self) -> Option<String> {
        let pem = std::fs::read(&self.chain_path).ok()?;
        let leaf = CertificateDer::pem_slice_iter(&pem).next()?.ok()?;
        crate::x509::parse(leaf.as_ref()).map(|l| l.not_after_rfc3339)
    }

    /// Validate, write and swap. Never restarts, execs or exits.
    pub fn install(&self, body: &[u8], now: i64) -> Result<Installed, Failure> {
        let _one = self.one.lock().unwrap_or_else(|p| p.into_inner());
        let v = validate(body, now).map_err(Failure::Invalid)?;
        write_pair(&self.chain_path, &self.key_path, &v).map_err(|detail| {
            Failure::WriteFailed {
                detail,
                sha256: v.sha256.clone(),
            }
        })?;
        *self.live.write().unwrap_or_else(|p| p.into_inner()) = Arc::clone(&v.config);
        Ok(Installed {
            sha256: v.sha256,
            not_after: v.not_after,
        })
    }
}

fn error_body(status: &str, error: &str) -> Vec<u8> {
    crate::api::http(
        status,
        "application/json",
        format!("{{\"error\":\"{error}\"}}").as_bytes(),
    )
}

/// The sha256 of the first certificate in a body's chain, for the log line of
/// a refused install; `None` when the body does not get that far.
fn leaf_sha256(body: &[u8]) -> Option<String> {
    let req: Body = serde_json::from_slice(body).ok()?;
    let leaf = CertificateDer::pem_slice_iter(req.chain.as_bytes())
        .next()?
        .ok()?;
    Some(sha256_hex(leaf.as_ref()))
}

/// Seconds since the Unix epoch by the system clock.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Answer an authenticated `POST …/InstallCertificate`. The caller has routed
/// it and checked the token. `read_body(n)` reads the `n`-byte body and is
/// called only once the size and type are acceptable. Returns the response and
/// a log line that names the outcome and the leaf's sha256, never key material.
pub fn respond(
    tls: Option<&LiveTls>,
    over_tls: bool,
    head: &str,
    read_body: impl FnOnce(usize) -> Vec<u8>,
    now: i64,
) -> (Vec<u8>, String) {
    let Some(tls) = tls else {
        return (
            error_body("409 Conflict", "tls_not_configured"),
            "certificate install refused: tls_not_configured".into(),
        );
    };
    if !over_tls {
        return (
            error_body("403 Forbidden", "tls_required"),
            "certificate install refused: tls_required".into(),
        );
    }
    // Absent is an empty body; present but not a number is refused below.
    let length = match crate::proxy::header(head, "content-length") {
        None => Some(0),
        Some(v) => v.trim().parse::<usize>().ok(),
    };
    if length.is_some_and(|n| n > MAX_BODY) {
        let length = length.unwrap_or(0);
        return (
            error_body("413 Payload Too Large", "too_large"),
            format!("certificate install refused: too_large ({length} bytes declared)"),
        );
    }
    let json = crate::proxy::header(head, "content-type")
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"));
    let Some(length) = length.filter(|_| json) else {
        return (
            error_body("400 Bad Request", Reason::BadJson.as_str()),
            "certificate install refused: bad_json".into(),
        );
    };
    let body = read_body(length);
    if body.len() != length {
        return (
            error_body("400 Bad Request", Reason::BadJson.as_str()),
            "certificate install refused: bad_json".into(),
        );
    }
    match tls.install(&body, now) {
        Ok(i) => {
            let out = format!(
                "{{\"installed\":true,\"not_after\":\"{}\",\"sha256\":\"{}\"}}",
                i.not_after, i.sha256
            );
            (
                crate::api::http("200 OK", "application/json", out.as_bytes()),
                format!(
                    "certificate installed: leaf sha256 {}, not after {}; new connections use it",
                    i.sha256, i.not_after
                ),
            )
        }
        Err(Failure::Invalid(r)) => (
            error_body("400 Bad Request", r.as_str()),
            match leaf_sha256(&body) {
                Some(h) => format!(
                    "certificate install refused: {}; leaf sha256 {h}",
                    r.as_str()
                ),
                None => format!("certificate install refused: {}", r.as_str()),
            },
        ),
        Err(Failure::WriteFailed { detail, sha256 }) => (
            error_body("500 Internal Server Error", "write_failed"),
            format!(
                "certificate install FAILED: write_failed ({detail}); leaf sha256 {sha256} \
                 not installed, the previous pair is still served"
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testcert::{cert, Key, Pair, Spec};
    use std::io::Read;
    use std::path::PathBuf;

    fn body_of(chain: &str, key: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "chain": chain, "key": key })).unwrap()
    }

    fn reason(body: &[u8]) -> Reason {
        match validate(body, now_unix()) {
            Err(r) => r,
            Ok(_) => panic!("validated"),
        }
    }

    fn pem_str(label: &str, der: &[u8]) -> String {
        String::from_utf8(pem(label, der)).unwrap()
    }

    /// A scratch directory holding a served pair `a`, and the LiveTls over it.
    struct Bench {
        dir: PathBuf,
        chain: PathBuf,
        key: PathBuf,
        a: Pair,
        live: LiveTls,
    }

    impl Bench {
        fn new(name: &str) -> Bench {
            let dir =
                std::env::temp_dir().join(format!("certinstall-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let (chain, key) = (dir.join("chain.pem"), dir.join("server.key"));
            let a = Pair::new("Bench CA A");
            std::fs::write(&chain, a.chain_pem()).unwrap();
            std::fs::write(&key, a.key.pem()).unwrap();
            let cfg = validate(&a.body(), now_unix()).unwrap().config;
            let live = LiveTls::new(cfg, chain.to_str().unwrap(), key.to_str().unwrap());
            Bench {
                dir,
                chain,
                key,
                a,
                live,
            }
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn head(len: usize, ctype: &str) -> String {
        format!(
            "POST /system_http_api/API_REV01/InstallCertificate HTTP/1.1\r\nHost: x\r\n\
             Content-Type: {ctype}\r\nContent-Length: {len}\r\n"
        )
    }

    fn status_and_body(r: &[u8]) -> (String, serde_json::Value) {
        let r = String::from_utf8(r.to_vec()).unwrap();
        let (h, b) = r.split_once("\r\n\r\n").unwrap();
        let status = h.split("\r\n").next().unwrap().to_string();
        (status, serde_json::from_str(b).unwrap())
    }

    #[test]
    fn a_valid_pair_validates_and_reports_its_leaf() {
        let p = Pair::new("CA");
        let v = validate(&p.body(), now_unix()).unwrap();
        assert_eq!(v.sha256, sha256_hex(&p.leaf_der));
        assert_eq!(v.sha256.len(), 64);
        assert!(v
            .sha256
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        let leaf = crate::x509::parse(&p.leaf_der).unwrap();
        assert_eq!(v.not_after, leaf.not_after_rfc3339);
        assert!(
            v.not_after.ends_with('Z') && v.not_after.len() == 20,
            "{}",
            v.not_after
        );
        // what would be written is exactly the parsed chain and key, re-encoded
        assert_eq!(v.chain_pem, p.chain_pem().into_bytes());
        assert_eq!(v.key_pem, p.key.pem().into_bytes());
    }

    #[test]
    fn bad_json() {
        assert_eq!(reason(b"not json"), Reason::BadJson);
        assert_eq!(reason(b"{\"chain\":\"x\"}"), Reason::BadJson, "no key");
        assert_eq!(reason(b"{\"key\":\"x\"}"), Reason::BadJson, "no chain");
        assert_eq!(reason(b"{\"chain\":1,\"key\":2}"), Reason::BadJson);
        assert_eq!(reason(b""), Reason::BadJson);
    }

    #[test]
    fn bad_chain() {
        let p = Pair::new("CA");
        let key = p.key.pem();
        assert_eq!(
            reason(&body_of("", &key)),
            Reason::BadChain,
            "no certificates"
        );
        assert_eq!(
            reason(&body_of(&key, &key)),
            Reason::BadChain,
            "a key is not a chain"
        );
        let five = (0..5)
            .map(|_| pem_str("CERTIFICATE", &p.leaf_der))
            .collect::<String>();
        assert_eq!(
            reason(&body_of(&five, &key)),
            Reason::BadChain,
            "more than four"
        );
        let junk = pem_str("CERTIFICATE", b"\x30\x03\x02\x01\x01");
        assert_eq!(
            reason(&body_of(&junk, &key)),
            Reason::BadChain,
            "not a certificate"
        );
        // a malformed issuer is refused too, not only a malformed leaf
        let tail = format!("{}{junk}", pem_str("CERTIFICATE", &p.leaf_der));
        assert_eq!(reason(&body_of(&tail, &key)), Reason::BadChain);
        // four is the limit, not over it
        let four = (0..4)
            .map(|_| pem_str("CERTIFICATE", &p.leaf_der))
            .collect::<String>();
        assert!(validate(&body_of(&four, &key), now_unix()).is_ok());
    }

    #[test]
    fn bad_key() {
        let p = Pair::new("CA");
        let chain = p.chain_pem();
        assert_eq!(reason(&body_of(&chain, "")), Reason::BadKey);
        assert_eq!(reason(&body_of(&chain, "garbage")), Reason::BadKey);
        let not_a_key = pem_str("PRIVATE KEY", b"\x30\x03\x02\x01\x00");
        assert_eq!(reason(&body_of(&chain, &not_a_key)), Reason::BadKey);
    }

    #[test]
    fn key_mismatch() {
        let a = Pair::new("CA A");
        let b = Pair::new("CA B");
        assert_eq!(
            reason(&body_of(&a.chain_pem(), &b.key.pem())),
            Reason::KeyMismatch
        );
        // the issuer's key does not match the leaf either
        let ca_key = Key::generate();
        let leaf = cert(&Spec::leaf("CA"), &a.key, &ca_key);
        let chain = pem_str("CERTIFICATE", &leaf);
        assert_eq!(reason(&body_of(&chain, &ca_key.pem())), Reason::KeyMismatch);
        assert!(validate(&body_of(&chain, &a.key.pem()), now_unix()).is_ok());
    }

    #[test]
    fn not_yet_valid_and_expired_are_judged_against_now() {
        let p = Pair::new("CA");
        let leaf = crate::x509::parse(&p.leaf_der).unwrap();
        let body = p.body();
        let at = |now| validate(&body, now).err();
        assert_eq!(at(leaf.not_before - 1), Some(Reason::NotYetValid));
        assert_eq!(at(leaf.not_before), None, "the window includes notBefore");
        assert_eq!(at(leaf.not_after), None, "and notAfter");
        assert_eq!(at(leaf.not_after + 1), Some(Reason::Expired));
        // and a certificate that really is expired, by the real clock
        let key = Key::generate();
        let now = now_unix();
        let old = Spec {
            not_before: now - 10 * 86_400,
            not_after: now - 86_400,
            ..Spec::leaf("self")
        };
        let chain = pem_str("CERTIFICATE", &cert(&old, &key, &key));
        assert_eq!(reason(&body_of(&chain, &key.pem())), Reason::Expired);
        let future = Spec {
            not_before: now + 86_400,
            ..Spec::leaf("self")
        };
        let chain = pem_str("CERTIFICATE", &cert(&future, &key, &key));
        assert_eq!(reason(&body_of(&chain, &key.pem())), Reason::NotYetValid);
    }

    #[test]
    fn no_san() {
        let key = Key::generate();
        let spec = Spec {
            san: None,
            ..Spec::leaf("self")
        };
        let chain = pem_str("CERTIFICATE", &cert(&spec, &key, &key));
        assert_eq!(reason(&body_of(&chain, &key.pem())), Reason::NoSan);
    }

    #[test]
    fn plaintext_is_403_and_unconfigured_is_409_and_neither_reads_the_body() {
        let b = Bench::new("gates");
        let body = b.a.body();
        let h = head(body.len(), "application/json");
        let never = |_: usize| -> Vec<u8> { panic!("body read") };
        let (r, log) = respond(None, true, &h, never, now_unix());
        let (st, v) = status_and_body(&r);
        assert_eq!(st, "HTTP/1.1 409 Conflict");
        assert_eq!(v["error"], "tls_not_configured");
        assert!(log.contains("tls_not_configured"));
        let (r, _) = respond(Some(&b.live), false, &h, never, now_unix());
        let (st, v) = status_and_body(&r);
        assert_eq!(st, "HTTP/1.1 403 Forbidden");
        assert_eq!(v["error"], "tls_required");
    }

    #[test]
    fn an_oversized_body_is_413_by_content_length_before_reading() {
        let b = Bench::new("413");
        let never = |_: usize| -> Vec<u8> { panic!("body read") };
        let (r, _) = respond(
            Some(&b.live),
            true,
            &head(MAX_BODY + 1, "application/json"),
            never,
            now_unix(),
        );
        let (st, v) = status_and_body(&r);
        assert_eq!(st, "HTTP/1.1 413 Payload Too Large");
        assert_eq!(v["error"], "too_large");
        // exactly the limit is read and judged on its content
        let (r, _) = respond(
            Some(&b.live),
            true,
            &head(MAX_BODY, "application/json"),
            |n| vec![b' '; n],
            now_unix(),
        );
        assert_eq!(status_and_body(&r).1["error"], "bad_json");
    }

    #[test]
    fn a_body_that_is_not_json_by_type_or_length_is_bad_json() {
        let b = Bench::new("ctype");
        let body = Pair::new("CA B").body();
        let never = |_: usize| -> Vec<u8> { panic!("body read") };
        let form = head(body.len(), "application/x-www-form-urlencoded");
        let (r, _) = respond(Some(&b.live), true, &form, never, now_unix());
        assert_eq!(status_and_body(&r).1["error"], "bad_json");
        let unparseable =
            "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: x\r\n";
        let (r, _) = respond(Some(&b.live), true, unparseable, never, now_unix());
        assert_eq!(status_and_body(&r).1["error"], "bad_json");
        // a body shorter than its Content-Length (the client hung up)
        let short = body[..body.len() - 1].to_vec();
        let (r, _) = respond(
            Some(&b.live),
            true,
            &head(body.len(), "application/json; charset=utf-8"),
            |_| short,
            now_unix(),
        );
        assert_eq!(status_and_body(&r).1["error"], "bad_json");
        assert_eq!(std::fs::read_to_string(&b.chain).unwrap(), b.a.chain_pem());
    }

    #[test]
    fn each_refusal_is_a_400_with_its_reason_and_changes_nothing() {
        let b = Bench::new("400");
        let before = b.live.current();
        let other = Pair::new("CA B");
        let key = Key::generate();
        let no_san = pem_str(
            "CERTIFICATE",
            &cert(
                &Spec {
                    san: None,
                    ..Spec::leaf("s")
                },
                &key,
                &key,
            ),
        );
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (b"{".to_vec(), "bad_json"),
            (body_of("", &other.key.pem()), "bad_chain"),
            (body_of(&other.chain_pem(), "x"), "bad_key"),
            (body_of(&other.chain_pem(), &b.a.key.pem()), "key_mismatch"),
            (body_of(&no_san, &key.pem()), "no_san"),
        ];
        for (body, want) in cases {
            let (r, log) = respond(
                Some(&b.live),
                true,
                &head(body.len(), "application/json"),
                |_| body.clone(),
                now_unix(),
            );
            let (st, v) = status_and_body(&r);
            assert_eq!(st, "HTTP/1.1 400 Bad Request", "{want}");
            assert_eq!(v["error"], want);
            assert!(log.contains(want), "{log}");
            assert!(!log.contains("PRIVATE"), "no key material in the log");
        }
        // the dated reasons, through the same path with the clock moved
        let body = other.body();
        let leaf = crate::x509::parse(&other.leaf_der).unwrap();
        for (now, want) in [
            (leaf.not_before - 60, "not_yet_valid"),
            (leaf.not_after + 60, "expired"),
        ] {
            let (r, log) = respond(
                Some(&b.live),
                true,
                &head(body.len(), "application/json"),
                |_| body.clone(),
                now,
            );
            assert_eq!(status_and_body(&r).1["error"], want);
            // a refusal names the leaf it refused
            assert!(log.contains(&sha256_hex(&other.leaf_der)), "{log}");
        }
        assert!(Arc::ptr_eq(&before, &b.live.current()), "config unchanged");
        assert_eq!(std::fs::read_to_string(&b.chain).unwrap(), b.a.chain_pem());
        assert_eq!(std::fs::read_to_string(&b.key).unwrap(), b.a.key.pem());
        assert!(
            !with_suffix(&b.key, ".prev").exists(),
            "no rotation on a refusal"
        );
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn an_install_writes_the_pair_rotates_prev_and_swaps_the_config() {
        let b = Bench::new("ok");
        let before = b.live.current();
        // the status page's footer reads the served leaf's expiry from the file
        let a_leaf = crate::x509::parse(&b.a.leaf_der).unwrap();
        assert_eq!(b.live.not_after(), Some(a_leaf.not_after_rfc3339.clone()));
        let new = Pair::new("CA B");
        let body = new.body();
        let (r, log) = respond(
            Some(&b.live),
            true,
            &head(body.len(), "application/json"),
            |n| body[..n].to_vec(),
            now_unix(),
        );
        let (st, v) = status_and_body(&r);
        assert_eq!(st, "HTTP/1.1 200 OK", "{v}");
        assert_eq!(v["installed"], true);
        assert_eq!(v["sha256"], sha256_hex(&new.leaf_der));
        let leaf = crate::x509::parse(&new.leaf_der).unwrap();
        assert_eq!(v["not_after"], leaf.not_after_rfc3339.as_str());
        assert_eq!(b.live.not_after(), Some(leaf.not_after_rfc3339.clone()));
        assert_eq!(v.as_object().unwrap().len(), 3, "{v}");
        assert!(
            log.contains(&sha256_hex(&new.leaf_der)) && !log.contains("PRIVATE"),
            "{log}"
        );

        // the new pair is on disk, the old one is .prev, the keys are 0600
        assert_eq!(std::fs::read_to_string(&b.chain).unwrap(), new.chain_pem());
        assert_eq!(std::fs::read_to_string(&b.key).unwrap(), new.key.pem());
        let (chain_prev, key_prev) = (with_suffix(&b.chain, ".prev"), with_suffix(&b.key, ".prev"));
        assert_eq!(
            std::fs::read_to_string(&chain_prev).unwrap(),
            b.a.chain_pem()
        );
        assert_eq!(std::fs::read_to_string(&key_prev).unwrap(), b.a.key.pem());
        assert_eq!(mode(&b.key), 0o600);
        assert_eq!(mode(&key_prev), 0o600);
        assert!(!with_suffix(&b.key, ".new").exists() && !with_suffix(&b.chain, ".new").exists());

        // the files load the way a relaunch would load them
        let chain = CertificateDer::pem_file_iter(&b.chain)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(chain[0].as_ref(), new.leaf_der.as_slice());
        let key = PrivateKeyDer::from_pem_file(&b.key).unwrap();
        assert!(server_config(chain, key).is_ok());

        assert!(!Arc::ptr_eq(&before, &b.live.current()), "config swapped");

        // a second install rotates once: .prev is now the pair it replaced
        let third = Pair::new("CA C");
        b.live.install(&third.body(), now_unix()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&chain_prev).unwrap(),
            new.chain_pem()
        );
        assert_eq!(std::fs::read_to_string(&key_prev).unwrap(), new.key.pem());
    }

    #[test]
    fn a_failed_write_restores_the_key_and_leaves_the_config_alone() {
        let b = Bench::new("rollback");
        let before = b.live.current();
        // `<chain>.new` as a directory: the chain write fails after the key
        // has already been replaced, the case that needs a restore
        let blocker = with_suffix(&b.chain, ".new");
        std::fs::create_dir(&blocker).unwrap();
        let new = Pair::new("CA B");
        let body = new.body();
        let (r, log) = respond(
            Some(&b.live),
            true,
            &head(body.len(), "application/json"),
            |_| body.clone(),
            now_unix(),
        );
        let (st, v) = status_and_body(&r);
        assert_eq!(st, "HTTP/1.1 500 Internal Server Error");
        assert_eq!(v["error"], "write_failed");
        assert!(
            log.contains("write_failed") && log.contains(&sha256_hex(&new.leaf_der)),
            "{log}"
        );
        assert_eq!(
            std::fs::read_to_string(&b.key).unwrap(),
            b.a.key.pem(),
            "key restored"
        );
        assert_eq!(std::fs::read_to_string(&b.chain).unwrap(), b.a.chain_pem());
        assert_eq!(mode(&b.key), 0o600);
        assert!(Arc::ptr_eq(&before, &b.live.current()), "config unchanged");

        // a failure before anything is replaced (the .prev write) also leaves
        // the pair alone
        std::fs::remove_dir(&blocker).unwrap();
        let blocker = with_suffix(&b.key, ".prev.new");
        std::fs::create_dir(&blocker).unwrap();
        assert!(matches!(
            b.live.install(&body, now_unix()),
            Err(Failure::WriteFailed { .. })
        ));
        assert_eq!(std::fs::read_to_string(&b.key).unwrap(), b.a.key.pem());
        assert_eq!(std::fs::read_to_string(&b.chain).unwrap(), b.a.chain_pem());
        assert!(Arc::ptr_eq(&before, &b.live.current()));
        std::fs::remove_dir(&blocker).unwrap();
        // and with the obstruction gone the same body installs
        assert!(b.live.install(&body, now_unix()).is_ok());
    }

    type Client = rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>;

    fn connect(addr: std::net::SocketAddr, ca_der: &[u8]) -> Client {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("panel.test").unwrap();
        let conn = rustls::ClientConnection::new(Arc::new(cfg), name).unwrap();
        let sock = std::net::TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        rustls::StreamOwned::new(conn, sock)
    }

    fn echo(c: &mut Client, msg: &[u8]) -> std::io::Result<Vec<u8>> {
        c.write_all(msg)?;
        c.flush()?;
        let mut got = vec![0u8; msg.len()];
        c.read_exact(&mut got)?;
        Ok(got)
    }

    #[test]
    fn a_new_connection_sees_the_new_pair_while_an_open_one_carries_on() {
        let b = Bench::new("swap");
        let live = Arc::new(b.live_clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Arc::clone(&live);
        // The same accept shape serve.rs uses: the config read once per
        // connection, then an echo standing in for a long-lived subscriber.
        std::thread::spawn(move || {
            crate::conn::serve(listener, 4, "certinstall test", move |raw, _| {
                let cfg = server.current();
                let Ok(mut sink) = crate::shim::Sink::accept(raw, Some(&cfg)) else {
                    return;
                };
                let mut buf = [0u8; 256];
                while let Ok(n) = sink.read(&mut buf) {
                    if n == 0 || sink.write_all(&buf[..n]).is_err() || sink.flush().is_err() {
                        return;
                    }
                }
            })
        });

        let mut open = connect(addr, &b.a.ca_der);
        assert_eq!(echo(&mut open, b"before").unwrap(), b"before");
        let leaf = |c: &Client| c.conn.peer_certificates().unwrap()[0].as_ref().to_vec();
        assert_eq!(leaf(&open), b.a.leaf_der);

        let new = Pair::new("CA B");
        let installed = live.install(&new.body(), now_unix()).unwrap();
        assert_eq!(installed.sha256, sha256_hex(&new.leaf_der));

        let mut fresh = connect(addr, &new.ca_der);
        assert_eq!(echo(&mut fresh, b"after").unwrap(), b"after");
        assert_eq!(
            leaf(&fresh),
            new.leaf_der,
            "a new connection gets the new leaf"
        );
        let mut stale = connect(addr, &b.a.ca_der);
        assert!(
            echo(&mut stale, b"x").is_err(),
            "the old CA no longer verifies"
        );

        // the connection opened before the install still works, on its old pair
        assert_eq!(echo(&mut open, b"still here").unwrap(), b"still here");
        assert_eq!(leaf(&open), b.a.leaf_der);
    }

    impl Bench {
        /// A second handle on the bench's files and current config.
        fn live_clone(&self) -> LiveTls {
            LiveTls::new(
                self.live.current(),
                self.chain.to_str().unwrap(),
                self.key.to_str().unwrap(),
            )
        }
    }
}
