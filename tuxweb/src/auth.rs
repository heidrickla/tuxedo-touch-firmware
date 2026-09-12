//! Stage 8b: tuxweb's own auth -- an admin-issued bearer token, hashed on disk.
//!
//! Decision 1 (2026-09-11): the replacement serves a NEW, simpler API and auth
//! rather than reimplementing the vendor's encrypted one (§1.5 dropped the
//! SharkSSL-era crypto; §2.5 makes the API new and lets the integration migrate).
//! So there is deliberately **no** `/tuxedoapi.html` AES key handout, no
//! challenge/HMAC login, no per-session key. A token is issued out of band by an
//! admin command, the integration is configured with it, and it is presented on
//! the push stream and every API call. tuxweb stores only the token's SHA-256, so
//! the store on disk cannot be replayed to authenticate, and tokens are
//! individually revocable (§2.5).
//!
//! The store lives on mtd17 (`/opt/tuxedo/configuration`), which survives a
//! reflash (unlike `/tmp`). Only the hash is written -- never the token.

use ring::digest;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

/// The token store path. mtd17, so it survives a reflash; a token must NOT go in
/// the arm marker, which is also there but is world-observable state.
pub const TOKEN_STORE: &str = "/opt/tuxedo/configuration/tuxweb-tokens.json";

#[derive(Serialize, Deserialize, Default)]
pub struct TokenStore {
    pub tokens: Vec<TokenEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenEntry {
    /// A human label so a token can be named and revoked (e.g. "home-assistant").
    pub label: String,
    /// Lowercase hex SHA-256 of the token. The token itself is shown once at
    /// issue and never stored.
    pub sha256: String,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// SHA-256 of a token, lowercase hex. Presented tokens are hashed and compared
/// against the stored hashes; the token is never persisted.
pub fn hash_token(token: &str) -> String {
    to_hex(digest::digest(&digest::SHA256, token.as_bytes()).as_ref())
}

/// Extract a presented token from a request head: `Authorization: Bearer <t>` or
/// `Cookie: tuxweb_token=<t>`. The cookie form exists because the push consumer
/// already sends a `Cookie` header, so it costs no new code path there.
pub fn token_from_head(head: &str) -> Option<String> {
    for line in head.split("\r\n").skip(1) {
        let (k, v) = line.split_once(':')?;
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("authorization") {
            if let Some(t) = v.strip_prefix("Bearer ") {
                return Some(t.trim().to_string());
            }
        } else if k.eq_ignore_ascii_case("cookie") {
            for c in v.split(';') {
                if let Some((n, val)) = c.trim().split_once('=') {
                    if n == "tuxweb_token" {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

impl TokenStore {
    /// Load the store, or an empty one if the file is absent. A malformed file is
    /// an error rather than a silent empty store: an empty store authenticates
    /// nobody, which would look exactly like "auth is off" if we swallowed a
    /// parse failure.
    pub fn load(path: &str) -> Result<TokenStore, String> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{path}: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TokenStore::default()),
            Err(e) => Err(format!("{path}: {e}")),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("{path}: {e}"))
    }

    /// Is this token valid? Hashes the presented token and compares against every
    /// stored hash in constant time, checking all entries so the time taken does
    /// not reveal which entry matched or how many exist.
    pub fn is_valid(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let want = hash_token(token);
        let want = want.as_bytes();
        let mut ok = false;
        for e in &self.tokens {
            // ring's constant-time compare; fold so no early return leaks timing
            ok |= ring::constant_time::verify_slices_are_equal(e.sha256.as_bytes(), want).is_ok();
        }
        ok
    }

    /// Mint a new token, store its hash under `label`, and return the token ONCE.
    /// 32 bytes from the system CSPRNG, hex -- 256 bits, so it is not guessable
    /// and not worth rate-limiting the way a 4-digit panel code is.
    pub fn issue(&mut self, label: &str) -> Result<String, String> {
        let rng = ring::rand::SystemRandom::new();
        let mut raw = [0u8; 32];
        rng.fill(&mut raw).map_err(|_| "CSPRNG failed".to_string())?;
        let token = to_hex(&raw);
        // replace any existing entry with the same label rather than duplicating
        self.tokens.retain(|e| e.label != label);
        self.tokens.push(TokenEntry { label: label.to_string(), sha256: hash_token(&token) });
        Ok(token)
    }

    /// Remove a token by label. Returns whether one was removed.
    pub fn revoke(&mut self, label: &str) -> bool {
        let before = self.tokens.len();
        self.tokens.retain(|e| e.label != label);
        self.tokens.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_lowercase_hex_of_the_right_length() {
        let h = hash_token("hello");
        assert_eq!(h.len(), 64, "sha-256 is 32 bytes = 64 hex chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // known SHA-256("hello")
        assert_eq!(h, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn an_issued_token_validates_and_a_wrong_one_does_not() {
        let mut s = TokenStore::default();
        let t = s.issue("home-assistant").unwrap();
        assert!(s.is_valid(&t), "the freshly issued token must validate");
        assert!(!s.is_valid("not-the-token"), "a wrong token must not");
        assert!(!s.is_valid(""), "an empty token must not");
        // the token is 256 bits of hex, and only its hash is stored
        assert_eq!(t.len(), 64);
        assert!(s.tokens.iter().all(|e| e.sha256 != t), "the raw token is never stored");
    }

    #[test]
    fn revoking_a_token_stops_it_validating() {
        let mut s = TokenStore::default();
        let t = s.issue("ha").unwrap();
        assert!(s.is_valid(&t));
        assert!(s.revoke("ha"));
        assert!(!s.is_valid(&t), "a revoked token must not validate");
        assert!(!s.revoke("ha"), "revoking a missing label returns false");
    }

    #[test]
    fn issuing_the_same_label_replaces_rather_than_duplicates() {
        let mut s = TokenStore::default();
        let t1 = s.issue("ha").unwrap();
        let t2 = s.issue("ha").unwrap();
        assert_eq!(s.tokens.len(), 1, "one label, one entry");
        assert!(!s.is_valid(&t1), "the old token is invalidated by re-issue");
        assert!(s.is_valid(&t2));
    }

    #[test]
    fn the_store_round_trips_through_disk() {
        let mut s = TokenStore::default();
        let t = s.issue("ha").unwrap();
        let p = std::env::temp_dir().join(format!("tok-{}.json", std::process::id()));
        let path = p.to_str().unwrap();
        s.save(path).unwrap();
        let loaded = TokenStore::load(path).unwrap();
        assert!(loaded.is_valid(&t), "a loaded store validates the token");
        let _ = std::fs::remove_file(&p);
        // an absent file is an empty store, not an error
        assert!(TokenStore::load(path).unwrap().tokens.is_empty());
    }

    #[test]
    fn tokens_are_read_from_both_header_forms() {
        let head = |h: &str| format!("GET / HTTP/1.1\r\n{h}\r\n\r\n");
        assert_eq!(
            token_from_head(&head("Authorization: Bearer abc123")).as_deref(),
            Some("abc123")
        );
        assert_eq!(
            token_from_head(&head("Cookie: x=y; tuxweb_token=deadbeef")).as_deref(),
            Some("deadbeef")
        );
        assert_eq!(token_from_head(&head("Host: x")), None);
    }

    #[test]
    fn a_malformed_store_is_an_error_not_an_empty_one() {
        // an empty store authenticates nobody; silently returning it for a corrupt
        // file would read as "auth is off", the wrong direction to fail.
        let p = std::env::temp_dir().join(format!("bad-{}.json", std::process::id()));
        std::fs::write(&p, b"{ not json").unwrap();
        let r = TokenStore::load(p.to_str().unwrap());
        let _ = std::fs::remove_file(&p);
        assert!(r.is_err(), "a corrupt store must be an error");
    }
}
