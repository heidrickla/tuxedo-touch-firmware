//! The vendor's web-account store, read and written in its own format.
//!
//! §1.6 decision (a): `tuxweb` maintains this file rather than owning a
//! separate one. The reason is an asymmetry that is easy to miss — the vendor
//! *web* UI dies with Barracuda, but the *touchscreen* account editor is
//! `/tuxedo`, which we keep. Own a separate store and an owner editing accounts
//! on the keypad writes a list the web never reads, with nothing reporting the
//! divergence.
//!
//! Everything here was verified against the panel's real file, not inferred:
//!
//! * AES-128 **OFB**, no padding, so ciphertext length equals plaintext length.
//! * The key and IV are 16-byte constants in `/tuxedo`'s `.data`. They are
//!   **not embedded here** — `key_from_binary` reads them out of `/tuxedo` at
//!   runtime. That keeps key material out of this repository, and it follows
//!   the vendor if a future firmware changes them.
//! * `webuseraccountsenc.json` and `webuseraccountsenc_sec.json` had identical
//!   md5s on the panel: `_sec` is a mirror, not a checksum. Both get written.
//! * Always five slots, matching the five-iteration count loop in
//!   `get_systemdata_message`.
//! * `EncNamePass = md5_hex(lower(userName) + passWord)`, established at 5/5
//!   accounts with eight other constructions at 0/5.
//!
//! `/tuxedo` re-reads the file on demand (`CAccountsSetup::readFromAccSettingsFile`
//! when the screen opens, and `get_systemdata_message`), so a write here is
//! picked up without restarting anything.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

/// Where the constants live in `/tuxedo`. Virtual addresses, resolved through
/// the program headers rather than assumed to equal file offsets.
const KEY_VA: u64 = 0xD09654;
const IV_VA: u64 = 0xD09664;

pub const STORE_PATH: &str = "/opt/tuxedo/configuration/webuseraccountsenc.json";
pub const MIRROR_PATH: &str = "/opt/tuxedo/configuration/webuseraccountsenc_sec.json";
pub const SLOTS: usize = 5;

#[derive(Clone, Copy)]
pub struct Envelope {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

/// One account. Field names and order are the vendor's.
///
/// Order is reproduced for tidiness, not necessity: in the live file entry 0
/// orders its last five fields differently from entries 1-4, which proves
/// `/tuxedo` reads them by name.
///
/// **Verified against the live panel 2026-09-07, and do not "fix" it.** A
/// round trip through `--accounts-rewrite` is 1053 bytes in, 1053 out, decodes
/// back to the same five sealed slots, and the decrypted JSON compares equal
/// as a data structure — but the bytes differ from plaintext offset 125,
/// because entry 0 ends `userCreatedDate, userUpdatedDate, accLockedCount,
/// accLockedTime, accountLocked` and entries 1-4 end `accountLocked,
/// accLockedTime, userCreatedDate, userUpdatedDate, accLockedCount`. serde
/// emits one declaration order for every element, so no single order
/// reproduces all five. This order matches entries 1-4: **4 of 5, which is the
/// maximum.** Reordering to match entry 0 would make it 1 of 5.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "u8UserId")]
    pub user_id: i64,
    #[serde(rename = "userName")]
    pub user_name: String,
    /// The four-digit panel user code, in the clear inside the envelope.
    /// Barracuda `strcpy`s this out to authenticate with; it is not a hash and
    /// cannot become one without breaking the login wire format.
    #[serde(rename = "passWord")]
    pub password: String,
    #[serde(rename = "EncNamePass")]
    pub enc_name_pass: String,
    pub status: i64,
    #[serde(rename = "accountLocked")]
    pub account_locked: i64,
    #[serde(rename = "accLockedTime")]
    pub acc_locked_time: i64,
    #[serde(rename = "userCreatedDate")]
    pub user_created_date: i64,
    #[serde(rename = "userUpdatedDate")]
    pub user_updated_date: i64,
    #[serde(rename = "accLockedCount")]
    pub acc_locked_count: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Store {
    #[serde(rename = "WEBUSERS")]
    pub users: Vec<User>,
}

/// `md5_hex(lower(userName) + passWord)`.
///
/// The same `lower(name) + pass` construction the login HMAC uses, which is the
/// cross-check that this reading is right rather than a coincidence that fit.
pub fn enc_name_pass(user_name: &str, password: &str) -> String {
    let mut h = Md5::new();
    h.update(user_name.to_lowercase().as_bytes());
    h.update(password.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl User {
    /// Recompute the digest from the current name and password.
    pub fn reseal(&mut self) {
        self.enc_name_pass = enc_name_pass(&self.user_name, &self.password);
    }

    /// Does the stored digest match the stored name and password?
    ///
    /// A mismatch means someone edited the file by hand, or wrote it with a
    /// different rule. Worth refusing to build on rather than silently fixing.
    pub fn is_sealed(&self) -> bool {
        self.enc_name_pass.eq_ignore_ascii_case(&enc_name_pass(
            &self.user_name,
            &self.password,
        ))
    }
}

/// AES-128 OFB. Symmetric: the same call encrypts and decrypts.
///
/// Written out rather than pulled from a mode crate because OFB is four lines
/// and the dependency would be larger than the code. The keystream is the
/// repeated encryption of the previous block, starting from the IV.
fn ofb(env: &Envelope, data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(&env.key.into());
    let mut feedback = aes::Block::from(env.iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        cipher.encrypt_block(&mut feedback);
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ feedback[i]);
        }
    }
    out
}

impl Store {
    pub fn decode(env: &Envelope, ciphertext: &[u8]) -> Result<Store, String> {
        let plain = ofb(env, ciphertext);
        let text = String::from_utf8_lossy(&plain);
        // the writer NUL-terminates its buffer but writes only `len` bytes, so
        // a trailing NUL is not expected -- tolerate one anyway
        let text = text.trim_end_matches('\0').trim();
        serde_json::from_str(text).map_err(|e| format!("account store: {e}"))
    }

    pub fn encode(&self, env: &Envelope) -> Result<Vec<u8>, String> {
        let text = serde_json::to_string(self).map_err(|e| format!("account store: {e}"))?;
        Ok(ofb(env, text.as_bytes()))
    }

    /// Every account, sealed and slot-counted, or an explanation.
    ///
    /// The five-slot invariant is checked because `get_systemdata_message`
    /// walks exactly five entries; a shorter array would make it read past the
    /// end of what we wrote.
    pub fn validate(&self) -> Result<(), String> {
        if self.users.len() != SLOTS {
            return Err(format!(
                "account store must hold exactly {SLOTS} slots, found {}",
                self.users.len()
            ));
        }
        for (i, u) in self.users.iter().enumerate() {
            if !u.is_sealed() {
                return Err(format!(
                    "slot {i} ({}): EncNamePass does not match its name and password",
                    u.user_id
                ));
            }
        }
        Ok(())
    }
}

/// Write the store to the vendor's two paths.
///
/// Order and mechanism both matter and neither is arbitrary:
///
/// * **Rename, never write in place.** Both `/tuxedo`'s
///   `readWebUserAccSetupJSONFile` and Barracuda's
///   `readUserNamePasswordFromJSON` open the main file directly and parse
///   whatever is there. A partially written file at that path is a panel that
///   cannot authenticate anyone, so the new bytes land under a temporary name
///   and are moved into place in one step.
/// * **Mirror first, main file last.** The main file is the one both readers
///   open; `_sec` is a mirror neither of them touches on these paths. Writing
///   the mirror first means an interruption leaves the authoritative file
///   either wholly old or wholly new, and never leaves the mirror behind the
///   file it mirrors.
///
/// The store is validated before anything is written. Refusing to serialise an
/// inconsistent store is the point: this function is the last place that can
/// tell the difference between a deliberate change and a mistake.
pub fn save(env: &Envelope, store: &Store, main: &str, mirror: &str) -> Result<usize, String> {
    store.validate()?;
    let bytes = store.encode(env)?;
    for path in [mirror, main] {
        let tmp = format!("{path}.tuxweb-new");
        std::fs::write(&tmp, &bytes).map_err(|e| format!("{tmp}: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{path}: {e}")
        })?;
    }
    Ok(bytes.len())
}

/// Why an account was refused. Callers get this; a client gets none of it.
///
/// The distinction is kept because the operator needs to know *why* a login
/// failed and the network must not: "no such user" and "wrong code" told apart
/// is a user enumeration oracle, and on a four-digit secret that matters more
/// than usual.
#[derive(Debug, PartialEq)]
pub enum Denied {
    NoSuchUser,
    WrongPassword,
    Disabled,
    Locked,
    /// The stored digest does not match the stored name and password. Someone
    /// edited the file by hand or wrote it with a different rule; refuse rather
    /// than guess which field is the truth.
    Tampered,
}

/// Constant-time compare, so a wrong code cannot be found a digit at a time.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

impl Store {
    /// Check a username and code against the store.
    ///
    /// **This is not a substitute for rate limiting.** The secret is four
    /// decimal digits — ten thousand possibilities — so the only thing standing
    /// between an attacker and an account is how fast they may guess. The
    /// vendor's own answer is `accLockedCount` and `accountLocked`, which are
    /// honoured here; a caller exposing this to a network MUST also throttle.
    /// P1 removed the permanent on-disk lockout for good reasons, and this must
    /// not quietly reintroduce one.
    ///
    /// Every candidate is examined rather than returning at the first match, so
    /// the work done does not depend on where in the file the user sits.
    pub fn authenticate(&self, user_name: &str, password: &str) -> Result<&User, Denied> {
        let mut found: Option<&User> = None;
        for u in &self.users {
            // usernames are matched case-insensitively because the digest that
            // binds name to password is computed over the lowercased name, so
            // the vendor already treats them that way
            if u.user_name.to_lowercase() == user_name.to_lowercase() {
                found = Some(u);
            }
        }
        let u = found.ok_or(Denied::NoSuchUser)?;
        if !u.is_sealed() {
            return Err(Denied::Tampered);
        }
        if u.status != 1 {
            return Err(Denied::Disabled);
        }
        if u.account_locked != 0 {
            return Err(Denied::Locked);
        }
        if !ct_eq(&u.password, password) {
            return Err(Denied::WrongPassword);
        }
        Ok(u)
    }
}

/// Read the AES key and IV out of `/tuxedo`.
///
/// Deliberately not embedded in this binary: the constants are the vendor's,
/// this repository is public, and reading them at runtime means a firmware that
/// changed them would still work.
pub fn key_from_binary(path: &str) -> Result<Envelope, String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let key = read_va(&data, KEY_VA).ok_or("could not map the key address")?;
    let iv = read_va(&data, IV_VA).ok_or("could not map the iv address")?;
    Ok(Envelope { key, iv })
}

/// Map a virtual address to a file offset through the ELF program headers and
/// read 16 bytes. `.data` is not at `vaddr - 0x8000` or any other fixed skew,
/// so the headers are consulted rather than a remembered constant.
fn read_va(d: &[u8], va: u64) -> Option<[u8; 16]> {
    if d.len() < 0x34 || &d[..4] != b"\x7fELF" || d[4] != 1 {
        return None; // 32-bit ELF only; the panel has nothing else
    }
    let u16at = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]) as usize;
    let u32at = |o: usize| {
        u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) as u64
    };
    let phoff = u32at(0x1C) as usize;
    let phentsize = u16at(0x2A);
    let phnum = u16at(0x2C);
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if p + 32 > d.len() || u32at(p) != 1 {
            continue; // PT_LOAD only
        }
        let (offset, vaddr, filesz) = (u32at(p + 4), u32at(p + 8), u32at(p + 16));
        if va >= vaddr && va + 16 <= vaddr + filesz {
            let at = (offset + (va - vaddr)) as usize;
            return d.get(at..at + 16)?.try_into().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway envelope. The panel's real constants are not in this
    /// repository and these tests do not need them: the format is what is
    /// under test, not the vendor's key.
    fn test_env() -> Envelope {
        Envelope {
            key: *b"0123456789abcdef",
            iv: *b"fedcba9876543210",
        }
    }

    fn user(id: i64, name: &str, pass: &str) -> User {
        let mut u = User {
            user_id: id,
            user_name: name.into(),
            password: pass.into(),
            enc_name_pass: String::new(),
            status: 1,
            account_locked: 0,
            acc_locked_time: 0,
            user_created_date: 1_700_000_000,
            user_updated_date: 1_700_000_000,
            acc_locked_count: 0,
        };
        u.reseal();
        u
    }

    fn store() -> Store {
        Store {
            users: (1..=SLOTS as i64)
                .map(|i| user(i, &format!("User{i}"), "1234"))
                .collect(),
        }
    }

    #[test]
    fn enc_name_pass_is_md5_of_lowercased_name_plus_password() {
        // md5("alice1234"), computed with python rather than by running this
        // code and writing down what it said -- a vector produced by the thing
        // under test proves only that it is self-consistent.
        assert_eq!(
            enc_name_pass("alice", "1234"),
            "d739111b266f6ec2f72c0b5740a6f374"
        );
        // the case fold is the part that distinguishes this from the seven
        // other constructions that scored 0/5 against the real file
        assert_eq!(enc_name_pass("ALICE", "1234"), enc_name_pass("alice", "1234"));
        assert_ne!(enc_name_pass("alice", "1234"), enc_name_pass("alice", "4321"));
    }

    #[test]
    fn ofb_is_symmetric_and_length_preserving() {
        let env = test_env();
        // deliberately not a multiple of the block size: the panel's own file
        // is 1053 bytes, and OFB is a stream mode, so no padding may appear
        let plain = b"{\"WEBUSERS\":[]} and a tail that does not land on 16";
        let c = ofb(&env, plain);
        assert_eq!(c.len(), plain.len(), "OFB must not pad");
        assert_ne!(&c[..], &plain[..], "it must actually encrypt");
        assert_eq!(ofb(&env, &c), plain, "and decrypt with the same call");
    }

    #[test]
    fn a_store_survives_a_round_trip() {
        let env = test_env();
        let s = store();
        let blob = s.encode(&env).unwrap();
        // byte-identical re-encoding is NOT the goal and would be wrong to
        // assert: the vendor's own file orders entry 0's fields differently
        // from entries 1-4. Semantic equality is the contract.
        assert_eq!(Store::decode(&env, &blob).unwrap(), s);
    }

    #[test]
    fn the_json_carries_the_vendor_field_names() {
        let text = serde_json::to_string(&store()).unwrap();
        for name in [
            "WEBUSERS", "u8UserId", "userName", "passWord", "EncNamePass",
            "status", "accountLocked", "accLockedTime", "userCreatedDate",
            "userUpdatedDate", "accLockedCount",
        ] {
            assert!(text.contains(&format!("\"{name}\"")), "missing {name}");
        }
        // and none of Rust's snake_case leaks through
        assert!(!text.contains("user_name"), "{text}");
        assert!(!text.contains("enc_name_pass"), "{text}");
    }

    #[test]
    fn validate_rejects_a_wrong_slot_count() {
        let mut s = store();
        s.users.pop();
        let e = s.validate().unwrap_err();
        assert!(e.contains("exactly 5"), "{e}");
    }

    #[test]
    fn validate_rejects_a_tampered_digest() {
        let mut s = store();
        // the failure this catches: someone changes the password and forgets
        // to reseal, leaving a file the keypad and the web disagree about
        s.users[2].password = "9999".into();
        let e = s.validate().unwrap_err();
        assert!(e.contains("EncNamePass"), "{e}");
        s.users[2].reseal();
        assert!(s.validate().is_ok());
    }

    #[test]
    fn a_truncated_or_wrongly_keyed_file_is_an_error_not_a_panic() {
        let env = test_env();
        let other = Envelope { key: *b"ffffffffffffffff", iv: test_env().iv };
        let blob = store().encode(&env).unwrap();
        assert!(Store::decode(&other, &blob).is_err(), "wrong key must not parse");
        assert!(Store::decode(&env, &blob[..20]).is_err(), "truncation must not parse");
        assert!(Store::decode(&env, &[]).is_err(), "empty must not parse");
    }

    #[test]
    fn authenticate_accepts_the_right_code_and_nothing_else() {
        let s = store();
        assert_eq!(s.authenticate("User3", "1234").unwrap().user_id, 3);
        // the digest binds the LOWERCASED name, so the vendor already treats
        // names case-insensitively and so must this
        assert_eq!(s.authenticate("user3", "1234").unwrap().user_id, 3);
        assert_eq!(s.authenticate("USER3", "1234").unwrap().user_id, 3);

        assert_eq!(s.authenticate("User3", "1235"), Err(Denied::WrongPassword));
        assert_eq!(s.authenticate("nobody", "1234"), Err(Denied::NoSuchUser));
        // a prefix must not pass: ct_eq compares lengths first
        assert_eq!(s.authenticate("User3", "123"), Err(Denied::WrongPassword));
        assert_eq!(s.authenticate("User3", "12345"), Err(Denied::WrongPassword));
        assert_eq!(s.authenticate("User3", ""), Err(Denied::WrongPassword));
    }

    #[test]
    fn authenticate_honours_the_vendors_status_and_lock_fields() {
        let mut s = store();
        s.users[0].status = 0;
        assert_eq!(s.authenticate("User1", "1234"), Err(Denied::Disabled));

        s.users[1].account_locked = 1;
        assert_eq!(s.authenticate("User2", "1234"), Err(Denied::Locked));

        // and a locked account must not be openable by the right code either
        s.users[1].account_locked = 1;
        assert!(s.authenticate("User2", "1234").is_err());
    }

    #[test]
    fn a_tampered_entry_is_refused_rather_than_guessed_at() {
        let mut s = store();
        // password changed without resealing: the file now disagrees with
        // itself, and picking a winner would be inventing an answer
        s.users[3].password = "0000".into();
        assert_eq!(s.authenticate("User4", "0000"), Err(Denied::Tampered));
        assert_eq!(s.authenticate("User4", "1234"), Err(Denied::Tampered));
        s.users[3].reseal();
        assert_eq!(s.authenticate("User4", "0000").unwrap().user_id, 4);
    }

    #[test]
    fn save_writes_both_paths_identically_and_leaves_no_temp_files() {
        let env = test_env();
        let dir = std::env::temp_dir().join(format!("tuxweb-acct-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main = dir.join("webuseraccountsenc.json");
        let mirror = dir.join("webuseraccountsenc_sec.json");
        let (m, s) = (main.to_str().unwrap(), mirror.to_str().unwrap());

        let n = save(&env, &store(), m, s).unwrap();
        let a = std::fs::read(&main).unwrap();
        let b = std::fs::read(&mirror).unwrap();
        assert_eq!(a.len(), n);
        // the panel's own two files had identical md5s; ours must too
        assert_eq!(a, b, "the mirror must be byte-identical to the main file");
        assert_eq!(Store::decode(&env, &a).unwrap(), store());

        for f in std::fs::read_dir(&dir).unwrap() {
            let p = f.unwrap().path();
            assert!(
                !p.to_string_lossy().contains("tuxweb-new"),
                "a temporary file was left behind: {p:?}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_refuses_an_inconsistent_store_before_touching_anything() {
        let env = test_env();
        let dir = std::env::temp_dir().join(format!("tuxweb-acct-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main = dir.join("main.json");
        let mirror = dir.join("mirror.json");

        let mut s = store();
        s.users[0].password = "9999".into(); // changed without resealing
        let e = save(&env, &s, main.to_str().unwrap(), mirror.to_str().unwrap()).unwrap_err();
        assert!(e.contains("EncNamePass"), "{e}");
        assert!(!main.exists(), "nothing may be written when validation fails");
        assert!(!mirror.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_va_walks_program_headers_and_refuses_rubbish() {
        assert!(read_va(b"not an elf", KEY_VA).is_none());
        assert!(read_va(&[], KEY_VA).is_none());
        // a 64-bit ELF header must be refused rather than misread
        let mut e64 = vec![0u8; 0x40];
        e64[..4].copy_from_slice(b"\x7fELF");
        e64[4] = 2;
        assert!(read_va(&e64, KEY_VA).is_none());
    }
}
