//! Stage 8d: the switch that turns tuxweb-installed-as-`Barracuda` into the
//! permanent server, and the guard that keeps a crash loop away from the
//! 24-relaunch hardware reset.
//!
//! `supervis` launches `/opt/webserver/Barracuda` with no arguments, so a
//! command line cannot select the mode. The stage-6/7 windows used a one-shot
//! marker that entering CONSUMED; a permanent server needs the opposite -- a
//! setting that survives every relaunch until someone removes it. So:
//!
//! * **`SERVE_CONF` present on mtd17 ⇒ serve mode** (bind, cert, token store…).
//!   Absent ⇒ the existing behaviour, a passthrough `execve` of the vendor. The
//!   panel therefore converges on the vendor from any state where the file is
//!   gone, and the revert is `rm` + `kill -9`, never a reflash.
//! * **The per-boot launch counter.** `/tmp` is tmpfs and a boot clears it, the
//!   same lifetime as `supervis`'s relaunch budget. Every serve-mode launch
//!   bumps it; past [`MAX_LAUNCHES_PER_BOOT`] tuxweb refuses serve mode and
//!   passes through instead, loudly. A serve build that crashes on launch is
//!   thereby bounded to a handful of the 24 relaunches and the panel keeps a
//!   working web server, rather than resetting itself in hardware with somebody
//!   standing in front of it (`TRAPS.md` §6).

use std::collections::BTreeMap;

/// On mtd17 so it survives a reflash -- and so a reflash does NOT silently
/// switch the panel back to the vendor either; that is a deliberate `rm`.
pub const SERVE_CONF: &str = "/opt/tuxedo/configuration/tuxweb-serve.conf";
/// tmpfs: cleared by a boot, like the relaunch budget it guards.
pub const LAUNCH_COUNTER: &str = "/tmp/tuxweb-serve-launches";
/// Serve-mode launches allowed per boot before falling back to passthrough.
/// Six spends a quarter of the budget on a broken build and leaves the rest.
pub const MAX_LAUNCHES_PER_BOOT: u32 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeConf {
    pub bind: String,
    pub redirect_bind: Option<String>,
    pub chain: Option<String>,
    pub key: Option<String>,
    pub token_store: String,
    pub quickarm: String,
    pub session: u32,
    /// Seconds of reply-queue silence before re-registering (`serve.rs`).
    pub silence: std::time::Duration,
}

/// Parse `key=value` lines. `#` comments and blank lines are ignored; unknown
/// keys are an error so a typo cannot silently mean "default". Every setting
/// has a panel-appropriate default except the cert pair, which is optional
/// only so the bench can run plaintext -- `serve` warns loudly without it.
pub fn parse(text: &str) -> Result<ServeConf, String> {
    let mut kv: BTreeMap<String, String> = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("line {}: expected key=value, got {line:?}", n + 1));
        };
        let k = k.trim();
        match k {
            "bind" | "redirect_bind" | "chain" | "key" | "token_store" | "quickarm"
            | "session" | "silence" => {}
            other => return Err(format!("line {}: unknown key {other:?}", n + 1)),
        }
        kv.insert(k.to_string(), v.trim().to_string());
    }
    let get = |k: &str| kv.get(k).cloned().filter(|v| !v.is_empty());
    let session = match get("session") {
        Some(s) => s.parse::<u32>().map_err(|_| format!("session: not a number: {s:?}"))?,
        None => 4242,
    };
    if session == 0 {
        return Err("session must be non-zero".into());
    }
    let silence = match get("silence") {
        Some(s) => {
            let secs = s.parse::<u64>().map_err(|_| format!("silence: not a number: {s:?}"))?;
            if secs == 0 {
                return Err("silence must be non-zero (it would re-register every tick)".into());
            }
            std::time::Duration::from_secs(secs)
        }
        None => crate::serve::DEFAULT_SILENCE,
    };
    Ok(ServeConf {
        bind: get("bind").unwrap_or_else(|| "0.0.0.0:443".into()),
        redirect_bind: Some(get("redirect_bind").unwrap_or_else(|| "0.0.0.0:80".into()))
            .filter(|s| s != "none"),
        chain: get("chain"),
        key: get("key"),
        token_store: get("token_store").unwrap_or_else(|| crate::auth::TOKEN_STORE.into()),
        quickarm: get("quickarm").unwrap_or_else(|| crate::session::QUICKARM_STATE.into()),
        session,
        silence,
    })
}

/// `None` if the file is absent (passthrough); `Some(Err)` if present but bad,
/// which the caller treats as "do not serve" -- a malformed switch must not be
/// read as any particular mode.
pub fn load(path: &str) -> Option<Result<ServeConf, String>> {
    match std::fs::read_to_string(path) {
        Ok(t) => Some(parse(&t).map_err(|e| format!("{path}: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(Err(format!("{path}: {e}"))),
    }
}

/// Increment the per-boot serve-launch counter and return the new count. A
/// counter that cannot be read counts as 0 and one that cannot be written is
/// reported but does not stop the launch -- the guard is a bound on a crash
/// loop, and a missing `/tmp` is a different, louder problem.
pub fn bump_launches(path: &str) -> u32 {
    let n: u32 = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
        + 1;
    if let Err(e) = std::fs::write(path, n.to_string()) {
        eprintln!("tuxweb: cannot write launch counter {path}: {e}");
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_panel_ports_and_paths() {
        let c = parse("").unwrap();
        assert_eq!(c.bind, "0.0.0.0:443");
        assert_eq!(c.redirect_bind.as_deref(), Some("0.0.0.0:80"));
        assert_eq!(c.token_store, crate::auth::TOKEN_STORE);
        assert_eq!(c.quickarm, crate::session::QUICKARM_STATE);
        assert_eq!(c.session, 4242);
        assert!(c.chain.is_none() && c.key.is_none());
        assert_eq!(c.silence, crate::serve::DEFAULT_SILENCE);
        // the bench sets it short; zero is refused (it would re-register every tick)
        assert_eq!(parse("silence=8").unwrap().silence.as_secs(), 8);
        assert!(parse("silence=0").unwrap_err().contains("non-zero"));
    }

    #[test]
    fn settings_override_and_comments_are_ignored() {
        let c = parse(
            "# bench\nbind = 127.0.0.1:48080\nredirect_bind=127.0.0.1:48081\n\
             chain=/tmp/c.pem\nkey=/tmp/k.pem\ntoken_store=/tmp/t.json\nsession=7\n",
        )
        .unwrap();
        assert_eq!(c.bind, "127.0.0.1:48080");
        assert_eq!(c.redirect_bind.as_deref(), Some("127.0.0.1:48081"));
        assert_eq!(c.chain.as_deref(), Some("/tmp/c.pem"));
        assert_eq!(c.session, 7);
        // "none" switches the redirect listener off
        assert_eq!(parse("redirect_bind=none").unwrap().redirect_bind, None);
    }

    #[test]
    fn a_typo_or_a_zero_session_is_an_error_not_a_default() {
        assert!(parse("bnid=1.2.3.4:443").unwrap_err().contains("unknown key"));
        assert!(parse("garbage line").unwrap_err().contains("key=value"));
        assert!(parse("session=0").unwrap_err().contains("non-zero"));
        assert!(parse("session=abc").unwrap_err().contains("not a number"));
    }

    #[test]
    fn absent_is_passthrough_and_malformed_is_an_error() {
        let p = std::env::temp_dir().join(format!("sc-{}.conf", std::process::id()));
        let path = p.to_str().unwrap();
        let _ = std::fs::remove_file(&p);
        assert!(load(path).is_none(), "no file means no serve mode");
        std::fs::write(&p, "nope").unwrap();
        assert!(matches!(load(path), Some(Err(_))), "a bad file must not select a mode");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn the_launch_counter_counts_and_the_guard_trips_past_the_bound() {
        let p = std::env::temp_dir().join(format!("lc-{}", std::process::id()));
        let path = p.to_str().unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(bump_launches(path), 1);
        assert_eq!(bump_launches(path), 2);
        for _ in 0..MAX_LAUNCHES_PER_BOOT {
            bump_launches(path);
        }
        assert!(bump_launches(path) > MAX_LAUNCHES_PER_BOOT, "past the bound: passthrough");
        // and the bound is well inside the 24-relaunch reset
        assert!(MAX_LAUNCHES_PER_BOOT < 24 / 2);
        let _ = std::fs::remove_file(&p);
    }
}
