//! Stage 8b: the typed API tuxweb serves from IPC.
//!
//! Two kinds of endpoint. The **capability endpoint** is new and is a
//! release-one requirement (§4.10.2): without it a public integration cannot
//! tell a replacement from stock without probing a stranger's alarm panel, so
//! every other improvement is unreachable. The **security endpoints** reproduce
//! the vendor's paths and — critically — its response *shapes*, misspellings and
//! all (§4.10.4): `Sucess`, and arm/disarm using different inner keys. Tidying
//! either breaks every client written against vendor firmware.
//!
//! This module is the pure part: routing (method+path -> [`Action`]) and the
//! response bytes. The queue I/O an `Action` implies — send a command, wait for
//! the reply — is the serve mode's job and reuses the proven stage-7 send path;
//! keeping it out of here is what lets every branch be a unit test.

use crate::ipc::cmd;

/// `tuxweb/<version>`, e.g. `tuxweb/0.1.0`. Clients branch on `capabilities`,
/// never on this (§4.10.6), but it is reported for humans.
pub const FIRMWARE: &str = concat!("tuxweb/", env!("CARGO_PKG_VERSION"));

/// Moves only when the SHAPE of the contract changes incompatibly, never for a
/// feature (§4.10.6). Clients do not branch on it.
pub const CONTRACT: u32 = 1;

/// Reported in the capability body; the panel's own four-letter model.
pub const PANEL_MODEL: &str = "TUXW";

/// The capabilities this build serves. Unordered; unknown strings are ignored
/// by clients, and adding one is backward compatible. These three are the free
/// wins reading the queue directly gives us (§4.10.3).
pub const CAPABILITIES: &[&str] = &["panel_link_state", "command_result", "status_refresh"];

/// The vendor namespace every real endpoint lives under. An unknown endpoint
/// INSIDE it 404s cleanly; unknown TOP-LEVEL paths 302 to a slash variant, so
/// staying inside it is the clean option (§4.10.6).
const API: &str = "/system_http_api/API_REV01";

/// What a request resolves to. The serve mode turns the IPC-backed ones into a
/// command + reply; the rest are answered from the response builders directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `GET /…/GetCapabilities` — session-optional, always 200 on custom.
    Capabilities,
    /// `POST /…/AdvancedSecurity/ArmWithCode` — `code` is ARM_AWAY/STAY/NIGHT.
    Arm { code: u32 },
    /// `POST /…/AdvancedSecurity/DisarmWithCode`.
    Disarm,
    /// `GET|POST /…/GetSecurityStatus` — read-only, served from the state model.
    Status,
    /// A known endpoint reached with the wrong method → 405.
    MethodNotAllowed,
    /// Anything else inside the API namespace → 404, the permanent absence
    /// answer a client keys its silent-fallback path on (§4.10.6).
    NotFound,
}

/// The request target with any query string removed, so `?url=x` does not defeat
/// an exact path match. Leaves the path otherwise untouched.
fn path_only(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

/// Route a request. `arm_code` supplies the arming level for `ArmWithCode`,
/// which the vendor takes in the request body/parameters rather than the path;
/// the serve mode parses it and passes it in, defaulting to ARM_STAY when a
/// client names no level, so a bare arm request is the least surprising one.
pub fn classify(method: &str, target: &str, arm_code: u32) -> Action {
    let path = path_only(target);
    let Some(rest) = path.strip_prefix(API) else {
        // Outside the namespace is not this router's business; the serve mode
        // handles static assets and the UI. Treat as not-an-API-call.
        return Action::NotFound;
    };
    match rest {
        "/GetCapabilities" => {
            if method.eq_ignore_ascii_case("GET") {
                Action::Capabilities
            } else {
                Action::MethodNotAllowed
            }
        }
        "/AdvancedSecurity/ArmWithCode" => {
            if method.eq_ignore_ascii_case("POST") {
                Action::Arm { code: arm_code }
            } else {
                Action::MethodNotAllowed
            }
        }
        "/AdvancedSecurity/DisarmWithCode" => {
            if method.eq_ignore_ascii_case("POST") {
                Action::Disarm
            } else {
                Action::MethodNotAllowed
            }
        }
        "/GetSecurityStatus" => {
            // Read-only; the vendor client POSTs it, but a GET is just as safe.
            if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("POST") {
                Action::Status
            } else {
                Action::MethodNotAllowed
            }
        }
        _ => Action::NotFound,
    }
}

fn http(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

/// `200` capability body. Built by hand rather than via serde so the exact
/// fields are visible here and cannot drift with a serializer's key ordering;
/// clients parse it as JSON and branch only on `capabilities`.
pub fn capabilities_response() -> Vec<u8> {
    let caps = CAPABILITIES
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        "{{\"contract\":{CONTRACT},\"firmware\":\"{FIRMWARE}\",\
         \"panel_model\":\"{PANEL_MODEL}\",\"capabilities\":[{caps}]}}"
    );
    http("200 OK", "application/json", body.as_bytes())
}

/// `404`, reproducing the exact 20-byte stock body (`{Status:"Not Found"}`,
/// MEASURED). 404 must remain the absence answer permanently (§4.10.6); a client
/// keys its silent path on it, so this is a hard contract, not a nicety.
pub fn not_found() -> Vec<u8> {
    http("404 Not Found", "application/json", b"{Status:\"Not Found\"}")
}

/// `405`, the answer for a known endpoint reached with the wrong method — one of
/// the three distinguishable answers (404/405/200) the vendor namespace gives
/// for free (§4.10.6).
pub fn method_not_allowed() -> Vec<u8> {
    http(
        "405 Method Not Allowed",
        "application/json",
        b"{Status:\"Method Not Allowed\"}",
    )
}

/// Arm's success body. `"Sucess"` and the inner key `"Response"` are the
/// vendor's and are part of the contract (§4.10.4) — do not correct either.
pub fn arm_success() -> Vec<u8> {
    http(
        "200 OK",
        "application/json",
        b"{\"Status\":\"Sucess\",\"Result\":{\"Response\":\"Command sent sucessfully\"}}",
    )
}

/// Disarm's success body. Note the inner key is `"Result"`, NOT `"Response"` —
/// arm and disarm are asymmetric on the vendor and a client depends on it
/// (§4.10.4). `result` is the disarm result string the panel returned.
pub fn disarm_success(result: &str) -> Vec<u8> {
    let body = format!(
        "{{\"Status\":\"Sucess\",\"Result\":{{\"Result\":\"{}\"}}}}",
        json_escape(result)
    );
    http("200 OK", "application/json", body.as_bytes())
}

/// Minimal JSON string escaping for a value we place inside a body. The disarm
/// result comes from the panel; escape the characters that would otherwise
/// break the JSON rather than trusting it.
fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// The arming level a client asked for, mapped to a command code. Names match
/// the vendor's arming vocabulary; an unrecognised or absent level is ARM_STAY,
/// the least consequential of the three (it does not commit an empty house to
/// an away schedule).
pub fn arm_code_for(level: &str) -> u32 {
    match level.to_ascii_lowercase().as_str() {
        "away" => cmd::ARM_AWAY,
        "night" => cmd::ARM_NIGHT,
        _ => cmd::ARM_STAY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[u8]) -> String {
        String::from_utf8(v.to_vec()).unwrap()
    }

    #[test]
    fn get_capabilities_is_routed_and_post_to_it_is_405() {
        assert_eq!(
            classify("GET", "/system_http_api/API_REV01/GetCapabilities", 0),
            Action::Capabilities
        );
        // a query string must not defeat the match
        assert_eq!(
            classify("GET", "/system_http_api/API_REV01/GetCapabilities?x=1", 0),
            Action::Capabilities
        );
        assert_eq!(
            classify("POST", "/system_http_api/API_REV01/GetCapabilities", 0),
            Action::MethodNotAllowed
        );
    }

    #[test]
    fn arm_and_disarm_are_post_only_and_carry_the_right_codes() {
        assert_eq!(
            classify("POST", "/system_http_api/API_REV01/AdvancedSecurity/ArmWithCode", cmd::ARM_AWAY),
            Action::Arm { code: cmd::ARM_AWAY }
        );
        assert_eq!(
            classify("POST", "/system_http_api/API_REV01/AdvancedSecurity/DisarmWithCode", 0),
            Action::Disarm
        );
        // GET on a write endpoint is a 405, never a silent no-op
        assert_eq!(
            classify("GET", "/system_http_api/API_REV01/AdvancedSecurity/ArmWithCode", 0),
            Action::MethodNotAllowed
        );
    }

    #[test]
    fn status_is_routed_for_get_and_post() {
        assert_eq!(
            classify("GET", "/system_http_api/API_REV01/GetSecurityStatus", 0),
            Action::Status
        );
        assert_eq!(
            classify("POST", "/system_http_api/API_REV01/GetSecurityStatus", 0),
            Action::Status
        );
        assert_eq!(
            classify("DELETE", "/system_http_api/API_REV01/GetSecurityStatus", 0),
            Action::MethodNotAllowed
        );
    }

    #[test]
    fn unknown_endpoints_inside_the_namespace_are_404() {
        assert_eq!(
            classify("GET", "/system_http_api/API_REV01/Nope", 0),
            Action::NotFound
        );
        // and something entirely outside the namespace is not an API call
        assert_eq!(classify("GET", "/index.html", 0), Action::NotFound);
    }

    #[test]
    fn capability_body_has_the_settled_fields() {
        let r = s(&capabilities_response());
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(r.contains("Content-Type: application/json\r\n"));
        let body = r.split("\r\n\r\n").nth(1).unwrap();
        // valid JSON, and every field §4.10.6 names is present
        let v: serde_json::Value = serde_json::from_str(body).expect("capabilities body is JSON");
        assert_eq!(v["contract"], 1);
        assert_eq!(v["firmware"], "tuxweb/0.1.0");
        assert_eq!(v["panel_model"], "TUXW");
        let caps = v["capabilities"].as_array().unwrap();
        assert!(caps.iter().any(|c| c == "command_result"));
        assert!(caps.iter().any(|c| c == "panel_link_state"));
        assert!(caps.iter().any(|c| c == "status_refresh"));
    }

    #[test]
    fn the_absence_answer_is_a_404_with_the_measured_body() {
        let r = s(&not_found());
        assert!(r.starts_with("HTTP/1.1 404 Not Found\r\n"), "{r}");
        // the exact 20-byte stock body, malformed-JSON key and all
        assert!(r.ends_with("{Status:\"Not Found\"}"), "{r}");
        assert_eq!("{Status:\"Not Found\"}".len(), 20, "the measured length");
    }

    #[test]
    fn arm_and_disarm_bodies_preserve_the_vendor_quirks() {
        let arm = s(&arm_success());
        assert!(arm.contains("\"Status\":\"Sucess\""), "the misspelling is the contract");
        assert!(arm.contains("\"Response\":\"Command sent sucessfully\""), "{arm}");

        let dis = s(&disarm_success("Disarmed"));
        assert!(dis.contains("\"Status\":\"Sucess\""));
        // disarm uses "Result", not "Response" -- the asymmetry is load-bearing
        assert!(dis.contains("\"Result\":{\"Result\":\"Disarmed\"}"), "{dis}");
        assert!(!dis.contains("\"Response\""), "disarm must not use arm's key");
    }

    #[test]
    fn a_disarm_result_is_json_escaped() {
        // the result comes from the panel; a quote in it must not break the body
        let dis = s(&disarm_success("a\"b"));
        let body = dis.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body).expect("still valid JSON");
        assert_eq!(v["Result"]["Result"], "a\"b");
    }

    #[test]
    fn arm_level_names_map_to_the_verified_codes() {
        assert_eq!(arm_code_for("away"), cmd::ARM_AWAY);
        assert_eq!(arm_code_for("night"), cmd::ARM_NIGHT);
        assert_eq!(arm_code_for("stay"), cmd::ARM_STAY);
        // absent/unknown level is the least consequential arm
        assert_eq!(arm_code_for(""), cmd::ARM_STAY);
        assert_eq!(arm_code_for("nonsense"), cmd::ARM_STAY);
    }
}
