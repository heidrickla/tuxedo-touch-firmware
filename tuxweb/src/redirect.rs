//! Stage 8c: what port 80 does once the vendor is gone -- redirect, nothing else.
//!
//! §2.6: "Port 80 answers exactly two things: a `301` to `https://` preserving
//! path and query, and (only while the legacy flag is on) the push stream. No
//! login form, no `200` on an HTML page, no `Set-Cookie`, no credential
//! accepted, ever." This module is the first of those two. The push-on-80
//! escape hatch (`push.legacy_plaintext`) defaults off and is wired in the serve
//! mode, not here.
//!
//! The redirect PRESERVES path and query. The vendor's defect was that `/`
//! redirected to a fixed page (`/redirect.html`) rather than to what was asked
//! for (§2.6); a bookmarked `https://panel/tuxedoapi.html` must survive the
//! http->https bounce, so the request target is copied through verbatim.
//!
//! Absolute redirects need a host, and it comes from the request's own `Host`
//! header -- never from a configured guess, so the panel does not send a client
//! to a name it was not already using. A request with no usable `Host` gets a
//! `400`, because an absolute `https://` Location cannot be formed without one
//! and a relative one cannot change scheme.

/// The status line + request target of an HTTP request head.
fn request_target(head: &str) -> Option<&str> {
    let line = head.lines().next()?;
    let mut it = line.split(' ');
    let _method = it.next()?;
    let target = it.next()?;
    // must look like HTTP/x on the third field, or this is not a request line
    let version = it.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    Some(target)
}

/// The `Host` header value with any `:port` stripped. Case-insensitive header
/// name; the value keeps its host but loses the port, because the redirect goes
/// to https and naming `:80` in an https URL would be wrong.
fn host(head: &str) -> Option<String> {
    for line in head.split("\r\n").skip(1) {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("host") {
            let v = v.trim();
            // IPv6 literal in brackets keeps its colons; only a trailing :port
            // after the bracket or after a bare host is stripped.
            let hostname = if let Some(rest) = v.strip_prefix('[') {
                // [::1]:80 -> [::1]
                match rest.split_once(']') {
                    Some((inner, _)) => format!("[{inner}]"),
                    None => v.to_string(),
                }
            } else {
                v.split(':').next().unwrap_or(v).to_string()
            };
            if hostname.is_empty() {
                return None;
            }
            return Some(hostname);
        }
    }
    None
}

/// Normalise the request target to an origin-form path+query beginning with `/`.
///
/// Origin-form (`/x?y`) is copied through. Absolute-form
/// (`http://host/x?y`, sent by some proxies) contributes only its path+query.
/// `*` (OPTIONS) and anything else become `/`.
fn path_and_query(target: &str) -> String {
    if target.starts_with('/') {
        return target.to_string();
    }
    if let Some(after) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        return match after.find('/') {
            Some(i) => after[i..].to_string(),
            None => "/".to_string(),
        };
    }
    "/".to_string()
}

/// Build the response port 80 returns for a request head: a `301` to the same
/// path+query under https, or a `400` if the request is unusable.
pub fn respond(head: &str) -> Vec<u8> {
    let Some(target) = request_target(head) else {
        return bad_request("malformed request line");
    };
    let Some(h) = host(head) else {
        return bad_request("no Host header: cannot form an absolute https redirect");
    };
    let loc = format!("https://{}{}", h, path_and_query(target));
    format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {loc}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes()
}

fn bad_request(why: &str) -> Vec<u8> {
    // A body so a human hitting it with curl sees why; no HTML, no form.
    let body = format!("400 Bad Request: {why}\n");
    format!(
        "HTTP/1.1 400 Bad Request\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[u8]) -> String {
        String::from_utf8(v.to_vec()).unwrap()
    }

    #[test]
    fn path_and_query_are_preserved() {
        let head = "GET /authenticated/tuxedoapi.html?url=x&y=2 HTTP/1.1\r\n\
                    Host: 203.0.113.5\r\n\r\n";
        let r = s(&respond(head));
        assert!(r.starts_with("HTTP/1.1 301 Moved Permanently\r\n"));
        assert!(
            r.contains("Location: https://203.0.113.5/authenticated/tuxedoapi.html?url=x&y=2\r\n"),
            "{r}"
        );
        assert!(r.contains("Content-Length: 0"));
        assert!(r.to_lowercase().contains("connection: close"));
        // the defects §2.6 names must not reappear
        assert!(!r.contains("Set-Cookie"), "a redirect must not set a cookie");
        assert!(!r.to_lowercase().contains("200 ok"));
    }

    #[test]
    fn root_redirects_to_root_not_a_fixed_page() {
        // the vendor bounced / to /redirect.html; we keep the request target
        let r = s(&respond("GET / HTTP/1.1\r\nHost: panel.local\r\n\r\n"));
        assert!(r.contains("Location: https://panel.local/\r\n"), "{r}");
    }

    #[test]
    fn the_host_port_is_stripped() {
        let r = s(&respond("GET /x HTTP/1.1\r\nHost: 203.0.113.5:80\r\n\r\n"));
        assert!(r.contains("Location: https://203.0.113.5/x\r\n"), "{r}");
        assert!(!r.contains(":80"), "an https Location must not carry :80");
    }

    #[test]
    fn an_ipv6_host_keeps_its_brackets_and_loses_only_the_port() {
        let r = s(&respond("GET /x HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n"));
        assert!(r.contains("Location: https://[2001:db8::1]/x\r\n"), "{r}");
    }

    #[test]
    fn host_is_matched_case_insensitively() {
        let r = s(&respond("GET /x HTTP/1.1\r\nhOsT:  example.test \r\n\r\n"));
        assert!(r.contains("Location: https://example.test/x\r\n"), "{r}");
    }

    #[test]
    fn no_host_is_a_400_not_a_redirect_to_nowhere() {
        let r = s(&respond("GET /x HTTP/1.1\r\nAccept: */*\r\n\r\n"));
        assert!(r.starts_with("HTTP/1.1 400"), "{r}");
        assert!(!r.contains("Location:"), "no absolute redirect is possible");
    }

    #[test]
    fn a_post_is_still_redirected() {
        // 301 on any method; the browser re-issues. A login POST to port 80 must
        // be bounced to https, never accepted here.
        let r = s(&respond("POST /authenticated/index.html HTTP/1.1\r\nHost: h\r\n\r\n"));
        assert!(r.contains("301 Moved Permanently"));
        assert!(r.contains("Location: https://h/authenticated/index.html\r\n"), "{r}");
    }

    #[test]
    fn absolute_form_contributes_only_path_and_query() {
        let r = s(&respond("GET http://other/x?z=1 HTTP/1.1\r\nHost: canonical\r\n\r\n"));
        // the Location host is the Host header's, not the absolute target's
        assert!(r.contains("Location: https://canonical/x?z=1\r\n"), "{r}");
    }

    #[test]
    fn a_garbage_first_line_is_a_400() {
        let r = s(&respond("not a request\r\nHost: h\r\n\r\n"));
        assert!(r.starts_with("HTTP/1.1 400"), "{r}");
    }
}
