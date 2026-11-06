//! Just enough DER to read what a certificate install checks in a leaf: its
//! validity window, its subjectAltName and its SubjectPublicKeyInfo.
//!
//! rustls and webpki parse certificates but do not hand these fields out, and a
//! full X.509 crate is a large dependency for three fields. This walks the
//! RFC 5280 `Certificate` structure and refuses anything that does not have
//! that shape; it does not verify signatures (nothing here trusts the issuer).

/// What `certinstall` needs from a leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf<'a> {
    /// `notBefore`, seconds since the Unix epoch.
    pub not_before: i64,
    /// `notAfter`, seconds since the Unix epoch.
    pub not_after: i64,
    /// `notAfter` as RFC 3339 UTC, e.g. `2027-11-06T12:00:00Z`.
    pub not_after_rfc3339: String,
    /// The whole `SubjectPublicKeyInfo` element, tag and length included, the
    /// same bytes rustls's `SigningKey::public_key` produces for a matching key.
    pub spki: &'a [u8],
    /// Entries in the subjectAltName extension; 0 when it is absent.
    pub san_entries: usize,
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0] EXPLICIT Version`.
const VERSION: u8 = 0xa0;
/// `[1] IMPLICIT issuerUniqueID`, `[2] IMPLICIT subjectUniqueID`.
const ISSUER_UID: u8 = 0x81;
const SUBJECT_UID: u8 = 0x82;
/// `[3] EXPLICIT Extensions`.
const EXTENSIONS: u8 = 0xa3;
/// id-ce-subjectAltName, 2.5.29.17, as encoded content.
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

/// One TLV: its tag, its content, and the whole element.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    whole: &'a [u8],
}

/// Read one element off the front of `input`; the rest follows it.
fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *input.first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tags do not occur in a certificate
    }
    let b1 = *input.get(1)?;
    let (len, hdr) = if b1 < 0x80 {
        (b1 as usize, 2)
    } else {
        let n = (b1 & 0x7f) as usize;
        if n == 0 || n > 3 {
            return None; // indefinite length, or longer than any certificate
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *input.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let whole = input.get(..end)?;
    Some((
        Tlv {
            tag,
            value: &whole[hdr..],
            whole,
        },
        &input[end..],
    ))
}

/// Read one element that must carry `tag`.
fn expect(input: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    read(input).filter(|(t, _)| t.tag == tag)
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn digits(s: &[u8]) -> Option<u32> {
    s.iter().try_fold(0u32, |acc, &c| {
        c.is_ascii_digit().then(|| acc * 10 + u32::from(c - b'0'))
    })
}

/// An RFC 5280 `Time`: UTCTime `YYMMDDHHMMSSZ` (years 1950-2049) or
/// GeneralizedTime `YYYYMMDDHHMMSSZ`. Returns Unix seconds and RFC 3339.
fn time(t: &Tlv<'_>) -> Option<(i64, String)> {
    let v = t.value;
    let (year, rest) = match t.tag {
        UTC_TIME if v.len() == 13 => {
            let yy = digits(&v[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &v[2..])
        }
        GENERALIZED_TIME if v.len() == 15 => (digits(&v[..4])?, &v[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let (mo, d, h, mi, s) = (
        digits(&rest[0..2])?,
        digits(&rest[2..4])?,
        digits(&rest[4..6])?,
        digits(&rest[6..8])?,
        digits(&rest[8..10])?,
    );
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo) || d == 0 || d > month_days[mo as usize - 1] {
        return None;
    }
    if h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let secs = days_from_civil(i64::from(year), mo, d) * 86_400
        + i64::from(h) * 3600
        + i64::from(mi) * 60
        + i64::from(s);
    Some((
        secs,
        format!("{year:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"),
    ))
}

/// Count the GeneralNames in a subjectAltName extension value.
fn san_entries(ext_value: &[u8]) -> Option<usize> {
    let (names, rest) = expect(ext_value, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let mut n = 0;
    let mut cur = names.value;
    while !cur.is_empty() {
        let (_, r) = read(cur)?;
        cur = r;
        n += 1;
    }
    Some(n)
}

/// Walk `Extensions` and return the subjectAltName entry count (0 if absent).
fn extensions_san(exts: &[u8]) -> Option<usize> {
    let (list, rest) = expect(exts, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let mut san = 0;
    let mut cur = list.value;
    while !cur.is_empty() {
        let (ext, r) = expect(cur, SEQUENCE)?;
        cur = r;
        let (oid, mut inner) = expect(ext.value, OID)?;
        if let Some((b, r)) = expect(inner, BOOLEAN) {
            if b.value.len() != 1 {
                return None;
            }
            inner = r;
        }
        let (value, r) = expect(inner, OCTET_STRING)?;
        if !r.is_empty() {
            return None;
        }
        if oid.value == OID_SAN {
            san = san_entries(value.value)?;
        }
    }
    Some(san)
}

/// Parse a DER certificate. `None` for anything that is not a well-formed
/// X.509 `Certificate` with a readable validity window.
pub fn parse(der: &[u8]) -> Option<Leaf<'_>> {
    let (cert, rest) = expect(der, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (tbs, r) = expect(cert.value, SEQUENCE)?;
    let (_sig_alg, r) = expect(r, SEQUENCE)?;
    let (_sig, r) = expect(r, BIT_STRING)?;
    if !r.is_empty() {
        return None;
    }

    let mut cur = tbs.value;
    if let Some((_, r)) = expect(cur, VERSION) {
        cur = r;
    }
    let (_serial, r) = expect(cur, INTEGER)?;
    let (_alg, r) = expect(r, SEQUENCE)?;
    let (_issuer, r) = expect(r, SEQUENCE)?;
    let (validity, r) = expect(r, SEQUENCE)?;
    let (_subject, r) = expect(r, SEQUENCE)?;
    let (spki, mut cur) = expect(r, SEQUENCE)?;

    let (nb, vr) = read(validity.value)?;
    let (na, vr) = read(vr)?;
    if !vr.is_empty() {
        return None;
    }
    let (not_before, _) = time(&nb)?;
    let (not_after, not_after_rfc3339) = time(&na)?;

    let mut san = 0;
    for tag in [ISSUER_UID, SUBJECT_UID, EXTENSIONS] {
        if let Some((t, r)) = expect(cur, tag) {
            if tag == EXTENSIONS {
                san = extensions_san(t.value)?;
            }
            cur = r;
        }
    }
    if !cur.is_empty() {
        return None;
    }
    Some(Leaf {
        not_before,
        not_after,
        not_after_rfc3339,
        spki: spki.whole,
        san_entries: san,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_days_match_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 11, 6), 20_763);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    fn t(tag: u8, s: &str) -> Option<(i64, String)> {
        let mut v = vec![tag, s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        let (tlv, _) = read(&v).unwrap();
        time(&tlv).map(|(n, r)| (n, r.to_string()))
    }

    #[test]
    fn both_time_forms_parse_and_bad_ones_do_not() {
        assert_eq!(
            t(UTC_TIME, "261106120000Z"),
            Some((1_793_966_400, "2026-11-06T12:00:00Z".into()))
        );
        // two-digit years at or above 50 are the 1900s
        assert_eq!(
            t(UTC_TIME, "500101000000Z").unwrap().1,
            "1950-01-01T00:00:00Z"
        );
        assert_eq!(
            t(GENERALIZED_TIME, "21000101000000Z").unwrap(),
            (4_102_444_800, "2100-01-01T00:00:00Z".into())
        );
        assert!(t(UTC_TIME, "261306120000Z").is_none(), "month 13");
        assert!(t(UTC_TIME, "270229120000Z").is_none(), "not a leap year");
        assert!(t(UTC_TIME, "261106120000+").is_none(), "only Z is RFC 5280");
        assert!(
            t(GENERALIZED_TIME, "261106120000Z").is_none(),
            "wrong length"
        );
    }

    #[test]
    fn a_truncated_or_trailing_element_is_refused() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x30, 0x05, 0x02, 0x01]).is_none());
        assert!(parse(&[0x30, 0x00, 0x00]).is_none());
    }
}
