//! Test-only certificates, built in the test from ring keys and hand-written
//! DER. Nothing here is a fixture file: every key is generated per run and
//! never written into the repository.

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
const OID_EKU: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else if n < 0x100 {
        v.extend_from_slice(&[0x81, n as u8]);
    } else {
        v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    v.extend_from_slice(content);
    v
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn name(cn: &str) -> Vec<u8> {
    let atv = seq(&[OID_CN, &tlv(0x0c, cn.as_bytes())]);
    seq(&[&tlv(0x31, &atv)])
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// UTCTime for 1950-2049, GeneralizedTime otherwise, as RFC 5280 requires.
fn time(unix: i64) -> Vec<u8> {
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    let hms = format!("{:02}{:02}{:02}Z", s / 3600, s / 60 % 60, s % 60);
    if (1950..2050).contains(&y) {
        tlv(0x17, format!("{:02}{m:02}{d:02}{hms}", y % 100).as_bytes())
    } else {
        tlv(0x18, format!("{y:04}{m:02}{d:02}{hms}").as_bytes())
    }
}

/// A P-256 key, with its PKCS#8 encoding.
pub struct Key {
    pub pkcs8: Vec<u8>,
    pair: EcdsaKeyPair,
}

impl Key {
    pub fn generate() -> Key {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng).unwrap();
        Key { pkcs8, pair }
    }

    fn spki(&self) -> Vec<u8> {
        let mut bits = vec![0u8];
        bits.extend_from_slice(self.pair.public_key().as_ref());
        seq(&[&seq(&[OID_EC_PUBLIC_KEY, OID_P256]), &tlv(0x03, &bits)])
    }

    /// The key as PEM, the way a client sends it.
    pub fn pem(&self) -> String {
        String::from_utf8(crate::certinstall::pem("PRIVATE KEY", &self.pkcs8)).unwrap()
    }
}

/// What to put in a certificate.
pub struct Spec<'a> {
    pub cn: &'a str,
    pub issuer_cn: &'a str,
    pub not_before: i64,
    pub not_after: i64,
    /// A dNSName subjectAltName; `None` leaves the extension out.
    pub san: Option<&'a str>,
    pub ca: bool,
    pub serial: u8,
}

impl Spec<'_> {
    /// A leaf for `panel.test`, valid from an hour ago for a year.
    pub fn leaf(issuer_cn: &str) -> Spec<'_> {
        let now = crate::certinstall::now_unix();
        Spec {
            cn: "panel.test",
            issuer_cn,
            not_before: now - 3600,
            not_after: now + 365 * 86_400,
            san: Some("panel.test"),
            ca: false,
            serial: 2,
        }
    }

    /// A self-signed CA valid from an hour ago for ten years.
    pub fn ca(cn: &str) -> Spec<'_> {
        let now = crate::certinstall::now_unix();
        Spec {
            cn,
            issuer_cn: cn,
            not_before: now - 3600,
            not_after: now + 3650 * 86_400,
            san: None,
            ca: true,
            serial: 1,
        }
    }
}

/// A certificate for `subject`'s key, signed by `signer`. DER.
pub fn cert(spec: &Spec<'_>, subject: &Key, signer: &Key) -> Vec<u8> {
    let alg = seq(&[OID_ECDSA_SHA256]);
    let mut exts = Vec::new();
    if spec.ca {
        let bc = seq(&[&tlv(0x01, &[0xff])]);
        exts.push(seq(&[
            OID_BASIC_CONSTRAINTS,
            &tlv(0x01, &[0xff]),
            &tlv(0x04, &bc),
        ]));
    } else {
        let eku = seq(&[OID_SERVER_AUTH]);
        exts.push(seq(&[OID_EKU, &tlv(0x04, &eku)]));
    }
    if let Some(dns) = spec.san {
        let names = seq(&[&tlv(0x82, dns.as_bytes())]);
        exts.push(seq(&[OID_SAN, &tlv(0x04, &names)]));
    }
    let ext_refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
    let tbs = seq(&[
        &tlv(0xa0, &tlv(0x02, &[2])),
        &tlv(0x02, &[spec.serial]),
        &alg,
        &name(spec.issuer_cn),
        &seq(&[&time(spec.not_before), &time(spec.not_after)]),
        &name(spec.cn),
        &subject.spki(),
        &tlv(0xa3, &seq(&ext_refs)),
    ]);
    let sig = signer
        .pair
        .sign(&SystemRandom::new(), &tbs)
        .unwrap()
        .as_ref()
        .to_vec();
    let mut bits = vec![0u8];
    bits.extend_from_slice(&sig);
    seq(&[&tbs, &alg, &tlv(0x03, &bits)])
}

/// A CA and a leaf it issued, with the leaf's key.
pub struct Pair {
    pub ca_der: Vec<u8>,
    pub leaf_der: Vec<u8>,
    pub key: Key,
}

impl Pair {
    pub fn new(ca_cn: &str) -> Pair {
        let ca_key = Key::generate();
        let key = Key::generate();
        Pair {
            ca_der: cert(&Spec::ca(ca_cn), &ca_key, &ca_key),
            leaf_der: cert(&Spec::leaf(ca_cn), &key, &ca_key),
            key,
        }
    }

    /// Leaf first, then the issuing CA, as PEM.
    pub fn chain_pem(&self) -> String {
        let mut s =
            String::from_utf8(crate::certinstall::pem("CERTIFICATE", &self.leaf_der)).unwrap();
        s.push_str(
            &String::from_utf8(crate::certinstall::pem("CERTIFICATE", &self.ca_der)).unwrap(),
        );
        s
    }

    /// The request body that installs this pair.
    pub fn body(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "chain": self.chain_pem(),
            "key": self.key.pem(),
        }))
        .unwrap()
    }
}

#[test]
fn civil_from_days_inverts_days_from_civil() {
    for days in [-1, 0, 11_017, 20_763, 47_482, 2_932_896] {
        let (y, m, d) = civil_from_days(days);
        assert_eq!(crate::x509::days_from_civil(y, m, d), days);
    }
}
