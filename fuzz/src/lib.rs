//! Fixtures shared by the fuzz targets and the seed-corpus generator.
//!
//! Everything is deterministic: fixed keys, a fixed clock and a DRBG from a
//! fixed seed, so a crashing input reproduces exactly, on any machine, with
//! `cargo fuzz run <target> <crash-file>`.

use std::sync::OnceLock;

use ic_core::sig::{SignatureAlgorithm, Signer};
use ic_core::traits::RandomSource;
use ic_pkix::{KeyAlgorithm, PrivateKeyInfo};
use ic_sig::SoftwareSigner;
use ironpki::x509::{self, CertificateParams, RootStore};
use ironpki::{Limits, Purpose};

/// 2026-09-28T00:00:00Z. Certificates are valid for a day either side.
pub const NOW: u64 = 1_790_553_600;

/// The name the leaf certificate is issued for.
pub const NAME: &str = "fuzz.test";

/// Every algorithm a certificate, CRL or OCSP response may be signed with.
pub const ALGORITHMS: &[SignatureAlgorithm] = ironpki::sign::VERIFY_ALGORITHMS;

/// The bounds the targets validate under: a short path, so that the search
/// reaches its depth limit, and the online signature budget.
pub const LIMITS: Limits = Limits {
    max_path_len: 4,
    ..Limits::ONLINE
};

/// A DRBG from a fixed seed. Each call starts the same stream.
pub fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_entropy(&[0x5a; 48], b"ironpki-fuzz").expect("fixed DRBG")
}

/// An ECDSA P-256 key whose scalar is `n` repeated: fixed, and never zero.
pub fn key(n: u8) -> SoftwareSigner {
    let mut der = [0u8; 200];
    let len = PrivateKeyInfo::Ec {
        algorithm: KeyAlgorithm::EcP256,
        private_key: &[n; 32],
        public_key: None,
    }
    .to_der(&mut der)
    .expect("PKCS#8");
    SoftwareSigner::from_pkcs8(&der[..len]).expect("a P-256 key")
}

/// A CA, a server certificate issued by it, and the CA's key.
pub struct Pki {
    pub ca_cert: Vec<u8>,
    pub ca_key: SoftwareSigner,
    pub leaf: Vec<u8>,
    pub roots: RootStore,
}

/// The fixtures, built once per process.
pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let mut r = rng();
        let ca_key = key(1);
        let ca_cert = x509::self_signed(
            &CertificateParams {
                subject_cn: "IronPKI Fuzz Root",
                dns_names: &[],
                ip_addresses: &[],
                not_before: NOW - 86_400,
                not_after: NOW + 86_400,
                is_ca: true,
                path_len: Some(1),
                usage: &[],
                serial: [1; 16],
            },
            &ca_key,
            &mut r,
        )
        .unwrap();
        let leaf = x509::issue(
            &CertificateParams {
                subject_cn: NAME,
                dns_names: &[NAME],
                ip_addresses: &[],
                not_before: NOW - 86_400,
                not_after: NOW + 86_400,
                is_ca: false,
                path_len: None,
                usage: &[Purpose::TlsServer],
                serial: [2; 16],
            },
            key(2).public_key(),
            &ca_cert,
            &ca_key,
            &mut r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&ca_cert).unwrap();
        Pki {
            ca_cert,
            ca_key,
            leaf,
            roots,
        }
    })
}

// ---------------------------------------------------------------------------
// Differential fixtures: certificates whose to-be-signed bytes the fuzzer
// mutates and the harness re-signs, so signatures always verify and both
// path validators reach their deepest checks.

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend([0x81, n as u8]);
    } else {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(body);
    out
}

fn dn(cn: &str) -> Vec<u8> {
    let atv = [tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat();
    tlv(0x30, &tlv(0x31, &tlv(0x30, &atv)))
}

fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut b = tlv(0x06, oid);
    if critical {
        b.extend(tlv(0x01, &[0xff]));
    }
    b.extend(tlv(0x04, value));
    tlv(0x30, &b)
}

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

fn tbs(serial: u8, issuer: &str, subject: &str, spki: &[u8], exts: &[Vec<u8>]) -> Vec<u8> {
    let validity = [tlv(0x17, b"260927000000Z"), tlv(0x17, b"260929000000Z")].concat();
    tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[serial]),
            tlv(0x30, &tlv(0x06, ECDSA_SHA256)),
            dn(issuer),
            tlv(0x30, &validity),
            dn(subject),
            spki.to_vec(),
            tlv(0xa3, &tlv(0x30, &exts.concat())),
        ]
        .concat(),
    )
}

/// A certificate from `tbs`, signed by `key` (ECDSA P-256, SHA-256). A TBS
/// too long to frame gives an empty certificate, which nothing accepts.
pub fn sign_tbs(tbs: &[u8], key: &SoftwareSigner) -> Vec<u8> {
    if tbs.len() > 60_000 {
        return Vec::new();
    }
    let mut sig = [0u8; 80];
    let n = key
        .sign(
            SignatureAlgorithm::EcdsaP256Sha256,
            tbs,
            &mut rng() as &mut dyn RandomSource,
            &mut sig,
        )
        .expect("ECDSA signs any message");
    let mut bits = vec![0u8];
    bits.extend_from_slice(&sig[..n]);
    tlv(
        0x30,
        &[
            tbs.to_vec(),
            tlv(0x30, &tlv(0x06, ECDSA_SHA256)),
            tlv(0x03, &bits),
        ]
        .concat(),
    )
}

/// A root, an intermediate with name constraints (permitted dNSName,
/// rfc822Name and URI host fuzz.test, permitted iPAddress 10.0.0.0/8,
/// excluded dNSName bad.fuzz.test and directoryName "Bad Subject") and
/// with every policy extension, and a leaf under it with a name of each
/// form and a policy the intermediate's mapping makes valid; the keys sign whatever TBS
/// the fuzzer makes of them.
pub struct DiffPki {
    pub root_key: SoftwareSigner,
    pub int_key: SoftwareSigner,
    pub int_tbs: Vec<u8>,
    pub leaf_tbs: Vec<u8>,
    /// A leaf as a TPM vendor issues one: the endorsement-key purpose and a
    /// key usage of keyEncipherment alone.
    pub ek_leaf_tbs: Vec<u8>,
    pub roots: RootStore,
}

/// The differential fixtures, built once per process.
pub fn diff_pki() -> &'static DiffPki {
    static D: OnceLock<DiffPki> = OnceLock::new();
    D.get_or_init(|| {
        let (root_key, int_key, leaf_key) = (key(3), key(4), key(5));
        let ca_bc = ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[0x01, 0x01, 0xff]));
        let ca_ku = ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0x01, 0x06]));
        let root = sign_tbs(
            &tbs(
                1,
                "Diff Root",
                "Diff Root",
                root_key.public_key(),
                &[ca_bc.clone(), ca_ku.clone()],
            ),
            &root_key,
        );
        let subtree = |t: u8, v: &[u8]| tlv(0x30, &tlv(t, v));
        let permitted = [
            subtree(0x82, b"fuzz.test"),
            subtree(0x81, b"fuzz.test"),
            subtree(0x86, b"fuzz.test"),
            subtree(0x87, &[10, 0, 0, 0, 255, 0, 0, 0]),
        ]
        .concat();
        let excluded = [
            subtree(0x82, b"bad.fuzz.test"),
            subtree(0xa4, &dn("Bad Subject")),
        ]
        .concat();
        let nc = ext(
            &[0x55, 0x1d, 0x1e],
            true,
            &tlv(
                0x30,
                &[tlv(0xa0, &permitted), tlv(0xa1, &excluded)].concat(),
            ),
        );
        // Policies: the intermediate holds 1.2.3.1 and 1.2.3.2, maps the
        // first to 1.2.3.3, requires an explicit policy of what it issues,
        // and inhibits further mapping and anyPolicy one certificate on.
        let policy = |n: u8| tlv(0x06, &[0x2a, 0x03, n]);
        let policies = |list: &[u8]| {
            let body: Vec<u8> = list.iter().flat_map(|n| tlv(0x30, &policy(*n))).collect();
            ext(&[0x55, 0x1d, 0x20], false, &tlv(0x30, &body))
        };
        let mappings = ext(
            &[0x55, 0x1d, 0x21],
            true,
            &tlv(0x30, &tlv(0x30, &[policy(1), policy(3)].concat())),
        );
        let constraints = ext(
            &[0x55, 0x1d, 0x24],
            true,
            &tlv(0x30, &[tlv(0x80, &[0]), tlv(0x81, &[1])].concat()),
        );
        let inhibit_any = ext(&[0x55, 0x1d, 0x36], true, &tlv(0x02, &[1]));
        let int_tbs = tbs(
            2,
            "Diff Root",
            "Diff Int",
            int_key.public_key(),
            &[
                ca_bc,
                ca_ku,
                nc,
                policies(&[1, 2]),
                mappings,
                constraints,
                inhibit_any,
            ],
        );
        let san = ext(
            &[0x55, 0x1d, 0x11],
            false,
            &tlv(
                0x30,
                &[
                    tlv(0x82, b"a.fuzz.test"),
                    tlv(0x81, b"a@fuzz.test"),
                    tlv(0x86, b"https://fuzz.test/a"),
                    tlv(0xa4, &dn("Fuzz Unit")),
                    tlv(0x87, &[10, 1, 2, 3]),
                ]
                .concat(),
            ),
        );
        let leaf_bc = ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[]));
        let leaf_ku = ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0x07, 0x80]));
        let eku = ext(
            &[0x55, 0x1d, 0x25],
            false,
            &tlv(
                0x30,
                &tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]),
            ),
        );
        let leaf_tbs = tbs(
            3,
            "Diff Int",
            "a.fuzz.test",
            leaf_key.public_key(),
            &[leaf_bc, leaf_ku, eku, san, policies(&[3])],
        );
        let ek_ku = ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0x05, 0x20]));
        let ek_eku = ext(
            &[0x55, 0x1d, 0x25],
            false,
            &tlv(0x30, &tlv(0x06, &[0x67, 0x81, 0x05, 0x08, 0x01])),
        );
        let ek_san = ext(
            &[0x55, 0x1d, 0x11],
            false,
            &tlv(0x30, &tlv(0x82, b"tpm.fuzz.test")),
        );
        let ek_leaf_tbs = tbs(
            4,
            "Diff Int",
            "tpm.fuzz.test",
            leaf_key.public_key(),
            &[
                ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[])),
                ek_ku,
                ek_eku,
                ek_san,
                policies(&[2]),
            ],
        );
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        DiffPki {
            root_key,
            int_key,
            int_tbs,
            leaf_tbs,
            ek_leaf_tbs,
            roots,
        }
    })
}

/// The pki_differential input for a fixture chain: selector, the
/// intermediate's TBS behind a two-byte length, then a leaf's TBS: the
/// TLS leaf, or the endorsement-key one.
pub fn diff_seed(sel: u8, endorsement_key: bool) -> Vec<u8> {
    let d = diff_pki();
    let mut out = vec![sel];
    out.extend((d.int_tbs.len() as u16).to_be_bytes());
    out.extend(&d.int_tbs);
    out.extend(if endorsement_key {
        &d.ek_leaf_tbs
    } else {
        &d.leaf_tbs
    });
    out
}
