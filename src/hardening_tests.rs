//! Certificate-handling regressions found by IronSocketLayer's 2026-10-06
//! security audit, carried here with the code they test.
//! Certificates are assembled from raw DER so that inputs the crate's own
//! builder refuses (a trailing-dot dNSName, thousands of extensions, a
//! non-CA "anchor" that signs) can still be presented to the validators.

use alloc::vec;
use alloc::vec::Vec;

use crate::sign::{self, KeyKind, SignatureScheme, SigningKey};
use crate::x509::{self, RootStore, VerifyOptions};
use crate::{ErrorKind, Limits, Purpose};

/// 2027-01-15, inside the 2020 to 2049 validity these certificates carry.
const NOW: u64 = 1_800_000_000;

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    sign::push_tlv(&mut out, tag, body);
    out
}

fn name(cn: &str) -> Vec<u8> {
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

fn basic_constraints(ca: bool) -> Vec<u8> {
    let body: &[u8] = if ca { &[0x01, 0x01, 0xff] } else { &[] };
    ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, body))
}

fn key_usage(ca: bool) -> Vec<u8> {
    let bits: &[u8] = if ca { &[0x01, 0x06] } else { &[0x07, 0x80] };
    ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, bits))
}

fn san(entries: &[(u8, &[u8])]) -> Vec<u8> {
    let body: Vec<u8> = entries.iter().flat_map(|(t, v)| tlv(*t, v)).collect();
    ext(&[0x55, 0x1d, 0x11], false, &tlv(0x30, &body))
}

fn name_constraints(excluded: &[(u8, &[u8])]) -> Vec<u8> {
    let list: Vec<u8> = excluded
        .iter()
        .flat_map(|(t, v)| tlv(0x30, &tlv(*t, v)))
        .collect();
    ext(&[0x55, 0x1d, 0x1e], true, &tlv(0x30, &tlv(0xa1, &list)))
}

fn cert(
    serial: u8,
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    exts: &[Vec<u8>],
    signer: &SigningKey,
) -> Vec<u8> {
    let alg = tlv(0x30, &tlv(0x06, ECDSA_SHA256));
    let validity = [tlv(0x17, b"200101000000Z"), tlv(0x17, b"491231235959Z")].concat();
    let tbs = tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[serial]),
            alg.clone(),
            issuer.to_vec(),
            tlv(0x30, &validity),
            subject.to_vec(),
            spki.to_vec(),
            tlv(0xa3, &tlv(0x30, &exts.concat())),
        ]
        .concat(),
    );
    let signature = signer
        .sign(SignatureScheme::EcdsaP256Sha256, &tbs, &mut rng())
        .unwrap();
    let mut bits = vec![0u8];
    bits.extend(signature);
    tlv(0x30, &[tbs, alg, tlv(0x03, &bits)].concat())
}

fn key() -> SigningKey {
    SigningKey::generate(KeyKind::EcdsaP256, &mut rng()).unwrap()
}

fn opts() -> VerifyOptions<'static> {
    VerifyOptions::new(
        NOW,
        Purpose::TlsServer,
        sign::VERIFY_SCHEMES,
        Limits::ONLINE,
    )
}

/// Both validators' verdicts on `leaf` issued by `int` under `roots`.
fn verdicts(
    leaf: &[u8],
    ints: &[&[u8]],
    roots: &RootStore,
) -> (Option<ErrorKind>, Option<ErrorKind>) {
    let o = opts();
    (
        x509::verify_chain(leaf, ints, roots, &o)
            .err()
            .map(|e| e.kind()),
        x509::verify_chain_fixed(leaf, ints, roots, &o)
            .err()
            .map(|e| e.kind()),
    )
}

/// REQ-X509-071: a dNSName with a trailing dot names the same host, so it
/// cannot escape an excluded subtree, as a name or as a wildcard, in either
/// validator.
#[test]
fn a_trailing_dot_does_not_escape_an_excluded_subtree() {
    let (root_key, int_key, leaf_key) = (key(), key(), key());
    let root = cert(
        1,
        &name("Root"),
        &name("Root"),
        root_key.spki(),
        &[basic_constraints(true), key_usage(true)],
        &root_key,
    );
    let int = cert(
        2,
        &name("Root"),
        &name("Int"),
        int_key.spki(),
        &[
            basic_constraints(true),
            key_usage(true),
            name_constraints(&[(0x82, b"evil.com")]),
        ],
        &root_key,
    );
    let mut roots = RootStore::new();
    roots.add_der(&root).unwrap();
    let refused = (
        Some(ErrorKind::CertificateUsage),
        Some(ErrorKind::CertificateUsage),
    );
    for dns in [
        &b"victim.evil.com."[..],
        b"evil.com.",
        b"*.evil.com.",
        b"VICTIM.Evil.COM.",
    ] {
        let leaf = cert(
            3,
            &name("Int"),
            &name("leaf"),
            leaf_key.spki(),
            &[
                basic_constraints(false),
                key_usage(false),
                san(&[(0x82, dns)]),
            ],
            &int_key,
        );
        assert_eq!(
            verdicts(&leaf, &[&int], &roots),
            refused,
            "{}",
            String::from_utf8_lossy(dns)
        );
    }
    // Control: a name outside the subtree is still accepted.
    let leaf = cert(
        3,
        &name("Int"),
        &name("leaf"),
        leaf_key.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[(0x82, b"good.example.")]),
        ],
        &int_key,
    );
    assert_eq!(verdicts(&leaf, &[&int], &roots), (None, None));
}

/// REQ-X509-074: a certificate trusted as an anchor that is not a CA (its
/// basicConstraints says so) is trusted as itself only; it cannot issue.
#[test]
fn a_non_ca_anchor_issues_nothing() {
    let (pinned_key, other_key) = (key(), key());
    let pinned = cert(
        9,
        &name("peer.example"),
        &name("peer.example"),
        pinned_key.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[(0x82, b"peer.example")]),
        ],
        &pinned_key,
    );
    let mut roots = RootStore::new();
    roots.add_der(&pinned).unwrap();
    // The anchored certificate itself is still accepted.
    assert_eq!(verdicts(&pinned, &[], &roots), (None, None));
    // A certificate it signed for another name is not.
    let forged = cert(
        10,
        &name("peer.example"),
        &name("bank"),
        other_key.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[(0x82, b"bank.example")]),
        ],
        &pinned_key,
    );
    let (owned, fixed) = verdicts(&forged, &[], &roots);
    assert!(owned.is_some() && owned == fixed, "{owned:?} / {fixed:?}");
}

/// REQ-OCSP-033: a leaf trusted directly as an anchor cannot attest its own
/// revocation status with a staple signed by its own key.
#[test]
fn a_self_anchored_leaf_cannot_staple_for_itself() {
    let k = key();
    let leaf = cert(
        9,
        &name("peer.example"),
        &name("peer.example"),
        k.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[(0x82, b"peer.example")]),
        ],
        &k,
    );
    let mut roots = RootStore::new();
    roots.add_der(&leaf).unwrap();
    let report = x509::verify_chain(&leaf, &[], &roots, &opts()).unwrap();
    assert_eq!(report.depth, 0);
    let now = NOW;
    let staple = x509::ocsp::build_response(
        &leaf,
        &leaf,
        &k,
        x509::ocsp::CertStatus::Good,
        now - 60,
        now + 3600,
        &mut rng(),
    )
    .unwrap();
    let e = x509::ocsp::verify_response(
        &staple,
        &leaf,
        &report.issuer_subject,
        &report.issuer_spki,
        now,
        sign::VERIFY_SCHEMES,
    )
    .unwrap_err();
    assert!(e.to_string().contains("cannot attest its own"), "{e}");
}

/// REQ-X509-073: the extension count is bounded before the duplicate check,
/// so a certificate of thousands of empty extensions is refused quickly
/// instead of costing quadratic time on every parse.
#[test]
fn a_certificate_with_thousands_of_extensions_is_refused_quickly() {
    let k = key();
    let mut all = vec![
        basic_constraints(false),
        key_usage(false),
        san(&[(0x82, b"x.example")]),
    ];
    for i in 0..14_000u32 {
        all.push(ext(
            &[0x2a, ((i >> 7) & 0x7f) as u8, (i & 0x7f) as u8],
            false,
            &[],
        ));
    }
    let c = cert(5, &name("i"), &name("l"), k.spki(), &all, &k);
    assert!(c.len() > 100_000);
    let start = std::time::Instant::now();
    let e = x509::Certificate::parse(&c).unwrap_err();
    let took = start.elapsed();
    assert_eq!(e.kind(), ErrorKind::BadCertificate, "{e}");
    assert!(e.to_string().contains("too many extensions"), "{e}");
    assert!(
        took < std::time::Duration::from_millis(100),
        "took {took:?}"
    );
}

/// `NameConstraints` with permitted and excluded subtrees of any forms.
fn constraints(permitted: &[(u8, &[u8])], excluded: &[(u8, &[u8])]) -> Vec<u8> {
    let list = |entries: &[(u8, &[u8])]| -> Vec<u8> {
        entries
            .iter()
            .flat_map(|(t, v)| tlv(0x30, &tlv(*t, v)))
            .collect()
    };
    let mut body = Vec::new();
    if !permitted.is_empty() {
        body.extend(tlv(0xa0, &list(permitted)));
    }
    if !excluded.is_empty() {
        body.extend(tlv(0xa1, &list(excluded)));
    }
    ext(&[0x55, 0x1d, 0x1e], true, &tlv(0x30, &body))
}

/// A subject of a common name and, after it, emailAddress attributes.
fn name_with_emails(cn: &str, emails: &[&[u8]]) -> Vec<u8> {
    let cn_atv = [tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat();
    let mut rdns = tlv(0x31, &tlv(0x30, &cn_atv));
    for email in emails {
        let atv = [
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01],
            ),
            tlv(0x16, email),
        ]
        .concat();
        rdns.extend(tlv(0x31, &tlv(0x30, &atv)));
    }
    tlv(0x30, &rdns)
}

/// A root, an intermediate carrying `nc`, and the verdict of both validators
/// on a leaf with `subject` and `san_entries` issued under it.
struct Constrained {
    int: Vec<u8>,
    int_key: SigningKey,
    leaf_key: SigningKey,
    roots: RootStore,
}

impl Constrained {
    fn new(nc: Vec<u8>) -> Self {
        let (root_key, int_key, leaf_key) = (key(), key(), key());
        let root = cert(
            1,
            &name("Root"),
            &name("Root"),
            root_key.spki(),
            &[basic_constraints(true), key_usage(true)],
            &root_key,
        );
        let int = cert(
            2,
            &name("Root"),
            &name("Int"),
            int_key.spki(),
            &[basic_constraints(true), key_usage(true), nc],
            &root_key,
        );
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        Self {
            int,
            int_key,
            leaf_key,
            roots,
        }
    }

    fn verdict(&self, subject: &[u8], san_entries: &[(u8, &[u8])]) -> Option<ErrorKind> {
        let mut exts = vec![basic_constraints(false), key_usage(false)];
        if !san_entries.is_empty() {
            exts.push(san(san_entries));
        }
        self.verdict_with(subject, &exts)
    }

    fn verdict_with(&self, subject: &[u8], exts: &[Vec<u8>]) -> Option<ErrorKind> {
        let leaf = cert(
            3,
            &name("Int"),
            subject,
            self.leaf_key.spki(),
            exts,
            &self.int_key,
        );
        let (owned, fixed) = verdicts(&leaf, &[&self.int], &self.roots);
        assert_eq!(owned, fixed, "the two validators disagree");
        owned
    }
}

const VIOLATION: Option<ErrorKind> = Some(ErrorKind::CertificateUsage);
const UNSUPPORTED: Option<ErrorKind> = Some(ErrorKind::UnsupportedCertificate);

/// REQ-X509-085: an rfc822Name constraint is evaluated, for rfc822Name
/// alternative names and for emailAddress attributes of the subject alike
/// (RFC 5280 §4.2.1.10): a host names every mailbox at that host, a leading
/// dot every mailbox at a host below the domain and not at the domain, and a
/// mailbox that mailbox alone, with the local part compared exactly. An
/// address or constraint there is no rule for refuses the path.
#[test]
fn rfc822_name_constraints_are_evaluated() {
    let leaf = name("leaf");

    // Permitted: one host.
    let host = Constrained::new(constraints(&[(0x81, b"example.com")], &[]));
    assert_eq!(host.verdict(&leaf, &[(0x81, b"a@example.com")]), None);
    assert_eq!(host.verdict(&leaf, &[(0x81, b"a@EXAMPLE.com")]), None);
    assert_eq!(
        host.verdict(&leaf, &[(0x81, b"a@mail.example.com")]),
        VIOLATION
    );
    assert_eq!(host.verdict(&leaf, &[(0x81, b"a@other.org")]), VIOLATION);
    // A certificate with no address is not what the constraint is about.
    assert_eq!(host.verdict(&leaf, &[(0x82, b"www.other.org")]), None);
    // The subject's emailAddress is an address too, wherever else one is.
    assert_eq!(
        host.verdict(&name_with_emails("leaf", &[b"a@example.com"]), &[]),
        None
    );
    assert_eq!(
        host.verdict(&name_with_emails("leaf", &[b"a@other.org"]), &[]),
        VIOLATION
    );
    assert_eq!(
        host.verdict(
            &name_with_emails("leaf", &[b"a@other.org"]),
            &[(0x81, b"a@example.com")]
        ),
        VIOLATION,
        "a good alternative name does not excuse a subject address"
    );
    // No rule for an address without a mailbox, so no verdict to give.
    assert_eq!(host.verdict(&leaf, &[(0x81, b"example.com")]), UNSUPPORTED);
    assert_eq!(host.verdict(&leaf, &[(0x81, b"@example.com")]), UNSUPPORTED);

    // Permitted: hosts below a domain, and not the domain.
    let below = Constrained::new(constraints(&[(0x81, b".example.com")], &[]));
    assert_eq!(below.verdict(&leaf, &[(0x81, b"a@mail.example.com")]), None);
    assert_eq!(below.verdict(&leaf, &[(0x81, b"a@example.com")]), VIOLATION);
    assert_eq!(
        below.verdict(&leaf, &[(0x81, b"a@notexample.com")]),
        VIOLATION
    );

    // Permitted: one mailbox. The local part is case-sensitive.
    let one = Constrained::new(constraints(&[(0x81, b"a@example.com")], &[]));
    assert_eq!(one.verdict(&leaf, &[(0x81, b"a@Example.COM")]), None);
    assert_eq!(one.verdict(&leaf, &[(0x81, b"A@example.com")]), VIOLATION);
    assert_eq!(one.verdict(&leaf, &[(0x81, b"b@example.com")]), VIOLATION);

    // Excluded.
    let excluded = Constrained::new(constraints(&[], &[(0x81, b"example.com")]));
    assert_eq!(excluded.verdict(&leaf, &[(0x81, b"a@other.org")]), None);
    assert_eq!(
        excluded.verdict(&leaf, &[(0x81, b"a@example.com")]),
        VIOLATION
    );
    assert_eq!(
        excluded.verdict(&name_with_emails("leaf", &[b"a@example.com"]), &[]),
        VIOLATION
    );
    assert_eq!(
        excluded.verdict(&leaf, &[(0x81, b"not-an-address")]),
        UNSUPPORTED,
        "it cannot be shown to be outside the excluded subtree"
    );

    // A constraint base there is no rule for refuses every path under it.
    for nc in [
        constraints(&[(0x81, b"@example.com")], &[]),
        constraints(&[(0x81, b"a@")], &[]),
        constraints(&[], &[(0x81, b"exa mple.com")]),
    ] {
        let c = Constrained::new(nc);
        assert_eq!(c.verdict(&leaf, &[(0x82, b"www.example.com")]), UNSUPPORTED);
    }
}

/// REQ-X509-008: a wildcard dNSName is held to DNS constraints for every
/// name it can match, not as a literal string. It is refused under an
/// excluded subtree it could reach into, and under a permitted subtree it
/// could reach out of.
#[test]
fn a_wildcard_is_constrained_for_every_name_it_matches() {
    let leaf = name("leaf");
    let excluded = Constrained::new(constraints(&[], &[(0x82, b"sub.example.test")]));
    assert_eq!(
        excluded.verdict(&leaf, &[(0x82, b"*.example.test")]),
        VIOLATION,
        "the wildcard matches the excluded sub.example.test"
    );
    assert_eq!(
        excluded.verdict(&leaf, &[(0x82, b"*.sub.example.test")]),
        VIOLATION
    );
    assert_eq!(excluded.verdict(&leaf, &[(0x82, b"*.other.test")]), None);
    assert_eq!(
        excluded.verdict(&leaf, &[(0x82, b"www.example.test")]),
        None
    );

    let permitted = Constrained::new(constraints(&[(0x82, b"example.test")], &[]));
    assert_eq!(permitted.verdict(&leaf, &[(0x82, b"*.example.test")]), None);
    assert_eq!(
        permitted.verdict(&leaf, &[(0x82, b"*.other.test")]),
        VIOLATION
    );
    let narrow = Constrained::new(constraints(&[(0x82, b"sub.example.test")], &[]));
    assert_eq!(
        narrow.verdict(&leaf, &[(0x82, b"*.example.test")]),
        VIOLATION,
        "the wildcard matches names outside the permitted subtree"
    );
    assert_eq!(
        narrow.verdict(&leaf, &[(0x82, b"*.sub.example.test")]),
        None
    );
}

/// REQ-X509-005, and the verification IronCrypto does for it: 22 certificate
/// signatures made by PyCA `cryptography` (see `tests/vectors/README.md`).
/// A curve signs with its own hash and no other, RSA-PSS only with MGF1 over
/// the same hash and a salt as long as it, and the recorded verdicts hold,
/// with one difference: IronPrivacyGuard did not verify P-521 and this crate
/// does.
#[test]
fn pyca_certificate_signatures_are_judged_as_recorded() {
    let vectors = ic_json::parse(include_str!("../tests/vectors/x509-signatures.json")).unwrap();
    let cases = vectors.get("cases").unwrap().as_array().unwrap();
    assert_eq!(cases.len(), 22);
    let opts = opts();
    let mut accepted = 0;
    for case in cases {
        let name = case.get("name").unwrap().as_str().unwrap();
        let hex = |key: &str| -> Vec<u8> {
            let s = case.get(key).unwrap().as_str().unwrap();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let (certificate, issuer_spki) = (hex("certificate"), hex("issuer_spki"));
        let recorded = case.get("accepted").unwrap().as_bool().unwrap();
        let expected = recorded || name == "unsupported_p521";
        let verdict = x509::Certificate::parse(&certificate)
            .and_then(|c| x509::check_signature(&c, &issuer_spki, &opts));
        assert_eq!(verdict.is_ok(), expected, "{name}: {:?}", verdict.err());
        accepted += usize::from(expected);
    }
    assert_eq!(accepted, 16, "15 recorded as accepted, and P-521");
}

const AT_CN: &[u8] = &[0x55, 0x04, 0x03];
const AT_C: &[u8] = &[0x55, 0x04, 0x06];
const AT_O: &[u8] = &[0x55, 0x04, 0x0a];
const AT_DC: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];
const UTF8: u8 = 0x0c;
const PRINTABLE: u8 = 0x13;
const T61: u8 = 0x14;
const IA5: u8 = 0x16;

/// An attribute: type, string tag, value.
type Attribute<'a> = (&'a [u8], u8, &'a [u8]);

/// A Name: each inner slice is one relative distinguished name's attributes,
/// given in DER order.
fn dn(rdns: &[&[Attribute<'_>]]) -> Vec<u8> {
    let body: Vec<u8> = rdns
        .iter()
        .flat_map(|rdn| {
            let set: Vec<u8> = rdn
                .iter()
                .flat_map(|(oid, tag, value)| {
                    tlv(0x30, &[tlv(0x06, oid), tlv(*tag, value)].concat())
                })
                .collect();
            tlv(0x31, &set)
        })
        .collect();
    tlv(0x30, &body)
}

/// REQ-X509-086: a directoryName constraint is evaluated, for the subject
/// and for directoryName alternative names alike (RFC 5280 §4.2.1.10): a
/// name is within a subtree whose relative distinguished names are the
/// first of its own, in order, printable ASCII compared without regard to
/// case or spacing. What cannot be compared here is never taken for a
/// match under a permitted subtree, and refuses the path under an excluded
/// one.
#[test]
fn directory_name_constraints_are_evaluated() {
    let base = dn(&[
        &[(AT_C, PRINTABLE, b"US")],
        &[(AT_O, UTF8, b"Example Corp")],
    ]);
    let permitted = Constrained::new(constraints(&[(0xa4, &base)], &[]));
    let under = |o_tag: u8, o: &[u8]| {
        dn(&[
            &[(AT_C, PRINTABLE, b"US")],
            &[(AT_O, o_tag, o)],
            &[(AT_CN, UTF8, b"leaf")],
        ])
    };
    let good = under(UTF8, b"Example Corp");
    assert_eq!(permitted.verdict(&good, &[]), None);
    assert_eq!(
        permitted.verdict(&under(PRINTABLE, b" example   CORP "), &[]),
        None,
        "another string type, case and spacing"
    );
    assert_eq!(permitted.verdict(&base, &[]), None, "the base itself");
    assert_eq!(
        permitted.verdict(&under(UTF8, b"Example Corporation"), &[]),
        VIOLATION
    );
    assert_eq!(
        permitted.verdict(&under(UTF8, b"ExampleCorp"), &[]),
        VIOLATION
    );
    // Shorter than the base, the base's names in another order, a name
    // that has them but does not begin with them, another attribute type.
    for outside in [
        dn(&[&[(AT_C, PRINTABLE, b"US")]]),
        dn(&[
            &[(AT_O, UTF8, b"Example Corp")],
            &[(AT_C, PRINTABLE, b"US")],
        ]),
        dn(&[
            &[(AT_CN, UTF8, b"leaf")],
            &[(AT_C, PRINTABLE, b"US")],
            &[(AT_O, UTF8, b"Example Corp")],
        ]),
        dn(&[
            &[(AT_C, PRINTABLE, b"US")],
            &[(AT_CN, UTF8, b"Example Corp")],
        ]),
        name("leaf"),
    ] {
        assert_eq!(permitted.verdict(&outside, &[]), VIOLATION, "{outside:?}");
    }
    // A directoryName alternative name is held to it as the subject is.
    assert_eq!(permitted.verdict(&good, &[(0xa4, &good)]), None);
    assert_eq!(
        permitted.verdict(&good, &[(0xa4, &name("elsewhere"))]),
        VIOLATION
    );
    // Names of other forms are not a directory name's business, and a
    // subject that is empty is not a name to hold to it.
    assert_eq!(permitted.verdict(&good, &[(0x82, b"www.other.org")]), None);
    let critical_san = ext(
        &[0x55, 0x1d, 0x11],
        true,
        &tlv(0x30, &tlv(0x82, b"www.other.org")),
    );
    let nameless = [basic_constraints(false), key_usage(false), critical_san];
    assert_eq!(permitted.verdict_with(&tlv(0x30, &[]), &nameless), None);

    // Excluded.
    let evil = dn(&[&[(AT_O, UTF8, b"Evil")]]);
    let excluded = Constrained::new(constraints(&[], &[(0xa4, &evil)]));
    let org = |tag: u8, o: &[u8]| dn(&[&[(AT_O, tag, o)], &[(AT_CN, UTF8, b"leaf")]]);
    assert_eq!(excluded.verdict(&org(UTF8, b"Good"), &[]), None);
    assert_eq!(excluded.verdict(&name("leaf"), &[]), None);
    assert_eq!(excluded.verdict(&org(UTF8, b"Evil"), &[]), VIOLATION);
    assert_eq!(excluded.verdict(&org(PRINTABLE, b"EVIL "), &[]), VIOLATION);
    assert_eq!(
        excluded.verdict(&org(UTF8, b"Good"), &[(0xa4, &evil)]),
        VIOLATION
    );
    assert_eq!(
        excluded.verdict(&org(T61, b"Evil"), &[]),
        UNSUPPORTED,
        "a string type with no rule cannot be shown to differ"
    );

    // Text outside ASCII is the same only when its encoding is.
    let zurich = |o: &str| dn(&[&[(AT_O, UTF8, o.as_bytes())], &[(AT_CN, UTF8, b"leaf")]]);
    let base = dn(&[&[(AT_O, UTF8, "Zürich".as_bytes())]]);
    let permitted = Constrained::new(constraints(&[(0xa4, &base)], &[]));
    assert_eq!(permitted.verdict(&zurich("Zürich"), &[]), None);
    assert_eq!(permitted.verdict(&zurich("ZÜRICH"), &[]), VIOLATION);
    let excluded = Constrained::new(constraints(&[], &[(0xa4, &base)]));
    assert_eq!(excluded.verdict(&zurich("Zürich"), &[]), VIOLATION);
    assert_eq!(excluded.verdict(&zurich("ZÜRICH"), &[]), UNSUPPORTED);
    assert_eq!(excluded.verdict(&name("leaf"), &[]), None, "another type");

    // An IA5String that differs only in case is not decided either way.
    let dc = |v: &[u8]| dn(&[&[(AT_DC, IA5, v)], &[(AT_CN, UTF8, b"leaf")]]);
    let base = dn(&[&[(AT_DC, IA5, b"example")]]);
    let permitted = Constrained::new(constraints(&[(0xa4, &base)], &[]));
    assert_eq!(permitted.verdict(&dc(b"example"), &[]), None);
    assert_eq!(permitted.verdict(&dc(b"EXAMPLE"), &[]), VIOLATION);
    let excluded = Constrained::new(constraints(&[], &[(0xa4, &base)]));
    assert_eq!(excluded.verdict(&dc(b"example"), &[]), VIOLATION);
    assert_eq!(excluded.verdict(&dc(b"EXAMPLE"), &[]), UNSUPPORTED);
    assert_eq!(excluded.verdict(&dc(b"other"), &[]), None);

    // Several attributes in one relative distinguished name are the same
    // only when their encoding is; a different number of them never is.
    let pair = |o_tag: u8, o: &[u8]| dn(&[&[(AT_CN, UTF8, b"a"), (AT_O, o_tag, o)]]);
    let permitted = Constrained::new(constraints(&[(0xa4, &pair(UTF8, b"b"))], &[]));
    assert_eq!(permitted.verdict(&pair(UTF8, b"b"), &[]), None);
    assert_eq!(permitted.verdict(&pair(PRINTABLE, b"B"), &[]), VIOLATION);
    let excluded = Constrained::new(constraints(&[], &[(0xa4, &pair(UTF8, b"b"))]));
    assert_eq!(excluded.verdict(&pair(UTF8, b"b"), &[]), VIOLATION);
    assert_eq!(excluded.verdict(&pair(PRINTABLE, b"B"), &[]), UNSUPPORTED);
    assert_eq!(excluded.verdict(&name("a"), &[]), None);

    // An empty base is the root of every name.
    let all = tlv(0x30, &[]);
    let permitted = Constrained::new(constraints(&[(0xa4, &all)], &[]));
    assert_eq!(permitted.verdict(&name("leaf"), &[]), None);
    let excluded = Constrained::new(constraints(&[], &[(0xa4, &all)]));
    assert_eq!(excluded.verdict(&name("leaf"), &[]), VIOLATION);
}

/// REQ-X509-086: a directoryName constraint binds the subject of a CA
/// below the constraining one as it binds the leaf's, in both validators.
#[test]
fn a_directory_name_constraint_binds_the_cas_below_it() {
    let corp = dn(&[&[(AT_O, UTF8, b"Corp")]]);
    let within = |cn: &[u8]| dn(&[&[(AT_O, UTF8, b"Corp")], &[(AT_CN, UTF8, cn)]]);
    for (sub_subject, expected) in [(within(b"Sub"), None), (name("Sub"), VIOLATION)] {
        let c = Constrained::new(constraints(&[(0xa4, &corp)], &[]));
        let sub_key = key();
        let sub = cert(
            4,
            &name("Int"),
            &sub_subject,
            sub_key.spki(),
            &[basic_constraints(true), key_usage(true)],
            &c.int_key,
        );
        let leaf = cert(
            5,
            &sub_subject,
            &within(b"leaf"),
            c.leaf_key.spki(),
            &[basic_constraints(false), key_usage(false)],
            &sub_key,
        );
        let (owned, fixed) = verdicts(&leaf, &[&sub, &c.int], &c.roots);
        assert_eq!(owned, fixed, "the two validators disagree");
        assert_eq!(owned, expected);
    }
}

/// REQ-X509-087: a uniformResourceIdentifier constraint is evaluated
/// against the host of each URI alternative name (RFC 5280 §4.2.1.10): a
/// host names that host alone, and a domain with a leading dot every host
/// below it and not the domain. A URI with no host that is a DNS name, or a
/// constraint that is neither, refuses the path.
#[test]
fn uri_name_constraints_are_evaluated() {
    let leaf = name("leaf");
    let host = Constrained::new(constraints(&[(0x86, b"example.com")], &[]));
    for inside in [
        &b"https://example.com/path"[..],
        b"https://example.com",
        b"https://EXAMPLE.com:8443/x?y#z",
        b"spiffe://example.com/workload",
        b"https://user:secret@example.com/",
        b"https://example.com?q=https://other.org/",
    ] {
        assert_eq!(host.verdict(&leaf, &[(0x86, inside)]), None);
    }
    for outside in [
        &b"https://www.example.com/"[..],
        b"https://other.org/",
        b"https://notexample.com/",
        b"https://example.com.other.org/",
        // What looks like the host is the user, the path, the query or the
        // fragment.
        b"https://example.com@other.org/",
        b"https://example.com:443@other.org/",
        b"https://other.org/@example.com",
        b"https://other.org?@example.com",
        b"https://other.org#@example.com",
        b"https://other.org/https://example.com/",
    ] {
        assert_eq!(
            host.verdict(&leaf, &[(0x86, outside)]),
            VIOLATION,
            "{}",
            core::str::from_utf8(outside).unwrap()
        );
    }
    // No host name to hold to the constraint: rejected, as RFC 5280 has it.
    for none in [
        &b"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"[..],
        b"mailto:a@example.com",
        b"https://192.0.2.1/",
        b"https://[2001:db8::1]/",
        b"https://[2001:db8::1]:443/",
        b"https:///path",
        b"https://example.com:port/",
        b"//example.com/",
        b"1https://example.com/",
        b"example.com",
        b"https://exa%6dple.com/",
    ] {
        assert_eq!(
            host.verdict(&leaf, &[(0x86, none)]),
            UNSUPPORTED,
            "{}",
            core::str::from_utf8(none).unwrap()
        );
    }
    // One bad URI among good ones is enough, and other forms are not held
    // to a URI constraint.
    assert_eq!(
        host.verdict(
            &leaf,
            &[
                (0x86, b"https://example.com/"),
                (0x86, b"https://other.org/")
            ]
        ),
        VIOLATION
    );
    assert_eq!(host.verdict(&leaf, &[(0x82, b"www.other.org")]), None);

    // Permitted: hosts below a domain, and not the domain.
    let below = Constrained::new(constraints(&[(0x86, b".example.com")], &[]));
    assert_eq!(
        below.verdict(&leaf, &[(0x86, b"https://a.example.com/")]),
        None
    );
    assert_eq!(
        below.verdict(&leaf, &[(0x86, b"https://a.b.Example.com/")]),
        None
    );
    assert_eq!(
        below.verdict(&leaf, &[(0x86, b"https://example.com/")]),
        VIOLATION
    );
    assert_eq!(
        below.verdict(&leaf, &[(0x86, b"https://notexample.com/")]),
        VIOLATION
    );

    // Excluded.
    let excluded = Constrained::new(constraints(&[], &[(0x86, b"example.com")]));
    assert_eq!(
        excluded.verdict(&leaf, &[(0x86, b"https://other.org/")]),
        None
    );
    assert_eq!(
        excluded.verdict(&leaf, &[(0x86, b"https://www.example.com/")]),
        None,
        "a host names that host alone"
    );
    assert_eq!(
        excluded.verdict(&leaf, &[(0x86, b"https://Example.com/")]),
        VIOLATION
    );
    assert_eq!(
        excluded.verdict(&leaf, &[(0x86, b"urn:example:thing")]),
        UNSUPPORTED,
        "it cannot be shown to be outside the excluded subtree"
    );

    // A constraint that is not a host or a domain refuses every path.
    for nc in [
        constraints(&[(0x86, b"https://example.com")], &[]),
        constraints(&[], &[(0x86, b"exa mple.com")]),
        constraints(&[(0x86, b".")], &[]),
    ] {
        let c = Constrained::new(nc);
        assert_eq!(c.verdict(&leaf, &[(0x82, b"www.example.com")]), UNSUPPORTED);
    }
}

/// REQ-CFG-009: under the CNSA profiles every certificate presented carries
/// a key of the suite, whether a path uses it or not (RFC 8603 section 4.1;
/// draft-jenkins-cnsa2-pkix-profile-05 section 4). An ML-KEM-1024 key is a
/// key of the 2.0 suite although nothing here reads it; a certificate that
/// does not parse is passed over, as path validation passes over it.
#[test]
fn cnsa_profiles_hold_every_presented_key_to_the_suite() {
    let signer = key();
    let with_spki = |spki: &[u8]| {
        cert(
            7,
            &name("Issuer"),
            &name("Subject"),
            spki,
            &[basic_constraints(false), key_usage(false)],
            &signer,
        )
    };
    let of = |kind| with_spki(SigningKey::generate(kind, &mut rng()).unwrap().spki());
    let other_spki = |oid: &[u8], len: usize| {
        let mut bits = vec![0u8; len + 1];
        bits[1..].fill(0x5a);
        tlv(
            0x30,
            &[tlv(0x30, &tlv(0x06, oid)), tlv(0x03, &bits)].concat(),
        )
    };
    let ml_kem = |n: u8, len| with_spki(&other_spki(&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 4, n], len));
    let ml_kem_1024 = ml_kem(3, 1568);
    let ml_kem_768 = ml_kem(2, 1184);
    let unparseable = vec![0x30, 0x03, 0x02, 0x01];
    let verdict = |r: crate::Result<()>| r.err().map(|e| (e.kind(), e.context()));
    let no1 = Some((
        ErrorKind::PolicyViolation,
        "CNSA 1.0 allows P-384 and RSA keys only",
    ));
    let no2 = Some((
        ErrorKind::PolicyViolation,
        "CNSA 2.0 allows ML-DSA-87 and ML-KEM-1024 keys only",
    ));
    for (kind, in1, in2) in [
        (KeyKind::EcdsaP256, false, false),
        (KeyKind::EcdsaP384, true, false),
        (KeyKind::EcdsaP521, false, false),
        (KeyKind::Ed25519, false, false),
        (KeyKind::MlDsa44, false, false),
        (KeyKind::MlDsa65, false, false),
        (KeyKind::MlDsa87, false, true),
    ] {
        let c = of(kind);
        let one = [c.as_slice()];
        assert_eq!(
            verdict(x509::check_cnsa1_keys(one.iter().copied())),
            if in1 { None } else { no1 },
            "{kind:?}"
        );
        assert_eq!(
            verdict(x509::check_cnsa2_keys(one.iter().copied())),
            if in2 { None } else { no2 },
            "{kind:?}"
        );
    }
    let check1 = |certs: &[&[u8]]| verdict(x509::check_cnsa1_keys(certs.iter().copied()));
    let check2 = |certs: &[&[u8]]| verdict(x509::check_cnsa2_keys(certs.iter().copied()));
    assert_eq!(check2(&[&ml_kem_1024]), None);
    assert_eq!(check2(&[&ml_kem_768]), no2);
    assert_eq!(check1(&[&ml_kem_1024]), no1);
    // One key outside the suite among several is enough, wherever it is;
    // what is not a certificate is not a key outside the suite.
    let (p384, p256, ml87) = (
        of(KeyKind::EcdsaP384),
        of(KeyKind::EcdsaP256),
        of(KeyKind::MlDsa87),
    );
    assert_eq!(check1(&[&p384, &unparseable, &p384]), None);
    assert_eq!(check1(&[&p384, &p384, &p256]), no1);
    assert_eq!(check1(&[&p256, &p384]), no1);
    assert_eq!(check1(&[]), None);
    assert_eq!(check2(&[&ml87, &unparseable, &ml_kem_1024]), None);
    assert_eq!(check2(&[&ml87, &p384]), no2);
    // An RSA key is still held to its own rule under CNSA 1.0.
    let rsa = |bits: usize| {
        let mut modulus = vec![0xffu8; bits / 8];
        modulus[bits / 8 - 1] = 0xfb;
        let key = [
            tlv(0x02, &[&[0u8][..], &modulus].concat()),
            tlv(0x02, &[1, 0, 1]),
        ]
        .concat();
        let mut bits = vec![0u8];
        bits.extend(tlv(0x30, &key));
        let alg = [
            tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]),
            tlv(0x05, &[]),
        ]
        .concat();
        with_spki(&tlv(0x30, &[tlv(0x30, &alg), tlv(0x03, &bits)].concat()))
    };
    assert_eq!(check1(&[&rsa(3072)]), None);
    assert_eq!(
        check1(&[&rsa(2048)]),
        Some((
            ErrorKind::PolicyViolation,
            "CNSA 1.0 allows RSA moduli of 3072 or 4096 bits only"
        ))
    );
    assert_eq!(check2(&[&rsa(3072)]), no2);
}

const ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x20, 0x00];
const POLICY_1: &[u8] = &[0x2a, 0x03, 0x01];
const POLICY_2: &[u8] = &[0x2a, 0x03, 0x02];
const POLICY_3: &[u8] = &[0x2a, 0x03, 0x03];

/// `certificatePolicies` naming `policies`.
fn certificate_policies(policies: &[&[u8]]) -> Vec<u8> {
    let list: Vec<u8> = policies
        .iter()
        .flat_map(|p| tlv(0x30, &tlv(0x06, p)))
        .collect();
    ext(&[0x55, 0x1d, 0x20], false, &tlv(0x30, &list))
}

/// `policyMappings` of issuer-domain and subject-domain pairs.
fn policy_mappings(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    let list: Vec<u8> = pairs
        .iter()
        .flat_map(|(issuer, subject)| tlv(0x30, &[tlv(0x06, issuer), tlv(0x06, subject)].concat()))
        .collect();
    ext(&[0x55, 0x1d, 0x21], true, &tlv(0x30, &list))
}

/// `policyConstraints` with either count.
fn policy_constraints(require_explicit: Option<u8>, inhibit_mapping: Option<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(n) = require_explicit {
        body.extend(tlv(0x80, &[n]));
    }
    if let Some(n) = inhibit_mapping {
        body.extend(tlv(0x81, &[n]));
    }
    ext(&[0x55, 0x1d, 0x24], true, &tlv(0x30, &body))
}

fn inhibit_any_policy(count: u8) -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x36], true, &tlv(0x02, &[count]))
}

/// Both validators' verdict on a path whose certificates carry `levels` of
/// extra extensions: the first is the certificate the root issued, the last
/// the leaf. The root carries `root_extra`.
fn policy_path(root_extra: &[Vec<u8>], levels: &[&[Vec<u8>]]) -> Option<ErrorKind> {
    policy_outcome(root_extra, levels, &x509::PolicyOptions::any()).err()
}

/// The same, for a caller's policy inputs: what both validators report of
/// policies, or the kind of error both give.
fn policy_outcome(
    root_extra: &[Vec<u8>],
    levels: &[&[Vec<u8>]],
    options: &x509::PolicyOptions<'_>,
) -> Result<x509::PolicyOutcome, ErrorKind> {
    let mut signer = key();
    let mut exts = vec![basic_constraints(true), key_usage(true)];
    exts.extend_from_slice(root_extra);
    let root = cert(1, &name("L0"), &name("L0"), signer.spki(), &exts, &signer);
    let mut roots = RootStore::new();
    roots.add_der(&root).unwrap();
    let mut certs = Vec::new();
    for (i, extra) in levels.iter().enumerate() {
        let ca = i + 1 < levels.len();
        let subject_key = key();
        let mut exts = vec![basic_constraints(ca), key_usage(ca)];
        exts.extend_from_slice(extra);
        certs.push(cert(
            2 + i as u8,
            &name(&format!("L{i}")),
            &name(&format!("L{}", i + 1)),
            subject_key.spki(),
            &exts,
            &signer,
        ));
        signer = subject_key;
    }
    let leaf = certs.pop().unwrap();
    let ints: Vec<&[u8]> = certs.iter().map(Vec::as_slice).collect();
    let mut o = opts();
    o.policy = *options;
    let owned = x509::verify_chain(&leaf, &ints, &roots, &o)
        .map(|r| r.policy)
        .map_err(|e| e.kind());
    let fixed = x509::verify_chain_fixed(&leaf, &ints, &roots, &o)
        .map(|r| r.policy)
        .map_err(|e| e.kind());
    assert_eq!(owned, fixed, "the two validators disagree");
    owned
}

/// REQ-X509-090: both validators take the caller's policy inputs and
/// report what held: whether a policy was required, and which of the
/// caller's policies are valid for the path, compared in the trust anchor's
/// domain. Unusable inputs are refused before anything is parsed, and a
/// pinned leaf, which has no path, has no policies processed.
#[test]
fn the_callers_policy_inputs_reach_both_validators() {
    use x509::PolicyOptions;
    let p = |policies: &[&[u8]]| certificate_policies(policies);
    let valid = |r: Result<x509::PolicyOutcome, ErrorKind>| r.map(|o| (o.required, o.valid));
    let plain: [&[Vec<u8>]; 2] = [&[p(&[POLICY_1])], &[p(&[POLICY_1])]];
    // The defaults: nothing required, nothing reported.
    assert_eq!(
        valid(policy_outcome(&[], &plain, &PolicyOptions::any())),
        Ok((false, 0))
    );
    assert_eq!(
        valid(policy_outcome(
            &[],
            &plain,
            &PolicyOptions::require(&[POLICY_1])
        )),
        Ok((true, 0b1))
    );
    assert_eq!(
        valid(policy_outcome(
            &[],
            &plain,
            &PolicyOptions::require(&[POLICY_2, POLICY_1])
        )),
        Ok((true, 0b10))
    );
    assert_eq!(
        policy_outcome(&[], &plain, &PolicyOptions::require(&[POLICY_2])),
        Err(ErrorKind::CertificateUsage)
    );
    // Named without being required.
    let mut named = PolicyOptions::any();
    named.acceptable = &[POLICY_2, POLICY_1];
    assert_eq!(
        valid(policy_outcome(&[], &plain, &named)),
        Ok((false, 0b10))
    );
    // Required of a path with no policies at all.
    assert_eq!(
        policy_outcome(&[], &[&[], &[]], &PolicyOptions::require(&[])),
        Err(ErrorKind::CertificateUsage)
    );
    // Under a mapping, the caller's policy is the one the anchor's domain
    // knows, not the one the leaf lists.
    let mapped: [&[Vec<u8>]; 2] = [
        &[p(&[POLICY_1]), policy_mappings(&[(POLICY_1, POLICY_2)])],
        &[p(&[POLICY_2])],
    ];
    assert_eq!(
        valid(policy_outcome(
            &[],
            &mapped,
            &PolicyOptions::require(&[POLICY_1])
        )),
        Ok((true, 0b1))
    );
    assert_eq!(
        policy_outcome(&[], &mapped, &PolicyOptions::require(&[POLICY_2])),
        Err(ErrorKind::CertificateUsage)
    );
    let mut no_mapping = PolicyOptions::require(&[POLICY_1]);
    no_mapping.inhibit_mapping = true;
    assert_eq!(
        policy_outcome(&[], &mapped, &no_mapping),
        Err(ErrorKind::CertificateUsage)
    );
    let any_top: [&[Vec<u8>]; 2] = [&[p(&[ANY_POLICY])], &[p(&[POLICY_1])]];
    let mut no_any = PolicyOptions::require(&[POLICY_1]);
    assert_eq!(
        valid(policy_outcome(&[], &any_top, &no_any)),
        Ok((true, 0b1))
    );
    no_any.inhibit_any = true;
    assert_eq!(
        policy_outcome(&[], &any_top, &no_any),
        Err(ErrorKind::CertificateUsage)
    );

    // Unusable inputs.
    let many = [POLICY_1; x509::MAX_ACCEPTABLE + 1];
    assert_eq!(
        policy_outcome(&[], &plain, &PolicyOptions::require(&many)),
        Err(ErrorKind::InvalidConfig)
    );
    assert_eq!(
        policy_outcome(&[], &plain, &PolicyOptions::require(&[&[0x80, 0x01]])),
        Err(ErrorKind::InvalidConfig)
    );

    // A pinned leaf has no path: nothing is processed, whatever is asked.
    let signer = key();
    let leaf = cert(
        1,
        &name("Pinned"),
        &name("Pinned"),
        signer.spki(),
        &[basic_constraints(false), key_usage(false)],
        &signer,
    );
    let mut roots = RootStore::new();
    roots.add_der(&leaf).unwrap();
    let mut o = opts();
    o.policy = PolicyOptions::require(&[POLICY_1]);
    let owned = x509::verify_chain(&leaf, &[], &roots, &o).unwrap();
    let fixed = x509::verify_chain_fixed(&leaf, &[], &roots, &o).unwrap();
    assert_eq!(owned.depth, 0);
    assert_eq!(owned.policy, x509::PolicyOutcome::default());
    assert_eq!(fixed.policy, x509::PolicyOutcome::default());
}

/// REQ-X509-088: both validators process certificate policies. A path is
/// refused when a certificate on it requires an explicit policy and none is
/// valid down to the leaf, with mappings, inhibited mapping and inhibited
/// anyPolicy applied; the three extensions are no longer refused as
/// unknown when critical; and the trust anchor's own are not processed.
#[test]
fn certificate_policies_are_processed_on_a_path() {
    let p = |policies: &[&[u8]]| certificate_policies(policies);
    let require = policy_constraints(Some(0), None);
    // Nothing requires a policy: every arrangement passes, critical or not.
    assert_eq!(
        policy_path(&[], &[&[p(&[POLICY_1])], &[p(&[POLICY_2])]]),
        None
    );
    assert_eq!(
        policy_path(
            &[],
            &[
                &[
                    p(&[POLICY_1]),
                    policy_mappings(&[(POLICY_1, POLICY_2)]),
                    policy_constraints(None, Some(0)),
                    inhibit_any_policy(0)
                ],
                &[]
            ]
        ),
        None
    );
    // The CA requires an explicit policy of what it issues.
    let ca = [p(&[POLICY_1]), require.clone()];
    assert_eq!(policy_path(&[], &[&ca, &[p(&[POLICY_1])]]), None);
    assert_eq!(policy_path(&[], &[&ca, &[p(&[POLICY_2])]]), VIOLATION);
    assert_eq!(policy_path(&[], &[&ca, &[]]), VIOLATION);
    assert_eq!(policy_path(&[], &[&ca, &[p(&[ANY_POLICY])]]), None);
    assert_eq!(
        policy_path(&[], &[&ca, &[p(&[POLICY_2, POLICY_1])]]),
        None,
        "one valid policy among several is enough"
    );
    // Deferred by two certificates, a two-certificate path is not held to it.
    let later = [p(&[POLICY_1]), policy_constraints(Some(2), None)];
    assert_eq!(policy_path(&[], &[&later, &[p(&[POLICY_2])]]), None);
    assert_eq!(
        policy_path(&[], &[&later, &[p(&[POLICY_2])], &[p(&[POLICY_2])]]),
        VIOLATION
    );
    // A leaf that requires a policy of itself.
    assert_eq!(
        policy_path(&[], &[&[p(&[POLICY_1])], core::slice::from_ref(&require)]),
        VIOLATION
    );
    assert_eq!(
        policy_path(
            &[],
            &[&[p(&[POLICY_1])], &[p(&[POLICY_1]), require.clone()]]
        ),
        None
    );

    // Three certificates: the policy must hold at each.
    let mid = |extra: &[Vec<u8>]| -> Vec<Vec<u8>> { extra.to_vec() };
    assert_eq!(
        policy_path(&[], &[&ca, &mid(&[p(&[POLICY_2])]), &[p(&[POLICY_1])]]),
        VIOLATION
    );
    // Mapped below the middle certificate: 1 is 2 from there on.
    let bridge = mid(&[p(&[POLICY_1]), policy_mappings(&[(POLICY_1, POLICY_2)])]);
    assert_eq!(policy_path(&[], &[&ca, &bridge, &[p(&[POLICY_2])]]), None);
    assert_eq!(
        policy_path(&[], &[&ca, &bridge, &[p(&[POLICY_1])]]),
        VIOLATION
    );
    assert_eq!(
        policy_path(&[], &[&ca, &bridge, &[p(&[POLICY_3])]]),
        VIOLATION
    );
    // Mapping inhibited from the top: the mapped policy is lost.
    let no_mapping = [p(&[POLICY_1]), policy_constraints(Some(0), Some(0))];
    assert_eq!(
        policy_path(&[], &[&no_mapping, &bridge, &[p(&[POLICY_2])]]),
        VIOLATION
    );
    assert_eq!(
        policy_path(&[], &[&no_mapping, &bridge, &[p(&[POLICY_1])]]),
        VIOLATION
    );
    // anyPolicy inhibited from the top.
    let no_any = [p(&[POLICY_1]), require.clone(), inhibit_any_policy(0)];
    assert_eq!(policy_path(&[], &[&no_any, &[p(&[ANY_POLICY])]]), VIOLATION);
    assert_eq!(policy_path(&[], &[&no_any, &[p(&[POLICY_1])]]), None);
    let any_later = [p(&[POLICY_1]), require.clone(), inhibit_any_policy(1)];
    assert_eq!(
        policy_path(
            &[],
            &[&any_later, &mid(&[p(&[ANY_POLICY])]), &[p(&[POLICY_1])]]
        ),
        None
    );
    assert_eq!(
        policy_path(
            &[],
            &[&any_later, &mid(&[p(&[ANY_POLICY])]), &[p(&[ANY_POLICY])]]
        ),
        VIOLATION
    );

    // The trust anchor is trusted for what the caller says, not for what
    // its certificate says of policies: its extensions are not processed.
    assert_eq!(
        policy_path(&[p(&[POLICY_1]), require], &[&[], &[p(&[POLICY_2])]]),
        None
    );
}

/// REQ-X509-089: the policy extensions are held to their encodings when a
/// certificate is parsed, so that nothing malformed reaches processing.
#[test]
fn policy_extensions_are_held_to_their_encodings() {
    let signer = key();
    let parses = |extension: Vec<u8>| {
        let der = cert(
            9,
            &name("Issuer"),
            &name("Subject"),
            signer.spki(),
            &[basic_constraints(true), key_usage(true), extension],
            &signer,
        );
        x509::Certificate::parse(&der)
            .map(|_| ())
            .map_err(|e| (e.kind(), e.context()))
    };
    let bad = |context| Err((ErrorKind::BadCertificate, context));
    let cp = |value: &[u8]| ext(&[0x55, 0x1d, 0x20], false, value);
    let information = |body: &[u8]| tlv(0x30, &tlv(0x30, body));
    let oid = tlv(0x06, POLICY_1);
    let qualifier = tlv(
        0x30,
        &[
            tlv(0x06, &[0x2b, 6, 1, 5, 5, 7, 2, 1]),
            tlv(0x16, b"https://cps.test/"),
        ]
        .concat(),
    );
    assert_eq!(parses(cp(&information(&oid))), Ok(()));
    assert_eq!(
        parses(cp(&information(
            &[oid.clone(), tlv(0x30, &qualifier)].concat()
        ))),
        Ok(())
    );
    assert_eq!(
        parses(cp(&tlv(0x30, &[]))),
        bad("empty certificatePolicies")
    );
    assert_eq!(
        parses(cp(&information(&[oid.clone(), tlv(0x30, &[])].concat()))),
        bad("empty policy qualifiers")
    );
    assert_eq!(
        parses(cp(&information(&tlv(0x06, &[0x2a, 0x80, 0x01])))),
        bad("nonminimal OBJECT IDENTIFIER subidentifier")
    );
    assert!(parses(cp(&information(&[]))).is_err());
    assert!(parses(cp(&information(&[oid.clone(), tlv(0x05, &[])].concat()))).is_err());
    assert!(parses(cp(&[information(&oid), vec![0x05, 0x00]].concat())).is_err());
    let many = |count: usize| {
        let list: Vec<u8> = (0..count)
            .flat_map(|i| {
                tlv(
                    0x30,
                    &tlv(0x06, &[0x2a, 0x03, 0x81 + (i >> 7) as u8, (i & 0x7f) as u8]),
                )
            })
            .collect();
        cp(&tlv(0x30, &list))
    };
    assert_eq!(parses(many(256)), Ok(()));
    assert_eq!(parses(many(257)), bad("too many certificate policies"));

    assert_eq!(parses(policy_mappings(&[(POLICY_1, POLICY_2)])), Ok(()));
    assert_eq!(parses(policy_mappings(&[])), bad("empty policyMappings"));
    for pair in [(ANY_POLICY, POLICY_2), (POLICY_1, ANY_POLICY)] {
        assert_eq!(
            parses(policy_mappings(&[(POLICY_1, POLICY_2), pair])),
            bad("anyPolicy in a policy mapping")
        );
    }
    let pm = |value: &[u8]| ext(&[0x55, 0x1d, 0x21], true, value);
    assert!(parses(pm(&information(&oid))).is_err(), "half a pair");
    assert!(
        parses(pm(&information(
            &[oid.clone(), oid.clone(), oid.clone()].concat()
        )))
        .is_err(),
        "three in a pair"
    );

    assert_eq!(parses(policy_constraints(Some(0), None)), Ok(()));
    assert_eq!(parses(policy_constraints(None, Some(3))), Ok(()));
    assert_eq!(parses(policy_constraints(Some(1), Some(2))), Ok(()));
    assert_eq!(
        parses(policy_constraints(None, None)),
        bad("empty policyConstraints")
    );
    let pc = |body: &[u8]| ext(&[0x55, 0x1d, 0x24], true, &tlv(0x30, body));
    assert!(
        parses(pc(&[tlv(0x81, &[1]), tlv(0x80, &[1])].concat())).is_err(),
        "out of order"
    );
    assert!(parses(pc(&tlv(0x80, &[0x80]))).is_err(), "negative");
    assert!(
        parses(pc(&tlv(0x80, &[0x00, 0x01]))).is_err(),
        "not minimal"
    );
    assert!(parses(pc(&tlv(0x80, &[]))).is_err(), "empty");
    assert!(parses(pc(&tlv(0x82, &[1]))).is_err(), "an unknown field");

    assert_eq!(parses(inhibit_any_policy(0)), Ok(()));
    let iap = |value: &[u8]| ext(&[0x55, 0x1d, 0x36], true, value);
    assert!(parses(iap(&tlv(0x02, &[0xff]))).is_err(), "negative");
    assert!(parses(iap(&tlv(0x02, &[]))).is_err(), "empty");
    assert!(parses(iap(&[tlv(0x02, &[1]), tlv(0x02, &[1])].concat())).is_err());
    assert!(parses(iap(&tlv(0x04, &[1]))).is_err(), "not an INTEGER");
}
