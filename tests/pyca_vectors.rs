//! Certificates made by an independent implementation (PyCA `cryptography`),
//! from IronPrivacyGuard's test vectors: see `tests/vectors/README.md`.
//!
//! Each case records the verdict of IronPrivacyGuard's own validator, which
//! this crate replaced there. The verdicts agree except where this crate has
//! a different rule on purpose; those cases are named below with the rule.

use ironpki::sign::VERIFY_ALGORITHMS;
use ironpki::x509::{
    RootStore, ServerName, VerifyOptions, verify_chain, verify_chain_fixed, verify_name,
};
use ironpki::{Limits, Purpose};

/// 2027-01-15, the time the vectors were generated to be judged at.
const NOW: u64 = 1_800_000_000;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn text<'a>(json: &'a ic_json::Json, key: &str) -> &'a str {
    json.get(key).unwrap().as_str().unwrap()
}

/// Where this crate accepts a TLS server certificate that IronPrivacyGuard's
/// validator refused, and why.
const SERVER_DIFFERENCES: &[(&str, &str)] = &[
    (
        "presented_terminal_dot_rejected",
        "REQ-X509-071: a dNSName with a trailing dot names the same host",
    ),
    (
        "any_eku_is_not_explicit_server_purpose",
        "REQ-X509-080: anyExtendedKeyUsage stands for the TLS purposes (RFC 5280 4.2.1.12)",
    ),
    (
        "constrained_wildcard_fails_closed",
        "REQ-X509-008: *.example.test lies wholly within the permitted example.test, and a \
         wildcard under a constraint is evaluated, not refused",
    ),
];

/// 41 TLS server certificates: a path to the anchor through one intermediate,
/// then the name. REQ-X509-003, REQ-X509-006, REQ-X509-008.
#[test]
fn pyca_server_certificates_are_judged_as_recorded() {
    let vectors = ic_json::parse(include_str!("vectors/x509-server-identity.json")).unwrap();
    assert_eq!(vectors.get("now").unwrap().as_i64(), Some(NOW as i64));
    let mut roots = RootStore::new();
    roots.add_der(&hex(text(&vectors, "anchor"))).unwrap();
    let opts = VerifyOptions::new(NOW, Purpose::TlsServer, VERIFY_ALGORITHMS, Limits::DEFAULT);
    let cases = vectors.get("cases").unwrap().as_array().unwrap();
    assert_eq!(cases.len(), 41);
    let mut differences = 0;
    for case in cases {
        let name = text(case, "name");
        let leaf = hex(text(case, "leaf"));
        let intermediate = hex(text(case, "intermediate"));
        let recorded = case.get("accepted").unwrap().as_bool().unwrap();
        let owned = verify_chain(&leaf, &[&intermediate], &roots, &opts);
        let fixed = verify_chain_fixed(&leaf, &[&intermediate], &roots, &opts);
        assert_eq!(
            owned.as_ref().err().map(|e| e.kind()),
            fixed.as_ref().err().map(|e| e.kind()),
            "{name}: the two validators disagree"
        );
        let named = ServerName::parse(text(case, "host"))
            .and_then(|host| verify_name(&leaf, &host))
            .is_ok();
        let accepted = owned.is_ok() && named;
        let expected = match SERVER_DIFFERENCES.iter().find(|(n, _)| *n == name) {
            Some(_) => {
                differences += 1;
                assert!(!recorded, "{name} is listed as a difference");
                true
            }
            None => recorded,
        };
        assert_eq!(accepted, expected, "{name}");
    }
    assert_eq!(differences, SERVER_DIFFERENCES.len());
}

/// The path this crate accepts and its recorded verdict refuses, with the
/// rule that makes the difference.
const PATH_DIFFERENCES: &[(&str, &str)] = &[(
    "unsupported_directory_constraint_fails_closed",
    "REQ-X509-086: a directoryName constraint is evaluated, not refused, and the leaf's \
     subject is the permitted name itself. OpenSSL 3.5 accepts this path too",
)];

/// 30 paths: intermediates in any order, several anchors, path length,
/// name constraints, validity, cross-signing. Judged for the endorsement-key
/// purpose, as IronPrivacyGuard judged them. All but one agree. REQ-X509-002,
/// REQ-X509-006, REQ-X509-008, REQ-X509-080, REQ-X509-086.
#[test]
fn pyca_paths_are_judged_as_recorded() {
    let vectors = ic_json::parse(include_str!("vectors/x509-paths.json")).unwrap();
    let opts = VerifyOptions::new(
        NOW,
        Purpose::TpmEndorsementKey,
        VERIFY_ALGORITHMS,
        Limits::DEFAULT,
    );
    let cases = vectors.get("cases").unwrap().as_array().unwrap();
    assert_eq!(cases.len(), 30);
    let mut differences = 0;
    for case in cases {
        let name = text(case, "name");
        let list = |key: &str| -> Vec<Vec<u8>> {
            case.get(key)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|c| hex(c.as_str().unwrap()))
                .collect()
        };
        let leaf = hex(text(case, "leaf"));
        let intermediates = list("intermediates");
        let intermediates: Vec<&[u8]> = intermediates.iter().map(Vec::as_slice).collect();
        let mut roots = RootStore::new();
        for anchor in list("anchors") {
            // An anchor that is not a usable certificate is not an anchor.
            let _ = roots.add_der(&anchor);
        }
        let recorded = case.get("accepted").unwrap().as_bool().unwrap();
        let expected = match PATH_DIFFERENCES.iter().find(|(n, _)| *n == name) {
            Some(_) => {
                differences += 1;
                assert!(!recorded, "{name} is listed as a difference");
                true
            }
            None => recorded,
        };
        let owned = verify_chain(&leaf, &intermediates, &roots, &opts);
        assert_eq!(owned.is_ok(), expected, "{name}: {:?}", owned.err());
        // The fixed-slot validator holds at most seven intermediates.
        if intermediates.len() <= 7 {
            let fixed = verify_chain_fixed(&leaf, &intermediates, &roots, &opts);
            assert_eq!(fixed.is_ok(), expected, "{name} (fixed): {:?}", fixed.err());
        }
    }
    assert_eq!(differences, PATH_DIFFERENCES.len());
}
