//! TPM endorsement-key certificates made by an independent implementation
//! (PyCA `cryptography`; see `tests/vectors/README.md`), validated for
//! [`Purpose::TpmEndorsementKey`]. `REQ-X509-080`.

use ironpki::sign::VERIFY_ALGORITHMS;
use ironpki::x509::{RootStore, VerifyOptions, verify_chain, verify_chain_fixed};
use ironpki::{ErrorKind, Limits, Purpose};

/// 2027-01-15, inside the vectors' 2020 to 2050 validity.
const NOW: u64 = 1_800_000_000;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn pyca_endorsement_key_certificates_validate_as_their_path_deserves() {
    let vectors =
        ic_json::parse(include_str!("vectors/attestation-certificate-policy.json")).unwrap();
    let mut roots = RootStore::new();
    roots
        .add_der(&hex(vectors.get("anchor").unwrap().as_str().unwrap()))
        .unwrap();
    let ek = VerifyOptions::new(
        NOW,
        Purpose::TpmEndorsementKey,
        VERIFY_ALGORITHMS,
        Limits::DEFAULT,
    );
    let tls = VerifyOptions::new(NOW, Purpose::TlsServer, VERIFY_ALGORITHMS, Limits::DEFAULT);

    // What path validation alone makes of each case. The three whose keys
    // differ from the TPM's are sound paths: binding a certificate to a
    // TPM is the caller's check, not this crate's.
    let expected: [(&str, Option<ErrorKind>); 10] = [
        ("matching_rsa_key", None),
        ("eku_absent_is_permitted", None),
        ("same_modulus_different_exponent", None),
        ("different_rsa_key", None),
        ("non_rsa_key", None),
        ("wrong_eku", Some(ErrorKind::CertificateUsage)),
        ("expired", Some(ErrorKind::CertificateExpired)),
        ("not_yet_valid", Some(ErrorKind::CertificateExpired)),
        (
            "unknown_critical_extension",
            Some(ErrorKind::UnsupportedCertificate),
        ),
        ("ca_cannot_be_end_entity", Some(ErrorKind::CertificateUsage)),
    ];
    let cases = vectors.get("cases").unwrap().as_array().unwrap();
    assert_eq!(cases.len(), expected.len());
    for (case, (name, want)) in cases.iter().zip(expected) {
        assert_eq!(case.get("name").unwrap().as_str().unwrap(), name);
        let leaf = hex(case.get("certificate").unwrap().as_str().unwrap());
        let owned = verify_chain(&leaf, &[], &roots, &ek);
        let fixed = verify_chain_fixed(&leaf, &[], &roots, &ek);
        assert_eq!(owned.as_ref().err().map(|e| e.kind()), want, "{name}");
        assert_eq!(fixed.as_ref().err().map(|e| e.kind()), want, "{name}");
        if let Ok(report) = owned {
            assert_eq!(report.depth, 1, "{name}");
            assert_eq!(
                report.anchor_subject_cn.as_deref(),
                Some("IPG disposable policy test CA")
            );
        }
    }

    // The first case names only the endorsement-key purpose, so it is not a
    // TLS server certificate; the second names no purpose, and its RSA key
    // could sign, so as a path it would pass for either.
    let named = hex(cases[0].get("certificate").unwrap().as_str().unwrap());
    assert_eq!(
        verify_chain(&named, &[], &roots, &tls).unwrap_err().kind(),
        ErrorKind::CertificateUsage
    );
}
