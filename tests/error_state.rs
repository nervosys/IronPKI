//! Once IronCrypto is in its error state, nothing validates and nothing is
//! issued: no chain, no OCSP response, no CRL-free path, no certificate or
//! response made. Since IronCrypto 0.3 its hashes refuse there too, so a
//! key identifier or CertID hash cannot be made from a module that failed.
//!
//! The state cannot be left, so this file is a process of its own and has
//! one test. Everything is made first, while the module works.

use ic_core::sig::Signer;
use ic_core::traits::RandomSource;
use ic_pkix::{KeyAlgorithm, PrivateKeyInfo};
use ic_sig::SoftwareSigner;
use ironpki::sign::VERIFY_ALGORITHMS;
use ironpki::x509::crl::{self, CrlStore};
use ironpki::x509::ocsp::{self, CertStatus};
use ironpki::x509::{self, CertificateParams, RootStore, VerifyOptions};
use ironpki::{ErrorKind, Limits, Purpose};

const NOW: u64 = 1_800_000_000;

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

/// Bytes that are not random and never refused: a test's stand-in, so that
/// what refuses below is the signing and hashing, not the DRBG.
struct Fixed;

impl RandomSource for Fixed {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        out.fill(0x5a);
        Ok(())
    }
}

fn p256() -> SoftwareSigner {
    let mut r = rng();
    let mut der = vec![0u8; 256];
    for _ in 0..64 {
        let mut secret = [0u8; 32];
        r.fill(&mut secret).unwrap();
        let n = PrivateKeyInfo::Ec {
            algorithm: KeyAlgorithm::EcP256,
            private_key: &secret,
            public_key: None,
        }
        .to_der(&mut der)
        .unwrap();
        if let Ok(signer) = SoftwareSigner::from_pkcs8(&der[..n]) {
            return signer;
        }
    }
    panic!("no usable P-256 key in 64 tries");
}

#[test]
fn nothing_validates_or_is_issued_in_the_error_state() {
    let (root_key, leaf_key) = (p256(), p256());
    let mut ca = CertificateParams::new("Error State Root", NOW - 3600, NOW + 86_400, [1; 16]);
    ca.is_ca = true;
    let root = x509::self_signed(&ca, &root_key, &mut rng()).unwrap();
    let mut leaf_params = CertificateParams::new("leaf.test", NOW - 3600, NOW + 86_400, [2; 16]);
    leaf_params.dns_names = &["leaf.test"];
    leaf_params.usage = &[Purpose::TlsServer];
    let leaf = x509::issue(
        &leaf_params,
        leaf_key.public_key(),
        &root,
        &root_key,
        &mut rng(),
    )
    .unwrap();
    let staple = ocsp::build_response(
        &leaf,
        &root,
        &root_key,
        CertStatus::Good,
        NOW - 60,
        NOW + 3600,
        &mut rng(),
    )
    .unwrap();
    let mut roots = RootStore::new();
    roots.add_der(&root).unwrap();
    let opts = VerifyOptions::new(NOW, Purpose::TlsServer, VERIFY_ALGORITHMS, Limits::DEFAULT);
    let anchor = x509::Certificate::parse(&root).unwrap();
    let check_staple = || {
        ocsp::verify_response(
            &staple,
            &leaf,
            anchor.subject_der(),
            anchor.spki_der(),
            NOW,
            VERIFY_ALGORITHMS,
        )
    };

    // An intermediate and an expired one of the same name and key, the
    // expired one first: a path search meets its expiry before it meets the
    // module's refusal, and must not report the expiry.
    let int_key = p256();
    let mut int_params = CertificateParams::new(
        "Error State Intermediate",
        NOW - 3600,
        NOW + 86_400,
        [3; 16],
    );
    int_params.is_ca = true;
    let int = x509::issue(
        &int_params,
        int_key.public_key(),
        &root,
        &root_key,
        &mut rng(),
    )
    .unwrap();
    int_params.not_after = NOW - 60;
    int_params.serial = [4; 16];
    let expired = x509::issue(
        &int_params,
        int_key.public_key(),
        &root,
        &root_key,
        &mut rng(),
    )
    .unwrap();
    let mut far_params = CertificateParams::new("far.test", NOW - 3600, NOW + 86_400, [5; 16]);
    far_params.dns_names = &["far.test"];
    far_params.usage = &[Purpose::TlsServer];
    let far = x509::issue(
        &far_params,
        leaf_key.public_key(),
        &int,
        &int_key,
        &mut rng(),
    )
    .unwrap();
    let both: [&[u8]; 2] = [&expired, &int];
    let crl = crl::build(&root, &root_key, &[], NOW - 60, NOW + 3600, 1, &mut rng()).unwrap();

    // While the module works, all of it does.
    x509::verify_chain(&far, &both, &roots, &opts).unwrap();
    CrlStore::new().add_der_for_issuer(&crl, &root).unwrap();
    x509::verify_chain(&leaf, &[], &roots, &opts).unwrap();
    x509::verify_chain_fixed(&leaf, &[], &roots, &opts).unwrap();
    check_staple().unwrap();

    // The DRBG refuses in the error state as well. The refusals below must
    // not be only its, so they are given bytes that never refuse.
    let mut r = Fixed;
    ic_core::module::enter_error_state();

    // REQ-ERR-001: each refusal says it is the module's, not a bad
    // signature, an unknown CA or an unsigned response.
    let refused = |e: ironpki::Error| assert_eq!(e.kind(), ErrorKind::ModuleState, "{e}");
    refused(x509::verify_chain(&leaf, &[], &roots, &opts).unwrap_err());
    refused(
        x509::verify_chain_fixed(&leaf, &[], &roots, &opts)
            .err()
            .unwrap(),
    );
    refused(check_staple().unwrap_err());
    refused(x509::verify_chain(&far, &both, &roots, &opts).unwrap_err());
    refused(
        x509::verify_chain_fixed(&far, &both, &roots, &opts)
            .err()
            .unwrap(),
    );
    refused(CrlStore::new().add_der_for_issuer(&crl, &root).unwrap_err());
    refused(x509::self_signed(&ca, &root_key, &mut r).unwrap_err());
    refused(
        x509::issue(
            &leaf_params,
            leaf_key.public_key(),
            &root,
            &root_key,
            &mut r,
        )
        .unwrap_err(),
    );
    refused(
        ocsp::build_response(
            &leaf,
            &root,
            &root_key,
            CertStatus::Good,
            NOW - 60,
            NOW + 3600,
            &mut r,
        )
        .unwrap_err(),
    );
}
