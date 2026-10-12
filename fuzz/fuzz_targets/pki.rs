//! Everything a caller hands this crate as DER it did not make: certificates,
//! through the parser, name matching and both path validators; certificate
//! requests; CRLs; OCSP responses; and trust anchors in both forms.
#![no_main]

use ironpki::x509::{self, Certificate, RootStore, ServerName, VerifyOptions, crl::CrlStore};
use ironpki::{Purpose, TrustAnchor};
use ironpki_fuzz::{ALGORITHMS, LIMITS, NAME, NOW, pki};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let p = pki();
    let purpose = match sel >> 4 & 3 {
        0 => Purpose::TlsServer,
        1 => Purpose::TlsClient,
        _ => Purpose::TpmEndorsementKey,
    };
    let mut opts = VerifyOptions::new(NOW, purpose, ALGORITHMS, LIMITS);
    opts.accept_anchor_as_leaf = sel & 0x80 != 0;
    match sel % 5 {
        0 => {
            if let Ok(c) = Certificate::parse(body) {
                let _ = (
                    c.serial(),
                    c.der(),
                    c.spki_der(),
                    c.subject_der(),
                    c.issuer_der(),
                );
                let _ = (c.not_before(), c.not_after(), c.is_ca(), c.common_name());
                let _ = (c.dns_names(), c.ip_addresses(), c.signature_scheme());
                let _ = c.uri_names();
                let _ = c
                    .subject_public_key()
                    .map(|k| (k.kind_id(), k.classical_bits()));
            }
            let _ = x509::verify_name(body, &ServerName::Dns(NAME));
            let _ = x509::check_leaf_fixed(body, &opts);
            // The input as a certificate request.
            if let Ok(r) = x509::request::CertificateRequest::parse(body) {
                let _ = (
                    r.der(),
                    r.subject_der(),
                    r.subject_common_name(),
                    r.spki_der(),
                );
                let _ = (r.dns_names(), r.ip_addresses(), r.uri_names());
                let _ = r.extension(&[0x55, 0x1d, 0x11]);
                let _ = r.subject_public_key().map(|k| k.kind_id());
                let _ = r.verify(ALGORITHMS);
            }
        }
        1 => {
            // The input as a leaf, then as an intermediate under a real
            // leaf, in both validators. They must agree on the verdict.
            for (leaf, ints) in [(body, &[][..]), (&p.leaf[..], &[body][..])] {
                let owned = x509::verify_chain(leaf, ints, &p.roots, &opts)
                    .map(|_| ())
                    .map_err(|e| e.kind());
                let fixed = x509::verify_chain_fixed(leaf, ints, &p.roots, &opts)
                    .map(|_| ())
                    .map_err(|e| e.kind());
                assert_eq!(owned, fixed, "the path validators disagree");
            }
        }
        2 => {
            let mut store = CrlStore::new();
            if store.add_der(body).is_ok() {
                opts.crls = Some(&store);
                opts.require_crl = true;
                let _ = x509::verify_chain(&p.leaf, &[], &p.roots, &opts);
            }
            let ca = Certificate::parse(&p.ca_cert).unwrap();
            let mut for_issuer = CrlStore::new();
            let _ = for_issuer.add_der_for_issuer(body, ca.spki_der());
        }
        3 => {
            let ca = Certificate::parse(&p.ca_cert).unwrap();
            let _ = x509::ocsp::verify_response(
                body,
                &p.leaf,
                ca.subject_der(),
                ca.spki_der(),
                NOW,
                ALGORITHMS,
            );
        }
        _ => {
            // The input as an anchor: a certificate, then the name
            // constraints of a key-form anchor for the fixture root, which
            // the real chain is then validated under.
            let mut store = RootStore::new();
            let _ = store.add(TrustAnchor::Certificate(body));
            if let Ok(text) = core::str::from_utf8(body) {
                let _ = store.add_pem_bundle(text);
            }
            let ca = Certificate::parse(&p.ca_cert).unwrap();
            let mut constrained = RootStore::new();
            if constrained
                .add(TrustAnchor::Key {
                    subject: ca.subject_der(),
                    spki: ca.spki_der(),
                    name_constraints: Some(body),
                })
                .is_ok()
            {
                let owned = x509::verify_chain(&p.leaf, &[], &constrained, &opts)
                    .map(|_| ())
                    .map_err(|e| e.kind());
                let fixed = x509::verify_chain_fixed(&p.leaf, &[], &constrained, &opts)
                    .map(|_| ())
                    .map_err(|e| e.kind());
                assert_eq!(owned, fixed, "the path validators disagree");
            }
        }
    }
});
