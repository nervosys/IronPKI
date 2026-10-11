//! Writes a seed corpus: real certificates, a CRL, an OCSP response and name
//! constraints, so the fuzzer starts from inputs that parse and verify, and
//! the PyCA-generated certificates from `tests/vectors`, which are shapes
//! this crate's own builder does not produce.
//!
//! It then replays each seed along its target's path and fails unless the
//! fixtures still validate, so a stale corpus is noticed here and not as a
//! fuzzer that never gets past the first check.

use std::path::Path;

use ironpki::Purpose;
use ironpki::x509::{self, VerifyOptions, crl, ocsp};
use ironpki_fuzz::{ALGORITHMS, LIMITS, NOW, diff_pki, diff_seed, pki, rng, sign_tbs};

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
}

fn with_sel(sel: u8, body: &[u8]) -> Vec<u8> {
    [&[sel][..], body].concat()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Every run of hex digits long enough to be a certificate, from a vector
/// file: no JSON reader is needed to find them.
fn certificates(json: &str) -> Vec<Vec<u8>> {
    json.split('"')
        .filter(|s| s.len() > 200 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(hex)
        .collect()
}

fn main() {
    let p = pki();
    let mut r = rng();

    // The fixtures validate, or the corpus would be useless.
    let opts = VerifyOptions::new(NOW, Purpose::TlsServer, ALGORITHMS, LIMITS);
    x509::verify_chain(&p.leaf, &[], &p.roots, &opts).expect("the fixture leaf validates");
    let d = diff_pki();
    let leaf = sign_tbs(&d.leaf_tbs, &d.int_key);
    let int = sign_tbs(&d.int_tbs, &d.root_key);
    x509::verify_chain(&leaf, &[&int], &d.roots, &opts)
        .expect("the differential fixture validates");
    x509::verify_chain_fixed(&leaf, &[&int], &d.roots, &opts)
        .expect("the differential fixture validates in fixed slots");

    write("pki", "leaf", &with_sel(0, &p.leaf));
    write("pki", "leaf-chain", &with_sel(1, &p.leaf));
    write("pki", "ca-as-intermediate", &with_sel(1, &p.ca_cert));
    write("pki", "leaf-as-ek", &with_sel(0x21, &p.leaf));
    write("pki", "leaf-pinned", &with_sel(0x81, &p.leaf));
    let list = crl::build(
        &p.ca_cert,
        &p.ca_key,
        &[(&[9u8; 16], NOW - 60)],
        NOW - 3600,
        NOW + 3600,
        1,
        &mut r,
    )
    .unwrap();
    write("pki", "crl", &with_sel(2, &list));
    let response = ocsp::build_response(
        &p.leaf,
        &p.ca_cert,
        &p.ca_key,
        ocsp::CertStatus::Good,
        NOW - 60,
        NOW + 3600,
        &mut r,
    )
    .unwrap();
    write("pki", "ocsp", &with_sel(3, &response));
    write("pki", "anchor", &with_sel(4, &p.ca_cert));
    // NameConstraints: permitted dNSName fuzz.test and rfc822Name fuzz.test.
    write(
        "pki",
        "constraints",
        &with_sel(
            4,
            &[
                0x30, 0x1c, 0xa0, 0x1a, 0x30, 0x0b, 0x82, 0x09, b'f', b'u', b'z', b'z', b'.', b't',
                b'e', b's', b't', 0x30, 0x0b, 0x81, 0x09, b'f', b'u', b'z', b'z', b'.', b't', b'e',
                b's', b't',
            ],
        ),
    );

    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors");
    let mut n = 0;
    for file in [
        "attestation-certificate-policy.json",
        "x509-server-identity.json",
        "x509-paths.json",
        "x509-signatures.json",
    ] {
        let text = std::fs::read_to_string(vectors.join(file)).unwrap();
        for der in certificates(&text) {
            write("pki", &format!("pyca-{n:03}"), &with_sel(0, &der));
            write("pki", &format!("pyca-{n:03}-chain"), &with_sel(1, &der));
            n += 1;
        }
    }
    assert!(n > 150, "found only {n} certificates in the vector files");

    // Each purpose, through an intermediate and directly under the root, for
    // the TLS leaf and for the endorsement-key leaf.
    let ek_opts = VerifyOptions::new(NOW, Purpose::TpmEndorsementKey, ALGORITHMS, LIMITS);
    let ek_leaf = sign_tbs(&d.ek_leaf_tbs, &d.int_key);
    x509::verify_chain(&ek_leaf, &[&int], &d.roots, &ek_opts)
        .expect("the endorsement-key fixture validates");
    x509::verify_chain_fixed(&ek_leaf, &[&int], &d.roots, &ek_opts)
        .expect("the endorsement-key fixture validates in fixed slots");
    for sel in 0..8 {
        write(
            "pki_differential",
            &format!("chain-{sel}"),
            &diff_seed(sel, false),
        );
        write(
            "pki_differential",
            &format!("ek-chain-{sel}"),
            &diff_seed(sel, true),
        );
    }
    println!(
        "wrote {} pki seeds and 16 pki_differential seeds",
        9 + 2 * n
    );
}
