//! Agreement with OpenSSL, in both directions, on certificates and CRLs.
//!
//! Ignored by default: they need `openssl` 3.5 or later on `PATH` (3.5 for
//! ML-DSA).
//!
//! ```console
//! $ cargo test --test openssl_interop -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use ic_core::sig::Signer;
use ic_pkix::{KeyAlgorithm, MlDsaParameterSet, MlDsaPrivateKey, PrivateKeyInfo};
use ic_sig::SoftwareSigner;
use ironpki::sign::VERIFY_ALGORITHMS;
use ironpki::x509::crl::{self, CrlStore};
use ironpki::x509::{
    self, CertificateParams, RootStore, ServerName, VerifyOptions, verify_chain,
    verify_chain_fixed, verify_name,
};
use ironpki::{ErrorKind, Limits, Purpose};

const NAME: &str = "leaf.interop.test";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("ironpki-openssl").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `openssl` in `dir`, returning its standard output and error together.
fn openssl(args: &[&str], dir: &Path) -> (bool, String) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl on PATH");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn must(args: &[&str], dir: &Path) -> String {
    let (ok, text) = openssl(args, dir);
    assert!(ok, "openssl {args:?}: {text}");
    text
}

fn to_pem(label: &str, der: &[u8]) -> String {
    let mut buf = vec![0u8; ic_pkix::pem::encoded_len(label, der.len())];
    let n = ic_pkix::pem::encode(label, der, &mut buf).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

fn from_pem(label: &str, pem: &str) -> Vec<u8> {
    let mut buf = vec![0u8; pem.len()];
    let n = ic_pkix::pem::decode(label, pem.as_bytes(), &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn read_cert(dir: &Path, file: &str) -> Vec<u8> {
    from_pem(
        ic_pkix::pem::CERTIFICATE,
        &std::fs::read_to_string(dir.join(file)).unwrap(),
    )
}

/// The kinds of key this crate issues with here.
#[derive(Clone, Copy, Debug)]
enum Kind {
    P256,
    P384,
    P521,
    Ed25519,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// A fresh software key of `kind`, through PKCS#8.
fn key(kind: Kind) -> SoftwareSigner {
    let mut r = rng();
    let mut der = vec![0u8; 256];
    for _ in 0..64 {
        let mut secret = [0u8; 66];
        r.fill(&mut secret).unwrap();
        if matches!(kind, Kind::P521) {
            secret[0] &= 0x01;
        }
        let ec = |algorithm, private_key| PrivateKeyInfo::Ec {
            algorithm,
            private_key,
            public_key: None,
        };
        let ml_dsa = |set| MlDsaPrivateKey::Seed {
            set,
            seed: &secret[..32],
        };
        let n = match kind {
            Kind::P256 => ec(KeyAlgorithm::EcP256, &secret[..32]).to_der(&mut der),
            Kind::P384 => ec(KeyAlgorithm::EcP384, &secret[..48]).to_der(&mut der),
            Kind::P521 => ec(KeyAlgorithm::EcP521, &secret[..66]).to_der(&mut der),
            Kind::Ed25519 => PrivateKeyInfo::Ed25519(&secret[..32]).to_der(&mut der),
            Kind::MlDsa44 => ml_dsa(MlDsaParameterSet::MlDsa44).to_der(&mut der),
            Kind::MlDsa65 => ml_dsa(MlDsaParameterSet::MlDsa65).to_der(&mut der),
            Kind::MlDsa87 => ml_dsa(MlDsaParameterSet::MlDsa87).to_der(&mut der),
        }
        .unwrap();
        if let Ok(signer) = SoftwareSigner::from_pkcs8(&der[..n]) {
            return signer;
        }
    }
    panic!("no usable {kind:?} key in 64 tries");
}

fn params<'a>(cn: &'a str, dns: &'a [&'a str], ca: bool, serial: u8) -> CertificateParams<'a> {
    CertificateParams {
        subject_cn: cn,
        dns_names: dns,
        ip_addresses: &[],
        not_before: now() - 3600,
        not_after: now() + 86_400,
        is_ca: ca,
        path_len: None,
        usage: if ca { &[] } else { &[Purpose::TlsServer] },
        serial: [serial; 16],
    }
}

/// A root, an intermediate and a leaf of one key kind, issued here.
struct Chain {
    root: Vec<u8>,
    int: Vec<u8>,
    int_key: SoftwareSigner,
    leaf: Vec<u8>,
}

fn chain(kind: Kind) -> Chain {
    let mut r = rng();
    let (root_key, int_key, leaf_key) = (key(kind), key(kind), key(kind));
    let root = x509::self_signed(&params("Interop Root", &[], true, 1), &root_key, &mut r).unwrap();
    let int = x509::issue(
        &params("Interop Intermediate", &[], true, 2),
        int_key.public_key(),
        &root,
        &root_key,
        &mut r,
    )
    .unwrap();
    let leaf = x509::issue(
        &params(NAME, &[NAME], false, 3),
        leaf_key.public_key(),
        &int,
        &int_key,
        &mut r,
    )
    .unwrap();
    Chain {
        root,
        int,
        int_key,
        leaf,
    }
}

/// OpenSSL, at its strictest, accepts the chains this crate issues, for
/// every key kind it issues with.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn openssl_verifies_the_chains_this_crate_issues() {
    for kind in [
        Kind::P256,
        Kind::P384,
        Kind::P521,
        Kind::Ed25519,
        Kind::MlDsa44,
        Kind::MlDsa65,
        Kind::MlDsa87,
    ] {
        let c = chain(kind);
        let dir = workdir(&format!("ours-{kind:?}"));
        let pem = |der: &[u8]| to_pem(ic_pkix::pem::CERTIFICATE, der);
        std::fs::write(dir.join("root.pem"), pem(&c.root)).unwrap();
        std::fs::write(dir.join("int.pem"), pem(&c.int)).unwrap();
        std::fs::write(dir.join("leaf.pem"), pem(&c.leaf)).unwrap();
        let (ok, text) = openssl(
            &[
                "verify",
                "-x509_strict",
                "-purpose",
                "sslserver",
                "-verify_hostname",
                NAME,
                "-CAfile",
                "root.pem",
                "-untrusted",
                "int.pem",
                "leaf.pem",
            ],
            &dir,
        );
        assert!(ok && text.contains("leaf.pem: OK"), "{kind:?}: {text}");
        // And it refuses the leaf without the intermediate, so the OK
        // above is a verdict on the path.
        let (ok, text) = openssl(&["verify", "-CAfile", "root.pem", "leaf.pem"], &dir);
        assert!(!ok, "{kind:?}: accepted without its issuer: {text}");
    }
}

/// This crate accepts the chains OpenSSL issues, in both validators, for
/// every signature algorithm it verifies, and refuses each under another
/// root or for another name.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn this_crate_verifies_the_chains_openssl_issues() {
    let cases: &[(&str, &[&str], &[&str])] = &[
        (
            "p256",
            &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
            &["-sha256"],
        ),
        (
            "p384",
            &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
            &["-sha384"],
        ),
        (
            "p521",
            &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-521"],
            &["-sha512"],
        ),
        ("ed25519", &["-newkey", "ed25519"], &[]),
        (
            "rsa2048-pkcs1-sha256",
            &["-newkey", "rsa:2048"],
            &["-sha256"],
        ),
        (
            "rsa3072-pkcs1-sha384",
            &["-newkey", "rsa:3072"],
            &["-sha384"],
        ),
        (
            "rsa4096-pkcs1-sha512",
            &["-newkey", "rsa:4096"],
            &["-sha512"],
        ),
        (
            "rsa2048-pss-sha256",
            &["-newkey", "rsa:2048"],
            &[
                "-sha256",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:-1",
            ],
        ),
        (
            "rsa3072-pss-sha384",
            &["-newkey", "rsa:3072"],
            &[
                "-sha384",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:-1",
            ],
        ),
        ("ml-dsa-44", &["-newkey", "ML-DSA-44"], &[]),
        ("ml-dsa-65", &["-newkey", "ML-DSA-65"], &[]),
        ("ml-dsa-87", &["-newkey", "ML-DSA-87"], &[]),
    ];
    let stranger = chain(Kind::P256).root;
    for (label, newkey, sign) in cases {
        let dir = workdir(&format!("openssl-{label}"));
        let base = ["req", "-x509", "-nodes", "-days", "2"];
        let ca = [
            &base[..],
            newkey,
            sign,
            &[
                "-keyout",
                "cakey.pem",
                "-out",
                "ca.pem",
                "-subj",
                "/CN=OpenSSL Interop CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        ]
        .concat();
        must(&ca, &dir);
        let leaf = [
            &base[..],
            newkey,
            sign,
            &[
                "-keyout",
                "key.pem",
                "-out",
                "leaf.pem",
                "-CA",
                "ca.pem",
                "-CAkey",
                "cakey.pem",
                "-subj",
                "/CN=leaf",
                "-addext",
                "subjectAltName=DNS:leaf.interop.test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth",
            ],
        ]
        .concat();
        must(&leaf, &dir);
        // The clock is read after OpenSSL issued: its notBefore is that moment.
        let opts = VerifyOptions::new(
            now(),
            Purpose::TlsServer,
            VERIFY_ALGORITHMS,
            Limits::DEFAULT,
        );
        let (ca, leaf) = (read_cert(&dir, "ca.pem"), read_cert(&dir, "leaf.pem"));

        let mut roots = RootStore::new();
        roots.add_der(&ca).unwrap();
        let report =
            verify_chain(&leaf, &[], &roots, &opts).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(report.depth, 1, "{label}");
        verify_chain_fixed(&leaf, &[], &roots, &opts)
            .unwrap_or_else(|e| panic!("{label} (fixed): {e}"));
        verify_name(&leaf, &ServerName::parse(NAME).unwrap()).unwrap();
        assert_eq!(
            verify_name(&leaf, &ServerName::parse("other.interop.test").unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::CertificateNameMismatch,
            "{label}"
        );
        let mut other = RootStore::new();
        other.add_der(&stranger).unwrap();
        assert_eq!(
            verify_chain(&leaf, &[], &other, &opts).unwrap_err().kind(),
            ErrorKind::UnknownCa,
            "{label}"
        );
    }
}

/// OpenSSL accepts a CRL this crate issues, and refuses the certificate it
/// revokes and no other.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn openssl_honours_the_crls_this_crate_issues() {
    let c = chain(Kind::P256);
    let leaf_serial = [3u8; 16];
    for revoke in [false, true] {
        let dir = workdir(&format!("crl-ours-{revoke}"));
        let revoked: Vec<(&[u8], u64)> = if revoke {
            vec![(&leaf_serial, now() - 60)]
        } else {
            vec![(&[9u8; 16], now() - 60)]
        };
        let list = crl::build(
            &c.int,
            &c.int_key,
            &revoked,
            now() - 3600,
            now() + 3600,
            1,
            &mut rng(),
        )
        .unwrap();
        let pem = |der: &[u8]| to_pem(ic_pkix::pem::CERTIFICATE, der);
        std::fs::write(
            dir.join("chain.pem"),
            format!("{}{}", pem(&c.root), pem(&c.int)),
        )
        .unwrap();
        std::fs::write(dir.join("int.pem"), pem(&c.int)).unwrap();
        std::fs::write(dir.join("leaf.pem"), pem(&c.leaf)).unwrap();
        std::fs::write(dir.join("crl.pem"), to_pem("X509 CRL", &list)).unwrap();
        let text = must(
            &["crl", "-in", "crl.pem", "-CAfile", "int.pem", "-noout"],
            &dir,
        );
        assert!(text.contains("verify OK"), "the CRL's signature: {text}");
        let (ok, text) = openssl(
            &[
                "verify",
                "-crl_check",
                "-CAfile",
                "chain.pem",
                "-CRLfile",
                "crl.pem",
                "leaf.pem",
            ],
            &dir,
        );
        if revoke {
            assert!(!ok && text.contains("certificate revoked"), "{text}");
        } else {
            assert!(ok && text.contains("leaf.pem: OK"), "{text}");
        }
    }
}

/// This crate honours a CRL OpenSSL issues: it shows an unrevoked
/// certificate good, and refuses a revoked one.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn this_crate_honours_the_crls_openssl_issues() {
    for revoke in [false, true] {
        let dir = workdir(&format!("crl-openssl-{revoke}"));
        must(
            &[
                "req",
                "-x509",
                "-nodes",
                "-days",
                "2",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-keyout",
                "cakey.pem",
                "-out",
                "ca.pem",
                "-subj",
                "/CN=OpenSSL CRL CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
            &dir,
        );
        must(
            &[
                "req",
                "-x509",
                "-nodes",
                "-days",
                "2",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-keyout",
                "key.pem",
                "-out",
                "leaf.pem",
                "-CA",
                "ca.pem",
                "-CAkey",
                "cakey.pem",
                "-subj",
                "/CN=leaf",
                "-addext",
                "subjectAltName=DNS:leaf.interop.test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth",
            ],
            &dir,
        );
        std::fs::write(dir.join("index.txt"), "").unwrap();
        std::fs::write(dir.join("crlnumber"), "01\n").unwrap();
        std::fs::write(
            dir.join("ca.cnf"),
            "[ ca ]\ndefault_ca = d\n[ d ]\ndatabase = index.txt\ncrlnumber = crlnumber\n\
             default_md = sha256\ndefault_crl_days = 1\n",
        )
        .unwrap();
        let ca_args = [
            "ca",
            "-config",
            "ca.cnf",
            "-keyfile",
            "cakey.pem",
            "-cert",
            "ca.pem",
        ];
        if revoke {
            must(&[&ca_args[..], &["-revoke", "leaf.pem"]].concat(), &dir);
        }
        must(
            &[&ca_args[..], &["-gencrl", "-out", "crl.pem"]].concat(),
            &dir,
        );

        let mut crls = CrlStore::new();
        assert_eq!(
            crls.add_pem(&std::fs::read_to_string(dir.join("crl.pem")).unwrap())
                .unwrap(),
            1
        );
        let mut roots = RootStore::new();
        roots.add_der(&read_cert(&dir, "ca.pem")).unwrap();
        let leaf = read_cert(&dir, "leaf.pem");
        let mut opts = VerifyOptions::new(
            now(),
            Purpose::TlsServer,
            VERIFY_ALGORITHMS,
            Limits::DEFAULT,
        );
        opts.crls = Some(&crls);
        opts.require_crl = true;
        let verdict = verify_chain(&leaf, &[], &roots, &opts);
        if revoke {
            assert_eq!(verdict.unwrap_err().kind(), ErrorKind::CertificateRevoked);
        } else {
            assert!(verdict.unwrap().crl_checked);
        }
    }
}

/// An OpenSSL CA and a leaf with serial 0x1234, and OpenSSL's OCSP response
/// for the leaf from an index in which its status is `flag` (`V` or `R`).
fn openssl_ocsp_fixture(dir: &Path, flag: char, digest: &str) {
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"];
    let base = ["req", "-x509", "-nodes", "-days", "2"];
    must(
        &[
            &base[..],
            &ec,
            &[
                "-keyout",
                "cakey.pem",
                "-out",
                "ca.pem",
                "-subj",
                "/CN=OpenSSL OCSP CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        ]
        .concat(),
        dir,
    );
    must(
        &[
            &base[..],
            &ec,
            &[
                "-keyout",
                "key.pem",
                "-out",
                "leaf.pem",
                "-CA",
                "ca.pem",
                "-CAkey",
                "cakey.pem",
                "-set_serial",
                "0x1234",
                "-subj",
                "/CN=leaf",
                "-addext",
                "subjectAltName=DNS:leaf.interop.test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
            ],
        ]
        .concat(),
        dir,
    );
    let line = match flag {
        'R' => "R\t300101000000Z\t250101000000Z\t1234\tunknown\t/CN=leaf\n",
        _ => "V\t300101000000Z\t\t1234\tunknown\t/CN=leaf\n",
    };
    std::fs::write(dir.join("index.txt"), line).unwrap();
    // The CertID digest option must precede -cert.
    let mut args = vec![
        "ocsp",
        "-index",
        "index.txt",
        "-rsigner",
        "ca.pem",
        "-rkey",
        "cakey.pem",
        "-CA",
        "ca.pem",
        "-issuer",
        "ca.pem",
    ];
    if !digest.is_empty() {
        args.push(digest);
    }
    args.extend_from_slice(&["-cert", "leaf.pem", "-respout", "resp.der", "-ndays", "1"]);
    must(&args, dir);
}

/// This crate reads the OCSP responses OpenSSL signs: good is good, with a
/// SHA-1 CertID (whose hashes it cannot check, and says so) and a SHA-256
/// one; revoked is refused; and a response is no use for another
/// certificate or under another issuer's key.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn this_crate_judges_the_ocsp_responses_openssl_signs() {
    use ironpki::x509::ocsp::{CertStatus, verify_response};
    let stranger = chain(Kind::P256);
    for (flag, digest) in [('V', ""), ('V', "-sha256"), ('R', "")] {
        let dir = workdir(&format!("ocsp-openssl-{flag}{digest}"));
        openssl_ocsp_fixture(&dir, flag, digest);
        let (ca, leaf) = (read_cert(&dir, "ca.pem"), read_cert(&dir, "leaf.pem"));
        let response = std::fs::read(dir.join("resp.der")).unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&ca).unwrap();
        let opts = VerifyOptions::new(
            now(),
            Purpose::TlsServer,
            VERIFY_ALGORITHMS,
            Limits::DEFAULT,
        );
        let path = verify_chain(&leaf, &[], &roots, &opts).unwrap();
        let judge = |leaf: &[u8], spki: &[u8]| {
            verify_response(
                &response,
                leaf,
                &path.anchor_subject,
                spki,
                now(),
                VERIFY_ALGORITHMS,
            )
        };
        let verdict = judge(&leaf, &path.anchor_spki);
        if flag == 'R' {
            assert_eq!(verdict.unwrap_err().kind(), ErrorKind::CertificateRevoked);
            continue;
        }
        let verified = verdict.unwrap_or_else(|e| panic!("{flag}{digest}: {e}"));
        assert_eq!(verified.status, CertStatus::Good);
        assert!(!verified.delegated);
        assert_eq!(verified.cert_id_hashes_checked, digest == "-sha256");
        assert!(
            judge(&stranger.leaf, &path.anchor_spki).is_err(),
            "{digest}: a response for another certificate"
        );
        let other_key = x509::Certificate::parse(&stranger.root).unwrap();
        assert!(
            judge(&leaf, other_key.spki_der()).is_err(),
            "{digest}: a response another issuer's key did not sign"
        );
    }
}

/// OpenSSL's OCSP verifier accepts the responses this crate signs and reads
/// the status in each.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn openssl_judges_the_ocsp_responses_this_crate_signs() {
    use ironpki::x509::ocsp::{CertStatus, build_response};
    let c = chain(Kind::P256);
    let t = now();
    for (label, status, expected) in [
        ("good", CertStatus::Good, "leaf.pem: good"),
        (
            "revoked",
            CertStatus::Revoked { at: t - 600 },
            "leaf.pem: revoked",
        ),
    ] {
        let dir = workdir(&format!("ocsp-ours-{label}"));
        let response = build_response(
            &c.leaf,
            &c.int,
            &c.int_key,
            status,
            t - 60,
            t + 3600,
            &mut rng(),
        )
        .unwrap();
        let pem = |der: &[u8]| to_pem(ic_pkix::pem::CERTIFICATE, der);
        std::fs::write(
            dir.join("chain.pem"),
            format!("{}{}", pem(&c.root), pem(&c.int)),
        )
        .unwrap();
        std::fs::write(dir.join("int.pem"), pem(&c.int)).unwrap();
        std::fs::write(dir.join("leaf.pem"), pem(&c.leaf)).unwrap();
        std::fs::write(dir.join("resp.der"), &response).unwrap();
        // This crate's CertIDs are SHA-256 (IronCrypto has no SHA-1), so
        // OpenSSL must look the certificate up by SHA-256; its default is
        // SHA-1.
        let (_, text) = openssl(
            &[
                "ocsp",
                "-respin",
                "resp.der",
                "-CAfile",
                "chain.pem",
                "-issuer",
                "int.pem",
                "-sha256",
                "-cert",
                "leaf.pem",
            ],
            &dir,
        );
        assert!(text.contains("Response verify OK"), "{label}: {text}");
        assert!(text.contains(expected), "{label}: {text}");
    }
}

/// A leaf under a constrained OpenSSL CA: its subject, its alternative
/// names in OpenSSL's notation, and whether a path to it is good.
type Leaf = (&'static str, &'static str, bool);

/// Name constraints, judged by OpenSSL and by both validators here on the
/// same OpenSSL-issued certificates: every verdict is the same, and is the
/// one RFC 5280 §4.2.1.10 gives. REQ-X509-008, REQ-X509-085, REQ-X509-086,
/// REQ-X509-087.
///
/// One rule is left out because the two differ on purpose: a wildcard that
/// reaches into an excluded DNS subtree is refused here, and OpenSSL reads
/// it as a literal name.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn name_constraints_are_judged_as_openssl_judges_them() {
    const PLAIN: &str = "/CN=Leaf One";
    const CORP: &str = "C=US\nO=Example Corp\n";
    let cases: &[(&str, &str, &[Leaf])] = &[
        (
            "permitted;DNS:example.com",
            "",
            &[
                (PLAIN, "DNS:a.example.com", true),
                (PLAIN, "DNS:example.com", true),
                (PLAIN, "DNS:A.Example.COM", true),
                (PLAIN, "DNS:*.example.com", true),
                (PLAIN, "DNS:a.other.org", false),
                (PLAIN, "DNS:notexample.com", false),
                (PLAIN, "DNS:a.example.com,DNS:a.other.org", false),
                (PLAIN, "IP:192.0.2.1", true),
            ],
        ),
        (
            "excluded;DNS:evil.example.com",
            "",
            &[
                (PLAIN, "DNS:good.example.com", true),
                (PLAIN, "DNS:evil.example.com", false),
                (PLAIN, "DNS:x.Evil.example.com", false),
                (PLAIN, "DNS:notevil.example.com", true),
            ],
        ),
        (
            "permitted;DNS:example.com,excluded;DNS:bad.example.com",
            "",
            &[
                (PLAIN, "DNS:a.example.com", true),
                (PLAIN, "DNS:bad.example.com", false),
                (PLAIN, "DNS:other.org", false),
            ],
        ),
        (
            "permitted;IP:10.0.0.0/255.0.0.0",
            "",
            &[
                (PLAIN, "IP:10.1.2.3", true),
                (PLAIN, "IP:192.0.2.1", false),
                (PLAIN, "IP:2001:db8::1", false),
                (PLAIN, "DNS:a.example.com", true),
            ],
        ),
        (
            "excluded;IP:10.0.0.0/255.0.0.0",
            "",
            &[(PLAIN, "IP:10.1.2.3", false), (PLAIN, "IP:192.0.2.1", true)],
        ),
        (
            "permitted;email:example.com",
            "",
            &[
                (PLAIN, "email:a@example.com", true),
                (PLAIN, "email:a@Example.COM", true),
                (PLAIN, "email:a@other.org", false),
                (PLAIN, "email:a@mail.example.com", false),
                ("/CN=Leaf One/emailAddress=a@example.com", "", true),
                ("/CN=Leaf One/emailAddress=a@other.org", "", false),
            ],
        ),
        (
            "permitted;email:.example.com",
            "",
            &[
                (PLAIN, "email:a@mail.example.com", true),
                (PLAIN, "email:a@example.com", false),
            ],
        ),
        (
            "permitted;email:a@example.com",
            "",
            &[
                (PLAIN, "email:a@example.com", true),
                (PLAIN, "email:b@example.com", false),
            ],
        ),
        (
            "excluded;email:example.com",
            "",
            &[
                (PLAIN, "email:a@other.org", true),
                (PLAIN, "email:a@example.com", false),
            ],
        ),
        (
            "permitted;URI:example.com",
            "",
            &[
                (PLAIN, "URI:https://example.com/path", true),
                (PLAIN, "URI:https://EXAMPLE.com:8443/", true),
                (PLAIN, "URI:https://www.example.com/", false),
                (PLAIN, "URI:https://other.org/https://example.com/", false),
                (PLAIN, "URI:https://example.com@other.org/", false),
                (
                    PLAIN,
                    "URI:urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                    false,
                ),
                (PLAIN, "URI:https://192.0.2.1/", false),
                (PLAIN, "DNS:a.other.org", true),
            ],
        ),
        (
            "permitted;URI:.example.com",
            "",
            &[
                (PLAIN, "URI:https://a.example.com/", true),
                (PLAIN, "URI:https://a.b.example.com/", true),
                (PLAIN, "URI:https://example.com/", false),
                (PLAIN, "URI:https://notexample.com/", false),
            ],
        ),
        (
            "excluded;URI:example.com",
            "",
            &[
                (PLAIN, "URI:https://example.com/", false),
                (PLAIN, "URI:https://other.org/", true),
            ],
        ),
        (
            "permitted;dirName:base",
            CORP,
            &[
                ("/C=US/O=Example Corp/CN=Leaf One", "", true),
                ("/C=US/O=example  CORP/CN=Leaf One", "", true),
                ("/C=US/O=Example Corp", "", true),
                ("/C=US/O=Other/CN=Leaf One", "", false),
                ("/C=US/O=Example Corporation/CN=Leaf One", "", false),
                ("/O=Example Corp/C=US/CN=Leaf One", "", false),
                ("/CN=Leaf One/C=US/O=Example Corp", "", false),
                ("/C=US", "", false),
                ("/C=US/O=Example Corp/CN=Leaf One", "dirName:inside", true),
                ("/C=US/O=Example Corp/CN=Leaf One", "dirName:outside", false),
                ("/C=US/O=Example Corp/CN=Leaf One", "DNS:a.other.org", true),
            ],
        ),
        (
            "excluded;dirName:base",
            "O=Evil\n",
            &[
                ("/O=Good/CN=Leaf One", "", true),
                (PLAIN, "", true),
                ("/O=Evil/CN=Leaf One", "", false),
                ("/O=EVIL/CN=Leaf One", "", false),
                ("/O=Good/CN=Leaf One", "dirName:evil", false),
            ],
        ),
    ];
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"];
    let base = ["req", "-x509", "-nodes", "-days", "2", "-config", "nc.cnf"];
    let mut judged = 0;
    for (n, (constraint, base_name, leaves)) in cases.iter().enumerate() {
        let dir = workdir(&format!("nc-{n}"));
        let config = |alternative_names: &str| {
            let san = if alternative_names.is_empty() {
                String::new()
            } else {
                format!("subjectAltName={alternative_names}\n")
            };
            format!(
                "[req]\ndistinguished_name=dn\n[dn]\n\
                 [root_ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n\
                 [ca_ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n\
                 nameConstraints=critical,{constraint}\n\
                 [leaf_ext]\nbasicConstraints=critical,CA:FALSE\n\
                 keyUsage=critical,digitalSignature\n{san}\
                 [base]\n{base_name}\
                 [inside]\n{CORP}OU=Unit\n[outside]\nC=US\nO=Elsewhere\n[evil]\nO=Evil\nCN=x\n"
            )
        };
        std::fs::write(dir.join("nc.cnf"), config("")).unwrap();
        must(
            &[
                &base[..],
                &ec,
                &[
                    "-extensions",
                    "root_ext",
                    "-subj",
                    "/CN=NC Root",
                    "-keyout",
                    "rootkey.pem",
                    "-out",
                    "root.pem",
                ],
            ]
            .concat(),
            &dir,
        );
        must(
            &[
                &base[..],
                &ec,
                &[
                    "-extensions",
                    "ca_ext",
                    "-subj",
                    "/CN=NC Intermediate",
                    "-CA",
                    "root.pem",
                    "-CAkey",
                    "rootkey.pem",
                    "-keyout",
                    "intkey.pem",
                    "-out",
                    "int.pem",
                ],
            ]
            .concat(),
            &dir,
        );
        let (root, int) = (read_cert(&dir, "root.pem"), read_cert(&dir, "int.pem"));
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        for (subject, alternative_names, expected) in *leaves {
            let what = format!("{constraint} [{base_name:?}]: {subject} {alternative_names}");
            std::fs::write(dir.join("nc.cnf"), config(alternative_names)).unwrap();
            must(
                &[
                    &base[..],
                    &ec,
                    &[
                        "-extensions",
                        "leaf_ext",
                        "-subj",
                        subject,
                        "-CA",
                        "int.pem",
                        "-CAkey",
                        "intkey.pem",
                        "-keyout",
                        "key.pem",
                        "-out",
                        "leaf.pem",
                    ],
                ]
                .concat(),
                &dir,
            );
            let (theirs, text) = openssl(
                &[
                    "verify",
                    "-x509_strict",
                    "-CAfile",
                    "root.pem",
                    "-untrusted",
                    "int.pem",
                    "leaf.pem",
                ],
                &dir,
            );
            let leaf = read_cert(&dir, "leaf.pem");
            let opts = VerifyOptions::new(
                now(),
                Purpose::TlsServer,
                VERIFY_ALGORITHMS,
                Limits::DEFAULT,
            );
            let owned = verify_chain(&leaf, &[&int], &roots, &opts);
            let fixed = verify_chain_fixed(&leaf, &[&int], &roots, &opts);
            assert_eq!(
                owned.as_ref().err().map(|e| e.kind()),
                fixed.as_ref().err().map(|e| e.kind()),
                "{what}: the two validators disagree"
            );
            assert_eq!(theirs, *expected, "{what}: OpenSSL says {text}");
            assert_eq!(owned.is_ok(), *expected, "{what}: {:?}", owned.err());
            if !expected {
                // Refused for the constraint, not for something else.
                assert!(
                    text.contains("permitted subtree violation")
                        || text.contains("excluded subtree violation")
                        || text.contains("unsupported name constraint")
                        || text.contains("unsupported or invalid name"),
                    "{what}: {text}"
                );
                assert!(
                    matches!(
                        owned.unwrap_err().kind(),
                        ErrorKind::CertificateUsage | ErrorKind::UnsupportedCertificate
                    ),
                    "{what}"
                );
            }
            judged += 1;
        }
    }
    assert_eq!(judged, 63);
}
