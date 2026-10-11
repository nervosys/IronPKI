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
