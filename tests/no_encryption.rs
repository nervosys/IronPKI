//! IronPKI encrypts and decrypts nothing (docs/EXPORT.md), and keys encrypted
//! at rest are IronCrypto's: `ic_pkix::pbes2`. This fails if `src/` grows its
//! own PBES2, or depends directly on the crates one would be built from.
//!
//! Transitive use through `ic-pkix` is fine; only IronPKI's own source and
//! direct dependencies are checked.

use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

/// The object identifiers a PBES2 implementation needs, with their DER
/// contents (X.690 §8.19).
const FORBIDDEN_OIDS: &[(&str, &str, &[u8])] = &[
    // RFC 8018 appendix A.4.
    (
        "PBES2",
        "1.2.840.113549.1.5.13",
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d],
    ),
    // RFC 8018 appendix A.2.
    (
        "PBKDF2",
        "1.2.840.113549.1.5.12",
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c],
    ),
    // RFC 8018 appendix B.1.2.
    (
        "HMAC-SHA-256",
        "1.2.840.113549.2.9",
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
    ),
    // NIST CSOR, aes256-CBC-PAD.
    (
        "AES-256-CBC",
        "2.16.840.1.101.3.4.1.42",
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a],
    ),
];

/// IronCrypto crates that would only be a direct dependency to encrypt.
const FORBIDDEN_DEPENDENCIES: &[&str] = &["ic-kdf", "ic-cipher", "ic-mac"];

/// Integer type suffixes, longest first so `u128` is not read as `u1` + `28`.
const SUFFIXES: &[&str] = &[
    "usize", "isize", "u128", "i128", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8",
];

/// Every integer literal in `text`, in order: `0x2a`, `42`, `42u8`, and the
/// `\x2a` escapes of byte strings. A DER encoding written as a byte array, in
/// hex, decimal or a mix of both, appears as a run of these.
fn integer_literals(text: &str) -> Vec<u64> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let word_start = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if b[i] == b'\\' && b.get(i + 1) == Some(&b'x') {
            let hex = text.get(i + 2..i + 4).unwrap_or("");
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        if word_start && b[i].is_ascii_digit() {
            let (radix, start) = if b[i] == b'0' && matches!(b.get(i + 1), Some(b'x' | b'X')) {
                (16, i + 2)
            } else {
                (10, i)
            };
            let mut end = start;
            while end < b.len() && (b[end].is_ascii_alphanumeric() || b[end] == b'_') {
                end += 1;
            }
            let mut literal = &text[start..end];
            for suffix in SUFFIXES {
                if let Some(s) = literal.strip_suffix(suffix) {
                    literal = s;
                    break;
                }
            }
            let digits: String = literal.chars().filter(|&c| c != '_').collect();
            if let Ok(v) = u64::from_str_radix(&digits, radix) {
                out.push(v);
            }
            i = end;
            continue;
        }
        i += 1;
    }
    out
}

/// `text` with whitespace, underscores and `0x` prefixes removed and the rest
/// lower-cased, so a DER encoding written as one hex string is found.
fn hex_run(text: &str) -> String {
    text.to_ascii_lowercase()
        .replace("0x", "")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .collect()
}

fn findings(text: &str) -> Vec<String> {
    let literals = integer_literals(text);
    let hex = hex_run(text);
    let mut out = Vec::new();
    for (name, dotted, der) in FORBIDDEN_OIDS {
        let der: Vec<u64> = der.iter().map(|&x| x as u64).collect();
        let der_hex: String = der.iter().map(|x| format!("{x:02x}")).collect();
        if text.contains(dotted) {
            out.push(format!("{name} {dotted}, dotted"));
        }
        if literals.windows(der.len()).any(|w| w == der.as_slice()) {
            out.push(format!("{name} {dotted}, as DER bytes"));
        }
        if hex.contains(&der_hex) {
            out.push(format!("{name} {dotted}, as a hex string"));
        }
    }
    out
}

#[test]
fn the_source_contains_no_pbes2() {
    let mut files = Vec::new();
    rust_files(&crate_dir().join("src"), &mut files);
    assert!(!files.is_empty());
    let mut found = Vec::new();
    for f in &files {
        for what in findings(&std::fs::read_to_string(f).unwrap()) {
            found.push(format!("{}: {what}", f.display()));
        }
    }
    assert!(
        found.is_empty(),
        "IronPKI encrypts nothing; keys encrypted at rest go through \
         ic_pkix::pbes2 (CONTRIBUTING.md):\n{}",
        found.join("\n")
    );
}

#[test]
fn no_direct_dependency_on_a_cipher_kdf_or_mac() {
    let manifest = std::fs::read_to_string(crate_dir().join("Cargo.toml")).unwrap();
    let mut section = String::new();
    let mut found = Vec::new();
    for line in manifest.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix('[') {
            section = header.trim_end_matches(']').trim().to_string();
            // [dependencies.ic-kdf], [target.'cfg(...)'.dev-dependencies.ic-mac]
            for dep in FORBIDDEN_DEPENDENCIES {
                if section.contains("dependencies.") && section.ends_with(&format!(".{dep}")) {
                    found.push(format!("[{section}]"));
                }
            }
            continue;
        }
        if !section.ends_with("dependencies") {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        for dep in FORBIDDEN_DEPENDENCIES {
            // A renamed dependency names its package.
            let renamed = value.contains(&format!("package = \"{dep}\""));
            if key == *dep || renamed {
                found.push(format!("[{section}] {key}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "IronPKI depends on no cipher, KDF or MAC crate directly; keys encrypted \
         at rest go through ic_pkix::pbes2 (CONTRIBUTING.md): {found:?}"
    );
}

#[test]
fn the_guard_finds_each_form() {
    // A guard that finds nothing verified nothing.
    let cases = [
        "const P: &str = \"1.2.840.113549.1.5.13\";",
        "const P: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];",
        "const P: &[u8] = &[42, 134, 72, 134, 247, 13, 2, 9];",
        "const P: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 1, 42u8];",
        "const P: &[u8] = b\"\\x60\\x86\\x48\\x01\\x65\\x03\\x04\\x01\\x2a\";",
        "const P: &str = \"2A864886F70D01050D\";",
    ];
    for case in cases {
        assert!(!findings(case).is_empty(), "missed: {case}");
    }
    // RSA with SHA-256 shares the PKCS prefix and is not encryption.
    assert!(findings("&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]").is_empty());
}
