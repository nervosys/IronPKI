//! The boundary to IronCrypto's signature code.
//!
//! Nothing here implements a signature: verification is `ic_sig::verify`,
//! and signing goes through whatever `ic_core::sig::Signer` the caller
//! holds. This module turns IronCrypto's errors into this crate's, and
//! limits the key types to the ones this crate's rules have been written
//! and tested for.

use alloc::vec::Vec;

use ic_core::sig::Signer;
use ic_core::traits::RandomSource;

use crate::error::{Error, ErrorKind, Result};

pub use ic_core::sig::SignatureAlgorithm;
pub use ic_sig::PublicKey;

/// The name the validator's code uses for an algorithm.
pub(crate) use ic_core::sig::SignatureAlgorithm as SignatureScheme;

#[cfg(test)]
pub(crate) use crate::testkey::{KeyKind, SigningKey};

/// OID content bytes for id-ml-dsa-44, 2.16.840.1.101.3.4.3.17 (RFC 9881).
pub(crate) const OID_ML_DSA_44: &[u8] = ic_pkix::oid::ML_DSA_44;
/// OID content bytes for id-ml-dsa-65, 2.16.840.1.101.3.4.3.18.
pub(crate) const OID_ML_DSA_65: &[u8] = ic_pkix::oid::ML_DSA_65;
/// OID content bytes for id-ml-dsa-87, 2.16.840.1.101.3.4.3.19.
pub(crate) const OID_ML_DSA_87: &[u8] = ic_pkix::oid::ML_DSA_87;

/// Every algorithm a certificate, CRL or OCSP response may be signed with
/// here, in a default preference order. SHA-1 is in none of them.
pub const VERIFY_ALGORITHMS: &[SignatureAlgorithm] = &[
    SignatureAlgorithm::MlDsa65,
    SignatureAlgorithm::MlDsa87,
    SignatureAlgorithm::Ed25519,
    SignatureAlgorithm::EcdsaP256Sha256,
    SignatureAlgorithm::EcdsaP384Sha384,
    SignatureAlgorithm::EcdsaP521Sha512,
    SignatureAlgorithm::RsaPssSha256,
    SignatureAlgorithm::RsaPssSha384,
    SignatureAlgorithm::RsaPssSha512,
    SignatureAlgorithm::RsaPkcs1Sha256,
    SignatureAlgorithm::RsaPkcs1Sha384,
    SignatureAlgorithm::RsaPkcs1Sha512,
    SignatureAlgorithm::MlDsa44,
];

#[cfg(test)]
pub(crate) const VERIFY_SCHEMES: &[SignatureAlgorithm] = VERIFY_ALGORITHMS;

/// Parse a DER `SubjectPublicKeyInfo` into a key this crate validates with:
/// ECDSA P-256, P-384 and P-521, Ed25519, RSA and ML-DSA. A malformed
/// structure is `bad-certificate`; a well-formed key of another kind is
/// `unsupported-certificate`.
pub(crate) fn public_key(spki: &[u8]) -> Result<PublicKey<'_>> {
    let key = PublicKey::from_spki(spki).map_err(|e| match e.kind() {
        ic_core::ErrorKind::Unsupported => Error::new(
            ErrorKind::UnsupportedCertificate,
            "unsupported public key algorithm",
        ),
        _ => Error::new(ErrorKind::BadCertificate, "malformed SubjectPublicKeyInfo"),
    })?;
    match key {
        PublicKey::EcP256(_)
        | PublicKey::EcP384(_)
        | PublicKey::EcP521(_)
        | PublicKey::Ed25519(_)
        | PublicKey::Rsa { .. }
        | PublicKey::MlDsa44(_)
        | PublicKey::MlDsa65(_)
        | PublicKey::MlDsa87(_) => Ok(key),
        _ => Err(Error::new(
            ErrorKind::UnsupportedCertificate,
            "unsupported public key algorithm",
        )),
    }
}

/// Verify `signature` over `message` with `key` under `algorithm`.
///
/// A signature that does not verify, for any reason, is `bad-signature`; a
/// key that is not a key for `algorithm` is `key-algorithm-mismatch`; an RSA
/// key outside the sizes IronCrypto accepts is `unsupported-certificate`.
pub(crate) fn verify(
    algorithm: SignatureAlgorithm,
    key: &PublicKey<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    ic_sig::verify(algorithm, key, message, signature).map_err(|e| match e.kind() {
        ic_core::ErrorKind::ModuleErrorState
        | ic_core::ErrorKind::SelfTestFailed
        | ic_core::ErrorKind::NotApprovedInFipsMode => Error::from(e),
        ic_core::ErrorKind::AuthenticationFailed => {
            Error::new(ErrorKind::BadSignature, "signature did not verify")
        }
        ic_core::ErrorKind::InvalidParameter => Error::new(
            ErrorKind::KeyAlgorithmMismatch,
            "signature algorithm does not match the key",
        ),
        ic_core::ErrorKind::Unsupported => {
            Error::new(ErrorKind::UnsupportedCertificate, "unusable RSA key")
        }
        _ => Error::new(ErrorKind::Crypto, e.context()),
    })
}

/// Sign `message` with `signer` under `algorithm`, returning the signature.
pub(crate) fn sign(
    signer: &dyn Signer,
    algorithm: SignatureAlgorithm,
    message: &[u8],
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let mut out = alloc::vec![0u8; algorithm.max_signature_len()];
    let n = signer
        .sign(algorithm, message, rng, &mut out)
        .map_err(|e| match e.kind() {
            ic_core::ErrorKind::InvalidParameter | ic_core::ErrorKind::InvalidLength => {
                Error::new(ErrorKind::InvalidConfig, "the signer refused the algorithm")
            }
            ic_core::ErrorKind::ModuleErrorState
            | ic_core::ErrorKind::SelfTestFailed
            | ic_core::ErrorKind::NotApprovedInFipsMode => Error::from(e),
            _ => Error::new(ErrorKind::Crypto, e.context()),
        })?;
    out.truncate(n);
    Ok(out)
}

/// Append a DER TLV with a definite length.
pub(crate) fn push_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        // Long form with as many length octets as the size needs (X.690
        // §8.1.3.5), so no length is ever truncated.
        let octets = (usize::BITS - n.leading_zeros()).div_ceil(8) as usize;
        out.push(0x80 | octets as u8);
        out.extend_from_slice(&n.to_be_bytes()[core::mem::size_of::<usize>() - octets..]);
    }
    out.extend_from_slice(body);
}
