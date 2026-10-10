//! Software keys for the tests, which issue the chains they validate.
//!
//! IronCrypto has no software implementation of `ic_core::sig::Signer` yet,
//! so the tests carry one. It is test code only: nothing outside
//! `#[cfg(test)]` can reach it, and it is to be replaced by IronCrypto's
//! when that exists.
#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use ic_core::sig::{Custody, Signer};

use ic_core::traits::{RandomSource, SignatureScheme as _};
use ic_core::{Zeroize, Zeroizing};
use ic_pkix::der::{self};

use crate::error::{Error, ErrorKind, Result};
use crate::sign::SignatureScheme;

/// OID content bytes for id-ml-dsa-44, 2.16.840.1.101.3.4.3.17 (RFC 9881).
pub const OID_ML_DSA_44: &[u8] = ic_pkix::oid::ML_DSA_44;
/// OID content bytes for id-ml-dsa-65, 2.16.840.1.101.3.4.3.18.
pub const OID_ML_DSA_65: &[u8] = ic_pkix::oid::ML_DSA_65;
/// OID content bytes for id-ml-dsa-87, 2.16.840.1.101.3.4.3.19.
pub const OID_ML_DSA_87: &[u8] = ic_pkix::oid::ML_DSA_87;

/// An ML-DSA parameter set (FIPS 204).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MlDsa {
    /// Category 2, available by explicit configuration.
    P44,
    /// Category 3.
    P65,
    /// Category 5, required by CNSA 2.0.
    P87,
}

/// Run `$body` with `$m` bound to the parameter set's IronCrypto module.
macro_rules! with_mldsa {
    ($p:expr, $m:ident, $body:expr) => {
        match $p {
            MlDsa::P44 => {
                use ic_mldsa::sign44 as $m;
                $body
            }
            MlDsa::P65 => {
                use ic_mldsa::sign as $m;
                $body
            }
            MlDsa::P87 => {
                use ic_mldsa::sign87 as $m;
                $body
            }
        }
    };
}

impl MlDsa {
    fn from_oid(oid: &[u8]) -> Option<Self> {
        if oid == OID_ML_DSA_44 {
            Some(Self::P44)
        } else if oid == OID_ML_DSA_65 {
            Some(Self::P65)
        } else if oid == OID_ML_DSA_87 {
            Some(Self::P87)
        } else {
            None
        }
    }

    fn oid(self) -> &'static [u8] {
        match self {
            Self::P44 => OID_ML_DSA_44,
            Self::P65 => OID_ML_DSA_65,
            Self::P87 => OID_ML_DSA_87,
        }
    }

    fn scheme(self) -> SignatureScheme {
        match self {
            Self::P44 => SignatureScheme::MlDsa44,
            Self::P65 => SignatureScheme::MlDsa65,
            Self::P87 => SignatureScheme::MlDsa87,
        }
    }

    fn kind_id(self) -> &'static str {
        match self {
            Self::P44 => "ml-dsa-44",
            Self::P65 => "ml-dsa-65",
            Self::P87 => "ml-dsa-87",
        }
    }

    fn public_len(self) -> usize {
        with_mldsa!(self, m, m::PUBLIC_KEY_LEN)
    }

    /// Key pair from the 32-byte seed `ξ` (FIPS 204): SPKI key bytes and the
    /// expanded secret key.
    fn keygen(self, seed: &[u8; 32]) -> Result<(Vec<u8>, SecretVec)> {
        with_mldsa!(self, m, {
            let mut pk = alloc::vec![0u8; m::PUBLIC_KEY_LEN];
            let mut sk = SecretVec::new(alloc::vec![0u8; m::SECRET_KEY_LEN]);
            let pk_arr: &mut [u8; m::PUBLIC_KEY_LEN] = pk
                .as_mut_slice()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ml-dsa pk length"))?;
            let sk_arr: &mut [u8; m::SECRET_KEY_LEN] = sk
                .get_mut()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ml-dsa sk length"))?;
            if !m::keygen(seed, pk_arr, sk_arr) {
                return Err(Error::new(
                    ErrorKind::Crypto,
                    "ml-dsa pairwise consistency test failed",
                ));
            }
            Ok((pk, sk))
        })
    }

    fn sign(self, sk: &[u8], message: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>> {
        with_mldsa!(self, m, {
            let sk: &[u8; m::SECRET_KEY_LEN] = sk
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ml-dsa sk length"))?;
            let mut sig = alloc::vec![0u8; m::SIGNATURE_LEN];
            let sig_arr: &mut [u8; m::SIGNATURE_LEN] = sig
                .as_mut_slice()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ml-dsa signature length"))?;
            if !m::sign(sk, message, b"", rnd, sig_arr) {
                return Err(Error::new(ErrorKind::Crypto, "ml-dsa signing failed"));
            }
            Ok(sig)
        })
    }

    #[inline(never)]
    fn verify(self, pk: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        with_mldsa!(self, m, {
            let pk: &[u8; m::PUBLIC_KEY_LEN] = pk
                .try_into()
                .map_err(|_| Error::new(ErrorKind::BadCertificate, "ml-dsa public key length"))?;
            let sig: &[u8; m::SIGNATURE_LEN] = signature
                .try_into()
                .map_err(|_| Error::new(ErrorKind::BadSignature, "ml-dsa signature length"))?;
            if m::verify(pk, message, b"", sig) {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::BadSignature,
                    "signature did not verify",
                ))
            }
        })
    }
}

enum KeyImpl {
    P256(Zeroizing<[u8; 32]>),
    P384(Zeroizing<[u8; 48]>),
    P521(Zeroizing<[u8; 66]>),
    Ed25519(Box<ic_ec::Ed25519Key>),
    Rsa(Box<ic_rsa::RsaPrivateKey>),
    /// The expanded secret key; `SecretVec` zeroizes it.
    MlDsa(MlDsa, SecretVec),
}

/// A private key that can sign handshakes. key bytes are
/// zeroized on drop.
pub struct SigningKey {
    inner: KeyImpl,
    /// DER `SubjectPublicKeyInfo` of the matching public key.
    spki: Vec<u8>,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningKey({})", self.kind_id())
    }
}

fn copy_fixed<const N: usize>(src: &[u8]) -> Result<Zeroizing<[u8; N]>> {
    if src.len() > N {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "private scalar too long",
        ));
    }
    // Left-pad: some encoders drop leading zero bytes from the scalar.
    let mut out = Zeroizing::new([0u8; N]);
    out.get_mut()[N - src.len()..].copy_from_slice(src);
    Ok(out)
}

fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Result<Vec<u8>> {
    let mut alg = Vec::new();
    push_tlv(&mut alg, der::OID, ic_pkix::oid::EC_PUBLIC_KEY);
    push_tlv(&mut alg, der::OID, curve_oid);
    spki_from_parts(&alg, point)
}

/// Build `SEQUENCE { SEQUENCE { alg }, BIT STRING key }`.
fn spki_from_parts(alg_body: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    push_tlv(&mut body, der::SEQUENCE, alg_body);
    let mut bits = Vec::with_capacity(key.len() + 1);
    bits.push(0);
    bits.extend_from_slice(key);
    push_tlv(&mut body, der::BIT_STRING, &bits);
    let mut out = Vec::new();
    push_tlv(&mut out, der::SEQUENCE, &body);
    Ok(out)
}

/// Append a DER TLV with a definite length.
pub fn push_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
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

impl SigningKey {
    /// Sign into caller storage using the initialized key.
    /// No allocation occurs; `out` must accommodate the scheme's largest signature.
    pub fn sign_into(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        rng: &mut dyn RandomSource,
        out: &mut [u8],
    ) -> Result<usize> {
        if !self.schemes().contains(&scheme) {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "scheme does not fit signing key",
            ));
        }
        let capacity = || Error::new(ErrorKind::CapacityExceeded, "signature storage");
        match &self.inner {
            KeyImpl::P256(sk) => {
                if out.len() < ic_pkix::ecdsa_signature::max_der_len(64) {
                    return Err(capacity());
                }
                let mut sig = [0u8; 64];
                ic_ec::EcdsaP256Sha256::sign(sk.get(), message, &mut sig)?;
                Ok(ic_pkix::ecdsa_signature::to_der(&sig, out)?)
            }
            KeyImpl::P384(sk) => {
                if out.len() < ic_pkix::ecdsa_signature::max_der_len(96) {
                    return Err(capacity());
                }
                let mut sig = [0u8; 96];
                ic_ec::EcdsaP384Sha384::sign(sk.get(), message, &mut sig)?;
                Ok(ic_pkix::ecdsa_signature::to_der(&sig, out)?)
            }
            KeyImpl::P521(sk) => {
                if out.len() < ic_pkix::ecdsa_signature::max_der_len(132) {
                    return Err(capacity());
                }
                let mut sig = [0u8; 132];
                ic_ec::p521::EcdsaP521Sha512::sign(sk.get(), message, &mut sig)?;
                Ok(ic_pkix::ecdsa_signature::to_der(&sig, out)?)
            }
            KeyImpl::Ed25519(k) => {
                k.sign(message, out.get_mut(..64).ok_or_else(capacity)?)?;
                Ok(64)
            }
            KeyImpl::Rsa(k) => {
                let sig = out.get_mut(..k.size()).ok_or_else(capacity)?;
                let mut rng = RngRef(rng);
                match scheme {
                    SignatureScheme::RsaPssSha256 => {
                        ic_rsa::PssSha256::sign(k, message, &mut rng, sig)?
                    }
                    SignatureScheme::RsaPssSha384 => {
                        ic_rsa::PssSha384::sign(k, message, &mut rng, sig)?
                    }
                    SignatureScheme::RsaPssSha512 => {
                        ic_rsa::PssSha512::sign(k, message, &mut rng, sig)?
                    }
                    _ => return Err(Error::new(ErrorKind::InvalidConfig, "TLS RSA scheme")),
                }
                Ok(sig.len())
            }
            KeyImpl::MlDsa(p, sk) => {
                let mut rnd = Zeroizing::new([0u8; 32]);
                fill_random(rng, rnd.get_mut())?;
                with_mldsa!(*p, m, {
                    let sig = out.get_mut(..m::SIGNATURE_LEN).ok_or_else(capacity)?;
                    let sig_arr = (&mut *sig).try_into().map_err(|_| capacity())?;
                    let sk = sk
                        .get()
                        .try_into()
                        .map_err(|_| Error::new(ErrorKind::Internal, "ML-DSA key length"))?;
                    if !m::sign(sk, message, b"", rnd.get(), sig_arr) {
                        return Err(Error::new(ErrorKind::Crypto, "ML-DSA signing failed"));
                    }
                    Ok(m::SIGNATURE_LEN)
                })
            }
        }
    }

    /// Load a PKCS#8 `PrivateKeyInfo` (DER).
    ///
    /// Accepts P-256, P-384, P-521, Ed25519, RSA (2048–4096 bits), and
    /// ML-DSA-65 in the seed form of draft-ietf-lamps-dilithium-certificates,
    /// or seed and expanded key together, which must agree.
    pub fn from_pkcs8_der(der_bytes: &[u8]) -> Result<Self> {
        // ic_pkix reads the PrivateKeyInfo; a file it refuses is malformed.
        // ML-DSA, which PrivateKeyInfo reports as unsupported, has its own
        // reader in ic_pkix.
        let parsed = ic_pkix::PrivateKeyInfo::from_der(der_bytes)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "malformed PKCS#8 private key"))?;
        match parsed {
            ic_pkix::PrivateKeyInfo::Ec {
                algorithm,
                private_key,
                ..
            } => match algorithm {
                ic_pkix::KeyAlgorithm::EcP256 => Self::ecdsa_p256(private_key),
                ic_pkix::KeyAlgorithm::EcP384 => Self::ecdsa_p384(private_key),
                ic_pkix::KeyAlgorithm::EcP521 => Self::ecdsa_p521(private_key),
                _ => Err(Error::new(ErrorKind::InvalidConfig, "unsupported curve")),
            },
            ic_pkix::PrivateKeyInfo::Ed25519(seed) => Self::ed25519(seed),
            ic_pkix::PrivateKeyInfo::Rsa {
                prime1,
                prime2,
                public_exponent,
                ..
            } => {
                // From the primes, so a file whose CRT values disagree with them
                // cannot produce a faulty signature that leaks the factorization.
                let key = ic_rsa::RsaPrivateKey::from_primes(prime1, prime2, public_exponent)
                    .map_err(|_| Error::new(ErrorKind::InvalidConfig, "rsa key rejected"))?;
                Self::rsa(key)
            }
            ic_pkix::PrivateKeyInfo::X25519(_) => Err(Error::new(
                ErrorKind::InvalidConfig,
                "an X25519 key agrees keys; it cannot sign",
            )),
            ic_pkix::PrivateKeyInfo::Unsupported { oid } if MlDsa::from_oid(oid).is_some() => {
                Self::from_pkcs8_mldsa(der_bytes)
            }
            ic_pkix::PrivateKeyInfo::Unsupported { .. } => Err(Error::new(
                ErrorKind::InvalidConfig,
                "unsupported private key algorithm",
            )),
        }
    }

    /// Load a PEM `PRIVATE KEY` (PKCS#8) block.
    pub fn from_pem(text: &str) -> Result<Self> {
        let mut der_buf = Zeroizing::new([0u8; 8192]);
        let n = ic_pkix::pem::decode(
            ic_pkix::pem::PRIVATE_KEY,
            text.as_bytes(),
            der_buf.get_mut(),
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::InvalidConfig,
                "no PEM PRIVATE KEY block (PKCS#8 expected)",
            )
        })?;
        Self::from_pkcs8_der(&der_buf.get()[..n])
    }

    /// ML-DSA PKCS#8 (RFC 9881), parsed by `ic_pkix::MlDsaPrivateKey`. The
    /// seed is required: the key is rebuilt from it, and a file that also
    /// carries the expanded key must match it, so a file whose two halves
    /// disagree is refused rather than half-trusted. The expanded-only form is
    /// refused, since nothing here could check it.
    fn from_pkcs8_mldsa(der_bytes: &[u8]) -> Result<Self> {
        // The algorithm is ML-DSA, so any refusal here (attributes,
        // parameters, a wrong length, an unknown form) is a malformed file.
        let parsed = ic_pkix::MlDsaPrivateKey::from_der(der_bytes)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "malformed PKCS#8 private key"))?;
        let p = match parsed.parameter_set() {
            ic_pkix::MlDsaParameterSet::MlDsa44 => MlDsa::P44,
            ic_pkix::MlDsaParameterSet::MlDsa65 => MlDsa::P65,
            ic_pkix::MlDsaParameterSet::MlDsa87 => MlDsa::P87,
        };
        let seed: &[u8; 32] = parsed
            .seed()
            .ok_or(Error::new(
                ErrorKind::InvalidConfig,
                "ML-DSA private key without its seed: the expanded-only form cannot be checked",
            ))?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "ML-DSA seed must be 32 bytes"))?;
        let key = Self::mldsa_from_seed(p, seed)?;
        if let (Some(expanded), KeyImpl::MlDsa(_, sk)) = (parsed.expanded_key(), &key.inner)
            && !ic_core::ct::verify(sk.get(), expanded)
        {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "ML-DSA expanded key does not match its seed",
            ));
        }
        Ok(key)
    }

    /// An ECDSA P-256 key from its 32-byte scalar.
    pub fn ecdsa_p256(scalar: &[u8]) -> Result<Self> {
        let sk = copy_fixed::<32>(scalar)?;
        let mut pk = [0u8; 65];
        ic_ec::EcdsaP256Sha256::public_key(sk.get(), &mut pk)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "invalid P-256 scalar"))?;
        Ok(Self {
            spki: ec_spki(ic_pkix::oid::P256, &pk)?,
            inner: KeyImpl::P256(sk),
        })
    }

    /// An ECDSA P-384 key from its 48-byte scalar.
    pub fn ecdsa_p384(scalar: &[u8]) -> Result<Self> {
        let sk = copy_fixed::<48>(scalar)?;
        let mut pk = [0u8; 97];
        ic_ec::EcdsaP384Sha384::public_key(sk.get(), &mut pk)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "invalid P-384 scalar"))?;
        Ok(Self {
            spki: ec_spki(ic_pkix::oid::P384, &pk)?,
            inner: KeyImpl::P384(sk),
        })
    }

    /// An ECDSA P-521 key from its 66-byte scalar.
    pub fn ecdsa_p521(scalar: &[u8]) -> Result<Self> {
        let sk = copy_fixed::<66>(scalar)?;
        let mut pk = [0u8; 133];
        ic_ec::p521::EcdsaP521Sha512::public_key(sk.get(), &mut pk)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "invalid P-521 scalar"))?;
        Ok(Self {
            spki: ec_spki(OID_P521, &pk)?,
            inner: KeyImpl::P521(sk),
        })
    }

    /// An Ed25519 key from its 32-byte seed.
    pub fn ed25519(seed: &[u8]) -> Result<Self> {
        let key = ic_ec::Ed25519Key::from_seed(seed)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "invalid Ed25519 seed"))?;
        let mut alg = Vec::new();
        push_tlv(&mut alg, der::OID, ic_pkix::oid::ED25519);
        let spki = spki_from_parts(&alg, key.public_key())?;
        Ok(Self {
            spki,
            inner: KeyImpl::Ed25519(Box::new(key)),
        })
    }

    /// An RSA key.
    pub fn rsa(key: ic_rsa::RsaPrivateKey) -> Result<Self> {
        let size = key.size();
        let mut modulus = alloc::vec![0u8; size];
        key.public_key().modulus_bytes(&mut modulus)?;
        let mut rsa_pub = alloc::vec![0u8; size + 32];
        let n = ic_pkix::write_rsa_public_key(&modulus, key.public_key().exponent(), &mut rsa_pub)?;
        let mut alg = Vec::new();
        push_tlv(&mut alg, der::OID, ic_pkix::oid::RSA_ENCRYPTION);
        push_tlv(&mut alg, der::NULL, &[]);
        // ic_pkix's writer builds from the end of the buffer, and `finish`
        // then moves the result to the front.
        let spki = spki_from_parts(&alg, &rsa_pub[..n])?;
        Ok(Self {
            spki,
            inner: KeyImpl::Rsa(Box::new(key)),
        })
    }

    /// An ML-DSA-44 key from its 32-byte seed (FIPS 204 `ξ`).
    /// ML-DSA-44 generation, key loading, signing and verification
    /// use IronCrypto's category 2 parameter set and RFC 9881 identifiers.
    pub fn mldsa44_from_seed(seed: &[u8; 32]) -> Result<Self> {
        Self::mldsa_from_seed(MlDsa::P44, seed)
    }

    /// An ML-DSA-65 key from its 32-byte seed (FIPS 204 `ξ`).
    pub fn mldsa65_from_seed(seed: &[u8; 32]) -> Result<Self> {
        Self::mldsa_from_seed(MlDsa::P65, seed)
    }

    /// An ML-DSA-87 key from its 32-byte seed (FIPS 204 `ξ`).
    pub fn mldsa87_from_seed(seed: &[u8; 32]) -> Result<Self> {
        Self::mldsa_from_seed(MlDsa::P87, seed)
    }

    fn mldsa_from_seed(p: MlDsa, seed: &[u8; 32]) -> Result<Self> {
        let (pk, sk) = p.keygen(seed)?;
        let mut alg = Vec::new();
        push_tlv(&mut alg, der::OID, p.oid());
        let spki = spki_from_parts(&alg, &pk)?;
        Ok(Self {
            spki,
            inner: KeyImpl::MlDsa(p, sk),
        })
    }

    /// Generate a fresh key of the given kind. Used by tests and by agents
    /// provisioning ephemeral identities.
    pub fn generate(kind: KeyKind, rng: &mut dyn RandomSource) -> Result<Self> {
        let mut seed = SecretVec::new(alloc::vec![0u8; 66]);
        for _ in 0..64 {
            fill_random(rng, seed.get_mut())?;
            let s = seed.get();
            let r = match kind {
                KeyKind::EcdsaP256 => Self::ecdsa_p256(&s[..32]),
                KeyKind::EcdsaP384 => Self::ecdsa_p384(&s[..48]),
                KeyKind::EcdsaP521 => {
                    let mut k = [0u8; 66];
                    k.copy_from_slice(&s[..66]);
                    k[0] &= 0x01;
                    let r = Self::ecdsa_p521(&k);
                    k.zeroize();
                    r
                }
                KeyKind::Ed25519 => Self::ed25519(&s[..32]),
                KeyKind::MlDsa44 | KeyKind::MlDsa65 | KeyKind::MlDsa87 => {
                    let p = match kind {
                        KeyKind::MlDsa44 => MlDsa::P44,
                        KeyKind::MlDsa65 => MlDsa::P65,
                        _ => MlDsa::P87,
                    };
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&s[..32]);
                    let r = Self::mldsa_from_seed(p, &k);
                    k.zeroize();
                    r
                }
            };
            if let Ok(key) = r {
                return Ok(key);
            }
        }
        Err(Error::new(ErrorKind::Crypto, "could not generate a key"))
    }

    /// DER `SubjectPublicKeyInfo` of the public half.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// A short identifier for reports.
    pub fn kind_id(&self) -> &'static str {
        match &self.inner {
            KeyImpl::P256(_) => "ecdsa-p256",
            KeyImpl::P384(_) => "ecdsa-p384",
            KeyImpl::P521(_) => "ecdsa-p521",
            KeyImpl::Ed25519(_) => "ed25519",
            KeyImpl::Rsa(_) => "rsa",
            KeyImpl::MlDsa(p, _) => p.kind_id(),
        }
    }

    /// Schemes this key can sign a handshake with, most preferred first.
    /// never PKCS#1 v1.5.
    pub fn schemes(&self) -> &'static [SignatureScheme] {
        use SignatureScheme as S;
        match &self.inner {
            KeyImpl::P256(_) => &[S::EcdsaP256Sha256],
            KeyImpl::P384(_) => &[S::EcdsaP384Sha384],
            KeyImpl::P521(_) => &[S::EcdsaP521Sha512],
            KeyImpl::Ed25519(_) => &[S::Ed25519],
            KeyImpl::Rsa(_) => &[S::RsaPssSha256, S::RsaPssSha384, S::RsaPssSha512],
            KeyImpl::MlDsa(MlDsa::P44, _) => &[S::MlDsa44],
            KeyImpl::MlDsa(MlDsa::P65, _) => &[S::MlDsa65],
            KeyImpl::MlDsa(MlDsa::P87, _) => &[S::MlDsa87],
        }
    }

    /// The first scheme this key supports that the peer offered and `allowed`
    /// permits, in this key's preference order.
    pub fn choose_scheme(
        &self,
        offered: &[SignatureScheme],
        allowed: &[SignatureScheme],
    ) -> Option<SignatureScheme> {
        self.schemes()
            .iter()
            .copied()
            .find(|s| offered.contains(s) && allowed.contains(s))
    }

    /// Sign `message` under `scheme`, producing TLS wire form.
    pub fn sign(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>> {
        if !self.schemes().contains(&scheme) {
            return Err(Error::new(
                ErrorKind::Internal,
                "scheme not supported by this key",
            ));
        }
        let ecdsa_der = |fixed: &[u8]| -> Result<Vec<u8>> {
            let mut der_buf = alloc::vec![0u8; ic_pkix::ecdsa_signature::max_der_len(fixed.len())];
            let n = ic_pkix::ecdsa_signature::to_der(fixed, &mut der_buf)?;
            der_buf.truncate(n);
            Ok(der_buf)
        };
        match &self.inner {
            KeyImpl::P256(sk) => {
                let mut sig = [0u8; 64];
                ic_ec::EcdsaP256Sha256::sign(sk.get(), message, &mut sig)?;
                ecdsa_der(&sig)
            }
            KeyImpl::P384(sk) => {
                let mut sig = [0u8; 96];
                ic_ec::EcdsaP384Sha384::sign(sk.get(), message, &mut sig)?;
                ecdsa_der(&sig)
            }
            KeyImpl::P521(sk) => {
                let mut sig = [0u8; 132];
                ic_ec::p521::EcdsaP521Sha512::sign(sk.get(), message, &mut sig)?;
                ecdsa_der(&sig)
            }
            KeyImpl::Ed25519(k) => {
                let mut sig = alloc::vec![0u8; 64];
                k.sign(message, &mut sig)?;
                Ok(sig)
            }
            KeyImpl::Rsa(k) => {
                let mut sig = alloc::vec![0u8; k.size()];
                let mut rng = RngRef(rng);
                match scheme {
                    SignatureScheme::RsaPssSha256 => {
                        ic_rsa::PssSha256::sign(k, message, &mut rng, &mut sig)?
                    }
                    SignatureScheme::RsaPssSha384 => {
                        ic_rsa::PssSha384::sign(k, message, &mut rng, &mut sig)?
                    }
                    SignatureScheme::RsaPssSha512 => {
                        ic_rsa::PssSha512::sign(k, message, &mut rng, &mut sig)?
                    }
                    _ => return Err(Error::new(ErrorKind::Internal, "rsa scheme")),
                }
                Ok(sig)
            }
            KeyImpl::MlDsa(p, sk) => {
                // Hedged signing: fresh randomness per FIPS 204 §3.4.
                let mut rnd = Zeroizing::new([0u8; 32]);
                fill_random(rng, rnd.get_mut())?;
                debug_assert_eq!(p.scheme(), scheme);
                p.sign(sk.get(), message, rnd.get())
            }
        }
    }
}

struct RngRef<'a>(&'a mut dyn RandomSource);

impl RandomSource for RngRef<'_> {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        self.0.fill(out)
    }
}

/// Key types [`SigningKey::generate`] can create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// ECDSA P-256.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// ECDSA P-521.
    EcdsaP521,
    /// Ed25519.
    Ed25519,
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

impl KeyKind {
    /// Every kind.
    pub const ALL: &'static [KeyKind] = &[
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::EcdsaP521,
        Self::Ed25519,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
    ];

    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
            Self::EcdsaP521 => "ecdsa-p521",
            Self::Ed25519 => "ed25519",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }
}

/// Secret bytes, wiped when dropped.
pub(crate) struct SecretVec(Vec<u8>);

impl SecretVec {
    fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    fn get(&self) -> &[u8] {
        &self.0
    }

    fn get_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

fn fill_random(rng: &mut dyn RandomSource, out: &mut [u8]) -> Result<()> {
    rng.fill(out)
        .map_err(|_| Error::new(ErrorKind::Crypto, "random source failed"))
}

/// OID content bytes for secp521r1, 1.3.132.0.35.
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

impl Signer for SigningKey {
    fn algorithms(&self) -> &[SignatureScheme] {
        self.schemes()
    }

    fn public_key(&self) -> &[u8] {
        self.spki()
    }

    fn custody(&self) -> Custody {
        Custody::Software
    }

    fn sign(
        &self,
        algorithm: SignatureScheme,
        message: &[u8],
        rng: &mut dyn RandomSource,
        out: &mut [u8],
    ) -> ic_core::Result<usize> {
        // Through the allocating path: `sign_into` asks for one byte more
        // than a P-521 signature can need.
        let signature = SigningKey::sign(self, algorithm, message, rng)
            .map_err(|_| ic_core::Error::new(ic_core::ErrorKind::InvalidParameter, "test key"))?;
        out.get_mut(..signature.len())
            .ok_or(ic_core::Error::new(
                ic_core::ErrorKind::InvalidLength,
                "signature storage",
            ))?
            .copy_from_slice(&signature);
        Ok(signature.len())
    }
}
