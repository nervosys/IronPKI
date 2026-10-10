//! Keys for the tests, which issue the chains they validate.
//!
//! Signing is IronCrypto's: a key here is an `ic_sig::SoftwareSigner`, made
//! from fresh key material written out as PKCS#8. This module only generates
//! that material and gives the tests the few methods they call. It is test
//! code: nothing outside `#[cfg(test)]` can reach it.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use ic_core::sig::{Custody, Signer};
use ic_core::traits::RandomSource;
use ic_pkix::{KeyAlgorithm, MlDsaParameterSet, MlDsaPrivateKey, PrivateKeyInfo};
use ic_sig::SoftwareSigner;

use crate::error::{Error, ErrorKind, Result};
use crate::sign::SignatureScheme;

/// Key types [`SigningKey::generate`] can create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
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
    pub(crate) const ALL: &'static [KeyKind] = &[
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::EcdsaP521,
        Self::Ed25519,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
    ];

    /// The identifier a report gives a key of this kind.
    pub(crate) const fn id(self) -> &'static str {
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

/// A private key held in memory, signing through IronCrypto.
pub(crate) struct SigningKey(Box<SoftwareSigner>);

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningKey({})", self.kind_id())
    }
}

fn cfg(context: &'static str) -> Error {
    Error::new(ErrorKind::InvalidConfig, context)
}

impl SigningKey {
    fn from_pkcs8(der: &[u8]) -> Result<Self> {
        SoftwareSigner::from_pkcs8(der)
            .map(|s| Self(Box::new(s)))
            .map_err(|_| cfg("key material is not a usable private key"))
    }

    /// A fresh key of `kind`.
    pub(crate) fn generate(kind: KeyKind, rng: &mut dyn RandomSource) -> Result<Self> {
        let mut der = vec![0u8; 256];
        // A random scalar is out of range with negligible probability; try
        // again rather than fail a test on it.
        for _ in 0..64 {
            let mut secret = [0u8; 66];
            rng.fill(&mut secret)
                .map_err(|_| Error::new(ErrorKind::Crypto, "random source failed"))?;
            // A P-521 scalar has 521 bits: one in its first byte.
            if kind == KeyKind::EcdsaP521 {
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
            let written = match kind {
                KeyKind::EcdsaP256 => ec(KeyAlgorithm::EcP256, &secret[..32]).to_der(&mut der),
                KeyKind::EcdsaP384 => ec(KeyAlgorithm::EcP384, &secret[..48]).to_der(&mut der),
                KeyKind::EcdsaP521 => ec(KeyAlgorithm::EcP521, &secret[..66]).to_der(&mut der),
                KeyKind::Ed25519 => PrivateKeyInfo::Ed25519(&secret[..32]).to_der(&mut der),
                KeyKind::MlDsa44 => ml_dsa(MlDsaParameterSet::MlDsa44).to_der(&mut der),
                KeyKind::MlDsa65 => ml_dsa(MlDsaParameterSet::MlDsa65).to_der(&mut der),
                KeyKind::MlDsa87 => ml_dsa(MlDsaParameterSet::MlDsa87).to_der(&mut der),
            };
            let n = written.map_err(|_| cfg("could not encode the key"))?;
            if let Ok(key) = Self::from_pkcs8(&der[..n]) {
                return Ok(key);
            }
        }
        Err(Error::new(ErrorKind::Crypto, "could not generate a key"))
    }

    /// An RSA key IronCrypto generated.
    pub(crate) fn rsa(key: ic_rsa::RsaPrivateKey) -> Result<Self> {
        let no = |_| cfg("RSA key without its factors");
        let size = key.size();
        let half = size / 2;
        let mut modulus = vec![0u8; size];
        key.public_key().modulus_bytes(&mut modulus).map_err(no)?;
        let mut private_exponent = vec![0u8; size];
        key.exponent_bytes(&mut private_exponent).map_err(no)?;
        let (mut prime1, mut prime2) = (vec![0u8; half], vec![0u8; half]);
        key.prime_bytes(&mut prime1, &mut prime2).map_err(no)?;
        let (mut exponent1, mut exponent2, mut coefficient) =
            (vec![0u8; half], vec![0u8; half], vec![0u8; half]);
        key.crt_exponent_bytes(&mut exponent1, &mut exponent2, &mut coefficient)
            .map_err(no)?;
        let mut der = vec![0u8; 8 * size + 256];
        let n = PrivateKeyInfo::Rsa {
            modulus: &modulus,
            public_exponent: key.public_key().exponent(),
            private_exponent: &private_exponent,
            prime1: &prime1,
            prime2: &prime2,
            exponent1: &exponent1,
            exponent2: &exponent2,
            coefficient: &coefficient,
        }
        .to_der(&mut der)
        .map_err(|_| cfg("could not encode the RSA key"))?;
        Self::from_pkcs8(&der[..n])
    }

    /// DER `SubjectPublicKeyInfo` of the matching public key.
    pub(crate) fn spki(&self) -> &[u8] {
        self.0.public_key()
    }

    /// The identifier a report gives this key.
    pub(crate) fn kind_id(&self) -> &'static str {
        crate::sign::public_key(self.spki()).map_or("unknown", |k| k.kind_id())
    }

    /// The algorithms this key signs with, most preferred first.
    pub(crate) fn schemes(&self) -> &[SignatureScheme] {
        self.0.algorithms()
    }

    /// Sign `message` under `scheme`.
    pub(crate) fn sign(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>> {
        crate::sign::sign(&*self.0, scheme, message, rng)
    }
}

impl Signer for SigningKey {
    fn algorithms(&self) -> &[SignatureScheme] {
        self.0.algorithms()
    }

    fn public_key(&self) -> &[u8] {
        self.0.public_key()
    }

    fn custody(&self) -> Custody {
        self.0.custody()
    }

    fn sign(
        &self,
        algorithm: SignatureScheme,
        message: &[u8],
        rng: &mut dyn RandomSource,
        out: &mut [u8],
    ) -> ic_core::Result<usize> {
        self.0.sign(algorithm, message, rng, out)
    }
}
