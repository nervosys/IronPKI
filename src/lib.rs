//! The IronSecurity stack's certificate layer.
//!
//! The stack has two X.509 path validators today, one in IronSocketLayer and
//! one in IronPrivacyGuard, and certificate encoding and issuance in
//! IronCrypto's `ic-pkix`. IronPKI is where they become one.
//!
//! # Status
//!
//! The extraction is in progress. [`x509`] is IronSocketLayer 0.3.4's
//! certificate code, moved here with its tests: parsing, path validation,
//! name matching, CRLs, OCSP responses and issuance. It verifies through
//! IronCrypto's `ic-sig`, signs through any `ic_core::sig::Signer`, and has
//! its own [`Error`]. It still speaks in IronSocketLayer's terms: its
//! `Usage` knows only TLS server and client, and its bounds are constants.
//!
//! The types at the root are the contract the finished validator is to
//! meet: what a caller asks for ([`Purpose`]), what it supplies
//! ([`TrustAnchor`]), and the work bounds no input may exceed ([`Limits`]).
//! [`x509`] does not use them yet. See `docs/REQUIREMENTS.md`.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub mod sign;
#[cfg(test)]
mod testkey;
pub mod x509;

pub use error::{Error, ErrorKind, Result};

/// What a certificate path is validated for. A path valid for one purpose
/// says nothing about another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Purpose {
    /// A TLS server certificate (`id-kp-serverAuth`).
    TlsServer,
    /// A TLS client certificate (`id-kp-clientAuth`).
    TlsClient,
    /// A TPM endorsement-key certificate (`tcg-kp-EKCertificate`).
    TpmEndorsementKey,
}

impl Purpose {
    /// Every purpose, for callers that enumerate them.
    pub const ALL: &'static [Self] = &[Self::TlsServer, Self::TlsClient, Self::TpmEndorsementKey];

    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::TlsServer => "tls-server",
            Self::TlsClient => "tls-client",
            Self::TpmEndorsementKey => "tpm-endorsement-key",
        }
    }

    /// The purpose with this identifier.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.id() == id)
    }

    /// The extended-key-usage OID a leaf must carry for this purpose, as
    /// dotted decimal.
    pub const fn extended_key_usage(self) -> &'static str {
        match self {
            Self::TlsServer => "1.3.6.1.5.5.7.3.1",
            Self::TlsClient => "1.3.6.1.5.5.7.3.2",
            Self::TpmEndorsementKey => "2.23.133.8.1",
        }
    }
}

/// A trust anchor the caller has chosen. A validator never trusts a
/// certificate because the peer presented it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnchor<'a> {
    /// A complete DER certificate. Its dates are not checked (RFC 5280).
    Certificate(&'a [u8]),
    /// A key-form anchor, as root programs distribute them. Each field is a
    /// complete DER element, header included.
    Key {
        /// The subject `Name`.
        subject: &'a [u8],
        /// The `SubjectPublicKeyInfo`.
        spki: &'a [u8],
        /// The `NameConstraints` extension value, binding every path that
        /// ends at this anchor.
        name_constraints: Option<&'a [u8]>,
    },
}

/// Hard bounds on the work one validation may do. Inputs beyond a bound are
/// refused; a bound is never silently raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most certificates in a path below the trust anchor: the leaf is
    /// counted and the anchor is not.
    pub max_path_len: usize,
    /// The most intermediate candidates a caller may supply.
    pub max_candidates: usize,
    /// The most trust anchors a caller may supply.
    pub max_anchors: usize,
    /// The most signature verifications path building may spend.
    pub max_signature_checks: usize,
    /// The largest certificate accepted, in bytes.
    pub max_certificate_len: usize,
}

impl Limits {
    /// Bounds for offline validation of evidence the caller chose to examine.
    /// These are the ones IronPrivacyGuard's validator enforces today.
    pub const DEFAULT: Self = Self {
        max_path_len: 8,
        max_candidates: 64,
        max_anchors: 256,
        max_signature_checks: 256,
        max_certificate_len: 65_536,
    };

    /// Tighter bounds for a live handshake, where a peer chooses the chain
    /// and each signature check is work it can impose. These are the ones
    /// IronSocketLayer enforces today: three checks per level of depth.
    pub const ONLINE: Self = Self {
        max_signature_checks: 24,
        ..Self::DEFAULT
    };

    /// Whether every bound is usable: nonzero, with at least one signature
    /// check for each certificate in the longest path.
    pub const fn is_valid(&self) -> bool {
        self.max_path_len >= 1
            && self.max_candidates > 0
            && self.max_anchors > 0
            && self.max_signature_checks >= self.max_path_len
            && self.max_certificate_len > 0
    }

    /// Whether a request of this size is within the bounds.
    pub const fn admits(&self, anchors: usize, candidates: usize) -> bool {
        anchors >= 1 && anchors <= self.max_anchors && candidates <= self.max_candidates
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How revocation is treated. Fetching is never done by the validator: the
/// caller supplies CRLs or OCSP responses it obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Revocation {
    /// Revocation is not checked. The result says so.
    #[default]
    NotChecked,
    /// Check any CRL or OCSP response the caller supplied; absence is
    /// accepted.
    IfSupplied,
    /// Require valid, current revocation information for every certificate
    /// below the anchor.
    Required,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_round_trip_and_name_their_key_usage() {
        for purpose in Purpose::ALL {
            assert_eq!(Purpose::from_id(purpose.id()), Some(*purpose));
        }
        assert_eq!(Purpose::from_id("code-signing"), None);
        assert_eq!(
            Purpose::TpmEndorsementKey.extended_key_usage(),
            "2.23.133.8.1"
        );
        assert_eq!(Purpose::TlsServer.extended_key_usage(), "1.3.6.1.5.5.7.3.1");
    }

    #[test]
    fn default_limits_are_valid_and_bound_requests() {
        let limits = Limits::default();
        assert!(limits.is_valid());
        assert!(limits.admits(1, 0));
        assert!(limits.admits(256, 64));
        assert!(!limits.admits(0, 0), "a validation needs a trust anchor");
        assert!(!limits.admits(257, 0));
        assert!(!limits.admits(1, 65));
        let unusable = Limits {
            max_path_len: 0,
            ..Limits::DEFAULT
        };
        assert!(!unusable.is_valid());
        // The online preset only tightens the default.
        assert!(Limits::ONLINE.is_valid());
        assert_eq!(Limits::ONLINE.max_signature_checks, 24);
        assert_eq!(Limits::ONLINE.max_path_len, Limits::DEFAULT.max_path_len);
        let starved = Limits {
            max_signature_checks: 7,
            ..Limits::DEFAULT
        };
        assert!(!starved.is_valid());
    }

    #[test]
    fn revocation_is_not_checked_unless_asked() {
        assert_eq!(Revocation::default(), Revocation::NotChecked);
    }
}
