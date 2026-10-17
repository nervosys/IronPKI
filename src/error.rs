//! Errors: a kind to branch on and a fixed context string to read.

use core::fmt;

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A certificate, name or key is malformed, or a signature on a
    /// certificate did not verify.
    BadCertificate,
    /// A certificate is well formed but uses something this library does
    /// not implement: a key type, a signature algorithm, a critical
    /// extension, a name-constraint form.
    UnsupportedCertificate,
    /// A certificate is outside its validity period.
    CertificateExpired,
    /// A certificate has been revoked.
    CertificateRevoked,
    /// A certificate may not be used this way: wrong purpose, not a CA,
    /// a path-length or name constraint violated.
    CertificateUsage,
    /// The certificate does not cover the name asked for.
    CertificateNameMismatch,
    /// No path leads to a trust anchor.
    UnknownCa,
    /// Revocation information is missing, stale, malformed or not
    /// authentic.
    BadCertificateStatus,
    /// The caller's policy refuses it: a signature algorithm not allowed, a
    /// key below the minimum size.
    PolicyViolation,
    /// A signature did not verify.
    BadSignature,
    /// A key was used with an algorithm it is not a key for.
    KeyAlgorithmMismatch,
    /// An argument the caller supplied is unusable.
    InvalidConfig,
    /// The input needs more than the bounds allow.
    CapacityExceeded,
    /// A cryptographic operation failed for a reason other than the input
    /// or the module's state, such as the random source failing.
    Crypto,
    /// REQ-ERR-001: IronCrypto refused because of the module's state: it is
    /// in its error state, its self-tests failed, or the algorithm is not
    /// approved in its approved mode. Not the input's fault, and nothing
    /// else is tried once it is seen: no other path, CRL or responder.
    ModuleState,
    /// A bug in this library.
    Internal,
}

impl ErrorKind {
    /// Every kind, for callers that enumerate them.
    pub const ALL: &'static [Self] = &[
        Self::BadCertificate,
        Self::UnsupportedCertificate,
        Self::CertificateExpired,
        Self::CertificateRevoked,
        Self::CertificateUsage,
        Self::CertificateNameMismatch,
        Self::UnknownCa,
        Self::BadCertificateStatus,
        Self::PolicyViolation,
        Self::BadSignature,
        Self::KeyAlgorithmMismatch,
        Self::InvalidConfig,
        Self::CapacityExceeded,
        Self::Crypto,
        Self::ModuleState,
        Self::Internal,
    ];

    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::BadCertificate => "bad-certificate",
            Self::UnsupportedCertificate => "unsupported-certificate",
            Self::CertificateExpired => "certificate-expired",
            Self::CertificateRevoked => "certificate-revoked",
            Self::CertificateUsage => "certificate-usage",
            Self::CertificateNameMismatch => "certificate-name-mismatch",
            Self::UnknownCa => "unknown-ca",
            Self::BadCertificateStatus => "bad-certificate-status",
            Self::PolicyViolation => "policy-violation",
            Self::BadSignature => "bad-signature",
            Self::KeyAlgorithmMismatch => "key-algorithm-mismatch",
            Self::InvalidConfig => "invalid-config",
            Self::CapacityExceeded => "capacity-exceeded",
            Self::Crypto => "crypto",
            Self::ModuleState => "module-state",
            Self::Internal => "internal",
        }
    }
}

/// An error: a kind and a static context string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    context: &'static str,
}

impl Error {
    /// Construct an error.
    pub const fn new(kind: ErrorKind, context: &'static str) -> Self {
        Self { kind, context }
    }

    /// What went wrong.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Where it went wrong, as fixed text.
    pub const fn context(&self) -> &'static str {
        self.context
    }

    /// The stable identifier of the kind.
    pub const fn id(&self) -> &'static str {
        self.kind.id()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.id(), self.context)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// A failure inside IronCrypto while handling a certificate. The two that
/// are about the input keep their meaning; the rest are not the input's
/// fault.
impl From<ic_core::Error> for Error {
    fn from(e: ic_core::Error) -> Self {
        use ic_core::ErrorKind as K;
        let kind = match e.kind() {
            K::AuthenticationFailed => ErrorKind::BadSignature,
            K::ModuleErrorState | K::SelfTestFailed | K::NotApprovedInFipsMode => {
                ErrorKind::ModuleState
            }
            K::MalformedEncoding => ErrorKind::BadCertificate,
            K::Unsupported => ErrorKind::UnsupportedCertificate,
            K::InvalidLength | K::InvalidParameter => ErrorKind::KeyAlgorithmMismatch,
            _ => ErrorKind::Crypto,
        };
        Error::new(kind, e.context())
    }
}

/// The result of a fallible operation in this crate.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn identifiers_are_unique_and_lead_the_text() {
        for (i, a) in ErrorKind::ALL.iter().enumerate() {
            for b in &ErrorKind::ALL[i + 1..] {
                assert_ne!(a.id(), b.id());
            }
        }
        assert_eq!(
            Error::new(ErrorKind::UnknownCa, "x").to_string(),
            "unknown-ca: x"
        );
    }
}
