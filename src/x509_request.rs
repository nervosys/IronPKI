//! Certificate requests: PKCS#10 (RFC 2986), read and made.
//!
//! A CA reads a request with [`CertificateRequest::parse`], checks with
//! [`CertificateRequest::verify`] that it was signed by the key it names,
//! which shows the requester holds that key, and then decides what to issue.
//! Nothing a request asks for is issued by itself: the CA builds
//! [`CertificateParams`](super::CertificateParams) from what it accepts of
//! the request, and passes [`CertificateRequest::spki_der`] to
//! [`issue`](super::issue).
//!
//! Of the request's attributes, only `extensionRequest` (PKCS#9, RFC 2985
//! section 5.4.2) is read; its extensions are held to the same rules as a
//! certificate's. Other attributes, such as a challenge password, are
//! checked for their shape and otherwise passed over: they ask nothing a
//! CA has to act on.

use alloc::vec::Vec;

use ic_core::sig::Signer;
use ic_core::traits::RandomSource;

use super::{
    Der, Extensions, IpAddr, OID_EXT_SAN, T_BIT_STRING, T_GN_DNS, T_GN_IP, T_GN_URI, T_INTEGER,
    T_OID, T_SEQUENCE, T_SET, alg_id, bad, check_algorithm_identifier_encoding, check_oid_encoding,
    check_rdn_sequence, check_subject_public_key_info, encode_name, for_each_san,
    is_valid_certificate_uri, is_valid_dns_name, name_common_name, parse_extensions, push_ext,
    push_tlv, rsa_bits, scheme_from_alg, whole_bits,
};
use crate::error::{Error, ErrorKind, Result};
use crate::sign::{self, PublicKey, SignatureScheme};

/// pkcs-9-at-extensionRequest, 1.2.840.113549.1.9.14.
const OID_EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];

/// The `[0] IMPLICIT` tag of a request's attributes.
const T_ATTRIBUTES: u8 = 0xa0;

/// The most attributes a request may carry.
const MAX_ATTRIBUTES: usize = 16;

/// A parsed PKCS#10 certificate request, borrowing from its DER.
#[derive(Debug, Clone)]
pub struct CertificateRequest<'a> {
    der: &'a [u8],
    info: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    sig_alg: &'a [u8],
    signature: &'a [u8],
    ext: Extensions<'a>,
    extensions: Option<&'a [u8]>,
}

impl<'a> CertificateRequest<'a> {
    /// Parse a DER `CertificationRequest`. `REQ-CSR-001`: the encoding is
    /// held to DER and to RFC 2986: version 1 (encoded 0), a subject Name
    /// whose attributes are valid, a SubjectPublicKeyInfo, attributes in
    /// DER order with one value or more each, at most one
    /// `extensionRequest` with exactly one value, a signature algorithm and
    /// a signature without unused bits. Requested extensions are held to
    /// the rules for a certificate's. Anything malformed is
    /// [`ErrorKind::BadCertificate`], never a panic.
    pub fn parse(der: &'a [u8]) -> Result<Self> {
        let mut outer = Der::new(der);
        let mut request = outer.nested(T_SEQUENCE)?;
        outer.finish()?;
        let info = request.expect_raw(T_SEQUENCE)?;
        let sig_alg = request.expect(T_SEQUENCE)?;
        check_algorithm_identifier_encoding(sig_alg)?;
        let signature = whole_bits(request.expect(T_BIT_STRING)?)?;
        request.finish()?;

        let mut fields = Der::new(info).nested(T_SEQUENCE)?;
        if fields.expect(T_INTEGER)? != [0] {
            return Err(bad("certificate request version is not 1"));
        }
        let subject = fields.expect_raw(T_SEQUENCE)?;
        check_rdn_sequence(Der::new(subject).expect(T_SEQUENCE)?)?;
        let spki = fields.expect_raw(T_SEQUENCE)?;
        check_subject_public_key_info(spki)?;
        let attributes = fields.expect(T_ATTRIBUTES)?;
        fields.finish()?;

        let mut extensions = None;
        let mut list = Der::new(attributes);
        let mut previous: Option<&[u8]> = None;
        let mut count = 0;
        while !list.is_empty() {
            count += 1;
            if count > MAX_ATTRIBUTES {
                return Err(bad("too many certificate request attributes"));
            }
            let encoded = list.expect_raw(T_SEQUENCE)?;
            // SET OF in DER order (X.690 section 11.6).
            if previous.is_some_and(|prev| prev > encoded) {
                return Err(bad("certificate request attributes are not in DER order"));
            }
            previous = Some(encoded);
            let mut attribute = Der::new(encoded).nested(T_SEQUENCE)?;
            let kind = attribute.expect(T_OID)?;
            check_oid_encoding(kind)?;
            let values = attribute.expect(T_SET)?;
            attribute.finish()?;
            if values.is_empty() {
                return Err(bad("certificate request attribute without a value"));
            }
            let mut each = Der::new(values);
            if kind == OID_EXTENSION_REQUEST {
                if extensions.is_some() {
                    return Err(bad("two extensionRequest attributes"));
                }
                let value = each.expect_raw(T_SEQUENCE)?;
                if !each.is_empty() {
                    return Err(bad("extensionRequest with more than one value"));
                }
                extensions = Some(value);
            } else {
                while !each.is_empty() {
                    each.any()?;
                }
            }
        }
        let ext = match extensions {
            Some(value) => parse_extensions(value)?,
            None => Extensions::default(),
        };
        Ok(Self {
            der,
            info,
            subject,
            spki,
            sig_alg,
            signature,
            ext,
            extensions,
        })
    }

    /// Check the request's signature with the key it names, under one of
    /// `allowed`: that whoever made the request holds the private key.
    /// Returns the algorithm. `REQ-CSR-002`: an algorithm outside `allowed`
    /// is [`ErrorKind::PolicyViolation`], as is an RSA key under 2048 bits;
    /// a signature that does not verify is [`ErrorKind::BadSignature`].
    ///
    /// ECDSA is verified only with each curve's own hash, as for
    /// certificates: P-256 with SHA-256, P-384 with SHA-384, P-521 with
    /// SHA-512. Another pairing is [`ErrorKind::UnsupportedCertificate`].
    /// OpenSSL signs a request with SHA-256 unless told otherwise, so a
    /// P-384 or P-521 request it makes needs `-sha384` or `-sha512`.
    pub fn verify(&self, allowed: &[SignatureScheme]) -> Result<SignatureScheme> {
        let scheme = scheme_from_alg(self.sig_alg)?;
        if !allowed.contains(&scheme) {
            return Err(Error::new(
                ErrorKind::PolicyViolation,
                "certificate request signature algorithm not allowed",
            ));
        }
        let key = self.subject_public_key()?;
        if rsa_bits(&key).is_some_and(|bits| bits < 2048) {
            return Err(Error::new(
                ErrorKind::PolicyViolation,
                "RSA key smaller than 2048 bits",
            ));
        }
        let ecdsa = |s: SignatureScheme| {
            matches!(
                s,
                SignatureScheme::EcdsaP256Sha256
                    | SignatureScheme::EcdsaP384Sha384
                    | SignatureScheme::EcdsaP521Sha512
            )
        };
        let ec_key = matches!(
            key,
            PublicKey::EcP256(_) | PublicKey::EcP384(_) | PublicKey::EcP521(_)
        );
        sign::verify(scheme, &key, self.info, self.signature).map_err(|e| match e.kind() {
            ErrorKind::KeyAlgorithmMismatch if ecdsa(scheme) && ec_key => Error::new(
                ErrorKind::UnsupportedCertificate,
                "ECDSA with a hash other than its curve's is not supported",
            ),
            ErrorKind::KeyAlgorithmMismatch => Error::new(
                ErrorKind::BadSignature,
                "certificate request signature does not match its key",
            ),
            _ => e,
        })?;
        Ok(scheme)
    }

    /// The request's DER.
    pub fn der(&self) -> &'a [u8] {
        self.der
    }

    /// The subject Name the request asks for, DER encoded.
    pub fn subject_der(&self) -> &'a [u8] {
        self.subject
    }

    /// The last common name in the subject, for display.
    pub fn subject_common_name(&self) -> Option<&'a str> {
        name_common_name(self.subject)
    }

    /// The SubjectPublicKeyInfo, DER encoded: what [`issue`](super::issue)
    /// takes.
    pub fn spki_der(&self) -> &'a [u8] {
        self.spki
    }

    /// The subject public key.
    pub fn subject_public_key(&self) -> Result<PublicKey<'a>> {
        sign::public_key(self.spki)
    }

    /// `REQ-CSR-003`: the dNSName alternative names requested.
    pub fn dns_names(&self) -> Vec<&'a str> {
        let mut out = Vec::new();
        let _ = for_each_san(self.ext.san, |tag, v| {
            if tag == T_GN_DNS
                && let Ok(s) = core::str::from_utf8(v)
            {
                out.push(s);
            }
        });
        out
    }

    /// `REQ-CSR-003`: the iPAddress alternative names requested.
    pub fn ip_addresses(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let _ = for_each_san(self.ext.san, |tag, v| {
            if tag == T_GN_IP {
                if let Ok(a) = <[u8; 4]>::try_from(v) {
                    out.push(IpAddr::V4(a));
                } else if let Ok(a) = <[u8; 16]>::try_from(v) {
                    out.push(IpAddr::V6(a));
                }
            }
        });
        out
    }

    /// `REQ-CSR-003`: the uniformResourceIdentifier alternative names
    /// requested.
    pub fn uri_names(&self) -> Vec<&'a str> {
        let mut out = Vec::new();
        let _ = for_each_san(self.ext.san, |tag, v| {
            if tag == T_GN_URI
                && let Ok(s) = core::str::from_utf8(v)
            {
                out.push(s);
            }
        });
        out
    }

    /// `REQ-CSR-003`: a requested extension by the contents of its object
    /// identifier: whether it is marked critical, and its value (the
    /// contents of the OCTET STRING). What to make of it is the CA's.
    pub fn extension(&self, oid: &[u8]) -> Option<(bool, &'a [u8])> {
        let mut outer = Der::new(self.extensions?);
        let mut list = outer.nested(T_SEQUENCE).ok()?;
        while !list.is_empty() {
            let mut e = list.nested(T_SEQUENCE).ok()?;
            let id = e.expect(T_OID).ok()?;
            let critical = e
                .optional(super::T_BOOLEAN)
                .ok()?
                .is_some_and(|b| b == [0xff]);
            let value = e.expect(super::T_OCTET_STRING).ok()?;
            if id == oid {
                return Some((critical, value));
            }
        }
        None
    }
}

/// What to put in a certificate request. Made with [`RequestParams::new`];
/// the fields are then set as needed.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RequestParams<'a> {
    /// Subject common name; may be empty when there are alternative names.
    pub subject_cn: &'a str,
    /// DNS alternative names to request.
    pub dns_names: &'a [&'a str],
    /// IP alternative names to request.
    pub ip_addresses: &'a [IpAddr],
    /// URI alternative names to request: absolute URIs.
    pub uris: &'a [&'a str],
}

impl<'a> RequestParams<'a> {
    /// A request for `subject_cn`, with no alternative names.
    pub fn new(subject_cn: &'a str) -> Self {
        Self {
            subject_cn,
            dns_names: &[],
            ip_addresses: &[],
            uris: &[],
        }
    }
}

/// Make a PKCS#10 request for `key`, signed with it under its first
/// algorithm. `REQ-CSR-004`: the alternative names go in an
/// `extensionRequest`, as a subjectAltName marked critical when the subject
/// is empty; names that a certificate could not carry are refused as
/// [`ErrorKind::InvalidConfig`], as by [`issue`](super::issue).
pub fn build(
    params: &RequestParams<'_>,
    key: &dyn Signer,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let cfg = |c| Error::new(ErrorKind::InvalidConfig, c);
    let names =
        !params.dns_names.is_empty() || !params.ip_addresses.is_empty() || !params.uris.is_empty();
    if params.subject_cn.is_empty() && !names {
        return Err(cfg("a request needs a subject name or an alternative name"));
    }
    if !params.dns_names.iter().all(|n| is_valid_dns_name(n, true)) {
        return Err(cfg("invalid DNS name in request parameters"));
    }
    if !params.uris.iter().all(|u| is_valid_certificate_uri(u)) {
        return Err(cfg("invalid URI in request parameters"));
    }
    let scheme = *key
        .algorithms()
        .first()
        .ok_or(cfg("key has no algorithm"))?;
    let alg = alg_id(scheme)?;

    let mut attributes = Vec::new();
    if names {
        let mut body = Vec::new();
        for n in params.dns_names {
            push_tlv(&mut body, T_GN_DNS, n.as_bytes());
        }
        for u in params.uris {
            push_tlv(&mut body, T_GN_URI, u.as_bytes());
        }
        for ip in params.ip_addresses {
            push_tlv(&mut body, T_GN_IP, ip.octets());
        }
        let mut san = Vec::new();
        push_tlv(&mut san, T_SEQUENCE, &body);
        let mut exts = Vec::new();
        push_ext(&mut exts, OID_EXT_SAN, params.subject_cn.is_empty(), &san);
        let mut value = Vec::new();
        push_tlv(&mut value, T_SEQUENCE, &exts);
        let mut set = Vec::new();
        push_tlv(&mut set, T_SET, &value);
        let mut attribute = Vec::new();
        push_tlv(&mut attribute, T_OID, OID_EXTENSION_REQUEST);
        attribute.extend_from_slice(&set);
        push_tlv(&mut attributes, T_SEQUENCE, &attribute);
    }

    let mut info = Vec::new();
    push_tlv(&mut info, T_INTEGER, &[0]);
    info.extend_from_slice(&encode_name(params.subject_cn));
    info.extend_from_slice(key.public_key());
    push_tlv(&mut info, T_ATTRIBUTES, &attributes);
    let mut info_der = Vec::new();
    push_tlv(&mut info_der, T_SEQUENCE, &info);

    let signature = sign::sign(key, scheme, &info_der, rng)?;
    let mut bits = Vec::with_capacity(signature.len() + 1);
    bits.push(0);
    bits.extend_from_slice(&signature);
    let mut request = info_der;
    request.extend_from_slice(&alg);
    push_tlv(&mut request, T_BIT_STRING, &bits);
    let mut out = Vec::new();
    push_tlv(&mut out, T_SEQUENCE, &request);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::sign::{KeyKind, SigningKey, VERIFY_ALGORITHMS};
    use crate::x509::{self, Certificate, CertificateParams};

    fn rng() -> ic_drbg::Rng {
        ic_drbg::Rng::from_os().unwrap()
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_tlv(&mut out, tag, body);
        out
    }

    const URI: &str = "nanda:agent/alpha-7";

    /// REQ-CSR-002, REQ-CSR-003, REQ-CSR-004: a request made here, for
    /// every key kind, parses, verifies under its own key, and reads back
    /// the names it asked for; a CA issues from it a certificate that
    /// carries them, URIs included.
    #[test]
    fn requests_made_here_verify_and_carry_their_names() {
        let ca_key = SigningKey::generate(KeyKind::EcdsaP384, &mut rng()).unwrap();
        let mut ca = CertificateParams::new("Request CA", 1_700_000_000, 1_900_000_000, [1; 16]);
        ca.is_ca = true;
        let ca_cert = x509::self_signed(&ca, &ca_key, &mut rng()).unwrap();
        for &kind in KeyKind::ALL {
            let key = SigningKey::generate(kind, &mut rng()).unwrap();
            let ips = [IpAddr::V4([192, 0, 2, 7])];
            let mut params = RequestParams::new("agent");
            params.dns_names = &["agent.example"];
            params.uris = &[URI];
            params.ip_addresses = &ips;
            let der = build(&params, &key, &mut rng()).unwrap();
            let request = CertificateRequest::parse(&der).unwrap();
            assert_eq!(
                request.verify(VERIFY_ALGORITHMS).unwrap(),
                key.algorithms()[0],
                "{kind:?}"
            );
            assert_eq!(request.subject_common_name(), Some("agent"));
            assert_eq!(request.spki_der(), key.spki());
            assert_eq!(request.dns_names(), ["agent.example"]);
            assert_eq!(request.uri_names(), [URI]);
            assert_eq!(request.ip_addresses(), ips);
            let (critical, _) = request.extension(OID_EXT_SAN).unwrap();
            assert!(!critical, "a subject name is present");
            assert_eq!(request.extension(&[0x55, 0x1d, 0x0f]), None);

            // The CA copies what it accepts: here, the URI alone.
            let uris = request.uri_names();
            let mut leaf = CertificateParams::new("", 1_700_000_000, 1_900_000_000, [2; 16]);
            leaf.uris = &uris;
            let cert =
                x509::issue(&leaf, request.spki_der(), &ca_cert, &ca_key, &mut rng()).unwrap();
            let cert = Certificate::parse(&cert).unwrap();
            assert_eq!(cert.uri_names(), [URI]);
            assert!(cert.dns_names().is_empty());
        }
        // An empty subject makes the requested subjectAltName critical.
        let key = SigningKey::generate(KeyKind::Ed25519, &mut rng()).unwrap();
        let mut params = RequestParams::new("");
        params.uris = &[URI];
        let der = build(&params, &key, &mut rng()).unwrap();
        let request = CertificateRequest::parse(&der).unwrap();
        assert_eq!(request.extension(OID_EXT_SAN).map(|e| e.0), Some(true));
        assert_eq!(request.subject_common_name(), None);
        request.verify(VERIFY_ALGORITHMS).unwrap();
        // A request with no names asks for no extensions.
        let der = build(&RequestParams::new("plain"), &key, &mut rng()).unwrap();
        let request = CertificateRequest::parse(&der).unwrap();
        assert!(request.uri_names().is_empty() && request.extension(OID_EXT_SAN).is_none());
    }

    /// REQ-CSR-002: a request whose signature its own key does not verify
    /// is refused, as is one signed under an algorithm not allowed.
    #[test]
    fn a_request_not_signed_by_its_key_is_refused() {
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng()).unwrap();
        let other = SigningKey::generate(KeyKind::EcdsaP256, &mut rng()).unwrap();
        let der = build(&RequestParams::new("agent"), &key, &mut rng()).unwrap();
        // The last byte of the signature, changed.
        let mut tampered = der.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let e = CertificateRequest::parse(&tampered)
            .unwrap()
            .verify(VERIFY_ALGORITHMS);
        assert_eq!(e.unwrap_err().kind(), ErrorKind::BadSignature);
        // Another key in the request than the one that signed it.
        let request = CertificateRequest::parse(&der).unwrap();
        let i = der
            .windows(key.spki().len())
            .position(|w| w == key.spki())
            .unwrap();
        let swapped = [&der[..i], other.spki(), &der[i + key.spki().len()..]].concat();
        let e = CertificateRequest::parse(&swapped)
            .unwrap()
            .verify(VERIFY_ALGORITHMS);
        assert_eq!(e.unwrap_err().kind(), ErrorKind::BadSignature);
        // ECDSA with another curve's hash: a P-384 key, its request marked
        // ecdsa-with-SHA256. Refused as unsupported, not as a bad signature.
        let p384 = SigningKey::generate(KeyKind::EcdsaP384, &mut rng()).unwrap();
        let der384 = build(&RequestParams::new("agent"), &p384, &mut rng()).unwrap();
        let sha384 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
        let i = der384.windows(8).position(|w| w == sha384).unwrap();
        let mut sha256 = der384.clone();
        sha256[i + 7] = 0x02;
        let e = CertificateRequest::parse(&sha256)
            .unwrap()
            .verify(VERIFY_ALGORITHMS)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedCertificate, "{e}");
        // An RSA key under 2048 bits is refused before its signature is
        // looked at.
        let modulus = [&[0x00][..], &[0xc5; 128]].concat();
        let rsa = [tlv(T_INTEGER, &modulus), tlv(T_INTEGER, &[1, 0, 1])].concat();
        let mut key_bits = vec![0u8];
        key_bits.extend(tlv(T_SEQUENCE, &rsa));
        let rsa_alg = [
            tlv(T_OID, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]),
            tlv(0x05, &[]),
        ]
        .concat();
        let rsa_spki = tlv(
            T_SEQUENCE,
            &[tlv(T_SEQUENCE, &rsa_alg), tlv(T_BIT_STRING, &key_bits)].concat(),
        );
        let info = tlv(
            T_SEQUENCE,
            &[
                tlv(T_INTEGER, &[0]),
                encode_name("agent"),
                rsa_spki,
                tlv(T_ATTRIBUTES, &[]),
            ]
            .concat(),
        );
        let sha256_rsa = tlv(
            T_SEQUENCE,
            &[
                tlv(T_OID, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11]),
                tlv(0x05, &[]),
            ]
            .concat(),
        );
        let small = tlv(
            T_SEQUENCE,
            &[info, sha256_rsa, tlv(T_BIT_STRING, &[0; 129])].concat(),
        );
        let e = CertificateRequest::parse(&small)
            .unwrap()
            .verify(VERIFY_ALGORITHMS)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PolicyViolation, "{e}");
        // An algorithm the caller does not allow.
        let e = request.verify(&[SignatureScheme::Ed25519]);
        assert_eq!(e.unwrap_err().kind(), ErrorKind::PolicyViolation);
        request.verify(&[SignatureScheme::EcdsaP256Sha256]).unwrap();
    }

    /// REQ-CSR-001: the encoding is held to RFC 2986 and DER.
    #[test]
    fn malformed_requests_are_refused() {
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng()).unwrap();
        let mut params = RequestParams::new("agent");
        params.uris = &[URI];
        let good = build(&params, &key, &mut rng()).unwrap();
        // Take the good request apart.
        let mut outer = Der::new(&good);
        let mut fields = outer.nested(T_SEQUENCE).unwrap();
        let info = fields.expect_raw(T_SEQUENCE).unwrap();
        let rest = fields.rest();
        let mut parts = Der::new(info).nested(T_SEQUENCE).unwrap();
        let _version = parts.expect_raw(T_INTEGER).unwrap();
        let subject = parts.expect_raw(T_SEQUENCE).unwrap();
        let spki = parts.expect_raw(T_SEQUENCE).unwrap();
        let ext_request = parts.expect(T_ATTRIBUTES).unwrap().to_vec();
        let request = |version: &[u8], attributes: &[u8], rest: &[u8]| {
            let info = tlv(
                T_SEQUENCE,
                &[version, subject, spki, &tlv(T_ATTRIBUTES, attributes)].concat(),
            );
            tlv(T_SEQUENCE, &[&info[..], rest].concat())
        };
        let v1 = tlv(T_INTEGER, &[0]);
        let attribute = |oid: &[u8], values: &[&[u8]]| {
            tlv(
                T_SEQUENCE,
                &[tlv(T_OID, oid), tlv(T_SET, &values.concat())].concat(),
            )
        };
        let password = attribute(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 7],
            &[&tlv(0x0c, b"secret")],
        );
        let parses = |der: &[u8]| CertificateRequest::parse(der).map(|_| ());
        assert_eq!(parses(&request(&v1, &ext_request, rest)), Ok(()));
        // Other attributes are passed over, in DER order.
        let (a, b) = if password < ext_request {
            (&password, &ext_request)
        } else {
            (&ext_request, &password)
        };
        assert_eq!(
            parses(&request(&v1, &[&a[..], &b[..]].concat(), rest)),
            Ok(())
        );
        assert_eq!(parses(&request(&v1, &[], rest)), Ok(()), "no attributes");
        let empty_extensions = tlv(T_SEQUENCE, &[]);
        // The good request's own extensions, twice, as two values.
        let mut attribute_der = Der::new(&ext_request);
        let mut fields = attribute_der.nested(T_SEQUENCE).unwrap();
        fields.expect(T_OID).unwrap();
        let extensions = Der::new(fields.expect(T_SET).unwrap())
            .expect_raw(T_SEQUENCE)
            .unwrap()
            .to_vec();
        let bad_subject = tlv(T_SEQUENCE, &tlv(T_SET, &[]));
        let refused = [
            ("a subject with an empty RDN", {
                let info = tlv(
                    T_SEQUENCE,
                    &[
                        &v1[..],
                        &bad_subject,
                        spki,
                        &tlv(T_ATTRIBUTES, &ext_request),
                    ]
                    .concat(),
                );
                tlv(T_SEQUENCE, &[&info[..], rest].concat())
            }),
            (
                "an extension request of two good values",
                request(
                    &v1,
                    &attribute(OID_EXTENSION_REQUEST, &[&extensions, &extensions]),
                    rest,
                ),
            ),
            (
                "version 2",
                request(&tlv(T_INTEGER, &[1]), &ext_request, rest),
            ),
            (
                "version not minimal",
                request(&tlv(T_INTEGER, &[0, 0]), &ext_request, rest),
            ),
            (
                "attributes out of order",
                request(&v1, &[&b[..], &a[..]].concat(), rest),
            ),
            (
                "two extension requests",
                request(&v1, &[&ext_request[..], &ext_request[..]].concat(), rest),
            ),
            (
                "an extension request of two values",
                request(
                    &v1,
                    &attribute(
                        OID_EXTENSION_REQUEST,
                        &[&empty_extensions, &empty_extensions],
                    ),
                    rest,
                ),
            ),
            (
                "an extension request of no extensions",
                request(
                    &v1,
                    &attribute(OID_EXTENSION_REQUEST, &[&empty_extensions]),
                    rest,
                ),
            ),
            (
                "an attribute with no value",
                request(&v1, &attribute(&[0x2a, 3], &[]), rest),
            ),
            (
                "trailing data",
                [request(&v1, &ext_request, rest), vec![0x05, 0x00]].concat(),
            ),
            (
                "trailing data in the request",
                request(&v1, &ext_request, &[rest, &[0x05, 0x00][..]].concat()),
            ),
        ];
        for (what, der) in refused {
            assert_eq!(
                CertificateRequest::parse(&der).unwrap_err().kind(),
                ErrorKind::BadCertificate,
                "{what}"
            );
        }
        // No attributes field at all.
        let info = tlv(T_SEQUENCE, &[&v1[..], subject, spki].concat());
        assert!(parses(&tlv(T_SEQUENCE, &[&info[..], rest].concat())).is_err());
        // A signature with unused bits.
        let sig_alg = Der::new(rest).expect_raw(T_SEQUENCE).unwrap();
        let mut bits = Der::new(&rest[sig_alg.len()..])
            .expect(T_BIT_STRING)
            .unwrap()
            .to_vec();
        bits[0] = 1;
        let odd = [sig_alg, &tlv(T_BIT_STRING, &bits)[..]].concat();
        assert!(parses(&request(&v1, &ext_request, &odd)).is_err());
        // Nothing panics on any prefix.
        for n in 0..good.len() {
            assert!(parses(&good[..n]).is_err());
        }
    }

    /// REQ-CSR-004, REQ-X509-092: names a certificate could not carry are
    /// not requested or issued; absolute URIs of any scheme are.
    #[test]
    fn names_a_certificate_cannot_carry_are_refused() {
        let key = SigningKey::generate(KeyKind::Ed25519, &mut rng()).unwrap();
        let ca = {
            let mut p = CertificateParams::new("CA", 1_700_000_000, 1_900_000_000, [1; 16]);
            p.is_ca = true;
            x509::self_signed(&p, &key, &mut rng()).unwrap()
        };
        for uri in [
            "",
            "agent",
            "/relative/path",
            "1nanda:x",
            "nanda:",
            "nan da:x",
            "nanda:a b",
            "nanda:\u{e9}",
            ":x",
        ] {
            let uris = [uri];
            let mut params = RequestParams::new("agent");
            params.uris = &uris;
            assert_eq!(
                build(&params, &key, &mut rng()).unwrap_err().kind(),
                ErrorKind::InvalidConfig,
                "{uri:?}"
            );
            let mut cert = CertificateParams::new("agent", 1_700_000_000, 1_900_000_000, [2; 16]);
            cert.uris = &uris;
            assert_eq!(
                x509::issue(&cert, key.spki(), &ca, &key, &mut rng())
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidConfig,
                "{uri:?}"
            );
        }
        for uri in [
            URI,
            "https://example.com/a?b#c",
            "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "spiffe://td/ns/x",
            "a+b-c.d:1",
        ] {
            let uris = [uri];
            let mut cert = CertificateParams::new("", 1_700_000_000, 1_900_000_000, [2; 16]);
            cert.uris = &uris;
            let der = x509::issue(&cert, key.spki(), &ca, &key, &mut rng()).unwrap();
            assert_eq!(Certificate::parse(&der).unwrap().uri_names(), [uri]);
        }
        assert_eq!(
            build(&RequestParams::new(""), &key, &mut rng())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidConfig
        );
    }
}
