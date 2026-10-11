# Changelog

## Unreleased

### Changed
- directoryName constraints are evaluated (REQ-X509-086), where a path
  under one used to be refused as unsupported. A name is within a subtree
  whose relative distinguished names are the first of its own, in order
  (RFC 5280 §4.2.1.10). The constraint governs a subject that is not empty
  and directoryName alternative names alike, so a permitted subtree binds
  the subject of every certificate below the constraining CA. Printable
  ASCII in a PrintableString or a UTF8String is compared without regard to
  case or spacing. Anything else is the same value only when its encoding
  is: text outside ASCII, other string types, an IA5String that differs in
  case, and a relative distinguished name of several attributes. Where that
  leaves a comparison undecided, a permitted subtree does not cover the
  name and an excluded one refuses the path.
- uniformResourceIdentifier constraints are evaluated (REQ-X509-087),
  likewise. The constraint governs the host of each URI alternative name: a
  host names that host alone, and a domain with a leading dot every host
  below it. A URI with no authority, or with an address for a host, is
  refused wherever a URI constraint applies, as RFC 5280 requires; so is
  every path under a constraint that is neither a host nor a domain.
- One of IronPrivacyGuard's recorded paths is therefore judged differently,
  and named in `tests/pyca_vectors.rs`: a leaf whose subject is the name a
  directoryName constraint permits was recorded as refused, because the
  constraint was not evaluated, and is now accepted. OpenSSL 3.5 accepts
  it too.

### Verification
- Agreement with OpenSSL 3.5 in both directions, in
  `tests/openssl_interop.rs` (ignored unless asked for; they need `openssl`
  on `PATH`). OpenSSL, with `-x509_strict`, verifies the chains this crate
  issues with ECDSA P-256, P-384 and P-521, Ed25519 and ML-DSA-44, -65 and
  -87 keys. Both validators here verify chains OpenSSL issues with those,
  with RSA PKCS#1 v1.5 and with RSA-PSS, and refuse each under another root
  and for another name. Each honours the other's CRL, revoked and not, and
  reads the other's OCSP responses, good and revoked.
- Name constraints judged beside OpenSSL: 63 OpenSSL-issued leaves under
  permitted and excluded DNS, address, e-mail, URI and directory-name
  subtrees get the same verdict from OpenSSL and from both validators
  here, and the verdict RFC 5280 gives. One rule is left out as a
  deliberate difference: a wildcard reaching into an excluded DNS subtree
  is refused here and read literally by OpenSSL.
- Two fuzz targets of this crate's own, in `fuzz/`: `pki`, for everything
  read as DER (certificates, CRLs, OCSP responses, trust anchors in both
  forms) under each purpose, and `pki_differential`, which fails if the two
  path validators disagree. The seed corpus includes every PyCA certificate
  in `tests/vectors`.

## 0.1.1 (2026-10-10)

rfc822Name constraints are evaluated, and 93 more independently generated
cases hold the validator. No API change.

### Changed
- rfc822Name constraints are evaluated (REQ-X509-085), where a path under
  one used to be refused as unsupported. A host names every mailbox at that
  host, a domain with a leading dot every mailbox at a host below it, and a
  mailbox that mailbox alone, with the local part compared exactly
  (RFC 5280 §4.2.1.10). The constraint governs rfc822Name alternative names
  and emailAddress attributes of the subject alike. An address or a
  constraint with no rule still refuses the path, and directory-name and
  URI constraints are still not evaluated.

### Verification
- 93 more cases from an independent implementation: IronPrivacyGuard's
  PyCA `cryptography` vectors for TLS server identity (41), path building
  (30) and certificate signatures (22), copied unchanged with their
  generators' provenance. IronPKI's verdict is the recorded one in 89. The
  four where it differs are named in the tests with the rule: a dNSName
  with a trailing dot names the same host; anyExtendedKeyUsage stands for
  the TLS purposes; a wildcard under a DNS constraint is evaluated, and
  `*.example.test` is within a permitted `example.test`; and P-521
  signatures are verified.
- A wildcard dNSName is tested against DNS constraints for the names it can
  match: refused under an excluded subtree it reaches into and under a
  permitted subtree it reaches out of.

## 0.1.0 (2026-10-10)

The first version.

- Scaffolded IronPKI: workspace, licence, CI, dependency policy, the initial
  types and the design notes in `docs/`. Not published.
- Moved IronSocketLayer 0.3.4's certificate code here as `ironpki::x509`,
  with its 217 tests: parsing, path validation, name matching, CRLs, OCSP
  responses and issuance. Signatures are verified by IronCrypto's `ic-sig`
  and issuance signs through any `ic_core::sig::Signer`. Algorithms are
  IronCrypto's `SignatureAlgorithm`; errors are this crate's own. A SHA-1
  signature algorithm is refused as policy when a certificate's algorithm
  is read, since IronCrypto does not name it. The code does not yet use
  `TrustAnchor` or `Limits`.
- Validation is for a `Purpose`, which replaces the validator's own `Usage`,
  and `Purpose::TpmEndorsementKey` is implemented (REQ-X509-080): the leaf
  must name the endorsement-key purpose if it has an extended key usage,
  and anyExtendedKeyUsage does not stand for it; its key usage need not
  allow `digitalSignature`; and a key of a kind no signature is verified
  with, such as one marked RSAES-OAEP, is not read, which the report says
  (`UNEXAMINED_KEY`). The TLS purposes behave as before. Checked against
  ten certificates made with PyCA `cryptography`, from IronPrivacyGuard.
- `VerifyOptions::new` takes `Limits`, and the validator's bounds come from
  it: path length, candidate certificates, trust anchors, signature checks
  and certificate size. A request beyond them is refused before it is
  parsed (REQ-X509-081). There is no default: `Limits::ONLINE` keeps the 24
  signature checks IronSocketLayer used; `Limits::DEFAULT` allows 256.
- `RootStore::add` takes a `TrustAnchor` in either form (REQ-X509-082).
- A report names the anchor a path ended at by its subject and key,
  `anchor_subject` and `anchor_spki`, in both validators (REQ-X509-083).
- Accepting a leaf that is itself a trust anchor, without a path, is an
  option, `VerifyOptions::accept_anchor_as_leaf`: on for the TLS purposes,
  as before, and off for an endorsement key (REQ-X509-084).
- `docs/TRACEABILITY.md` lists the 146 requirements tagged in the source and
  the tests that verify each; `tests/traceability.rs` fails if a tag has no
  row, a row has no tag, or a cited test does not exist. Four of
  IronSocketLayer's certificate hardening tests, which used only this code,
  moved here with it.
- The tests sign with IronCrypto's `ic_sig::SoftwareSigner`; the signing code
  they first brought from IronSocketLayer is gone. IronCrypto 0.2.21 is now
  the minimum.
