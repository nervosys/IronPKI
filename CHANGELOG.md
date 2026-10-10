# Changelog

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
