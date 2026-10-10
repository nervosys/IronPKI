# Changelog

## Unreleased

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
