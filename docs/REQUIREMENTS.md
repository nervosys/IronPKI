# IronPKI requirements

IronPKI is to be the IronSecurity stack's one certificate layer. This file
records what its consumers need from it, as design inputs for the extraction.

## Where the code is today

| Project | Code | What it does |
| --- | --- | --- |
| IronSocketLayer | `x509.rs`, `x509_ocsp.rs`, `x509_crl.rs` (about 15,500 lines) | Path validation for TLS, OCSP and CRL checking, trust stores including key-form anchors (`RootStore::add_anchor`, 0.3.3) |
| IronPrivacyGuard | `src/x509.rs`, `src/x509/` (about 1,700 lines) | Offline, bounded path validation for TPM EK certificates and TLS servers; no revocation |
| IronCrypto | `ic-pkix` | DER encoding and certificate issuance; `ic-sig` verifies signatures over X.509 public keys |

The plan the maintainer approved starts IronPKI from IronSocketLayer's
validator, with `ic-pkix` issuance joining it. IronSocketLayer's session owns
that extraction.

## Requirements from IronPrivacyGuard

A shared validator must offer all of these before IPG can adopt it:

1. **The TPM EK-certificate purpose**: extended key usage `2.23.133.8.1`, as
   well as TLS server and client.
2. **Fail closed on what it does not evaluate.** A name-constraint form the
   validator cannot match refuses the path. So does an unknown critical
   extension. IPG also refuses wildcard DNS names under DNS constraints.
3. **Every name is checked** against ancestor constraints, not only the name
   that matched the request. rfc822Name constraints also govern
   `emailAddress` attributes in the subject (RFC 5280 section 4.2.1.10).
4. **Hard work bounds**: path length, candidates, anchors and signature
   checks. IPG's are 8, 64, 256 and 256 (`Limits::DEFAULT`). Path length
   counts certificates below the anchor, leaf included, which is how both
   IPG and IronSocketLayer count it. Callers pass `Limits` explicitly;
   `Limits::ONLINE` keeps IronSocketLayer's 24 signature checks for
   handshakes, where the peer chooses the chain.
5. **No network.** No fetching of issuers, CRLs or OCSP responses.
6. **Caller-supplied time and anchors.** No implicit roots, no system store
   unless the caller asks, and no certificate trusted because the peer sent it.
7. **Key-form trust anchors** with name constraints preserved.
8. **No unsafe code, and IronCrypto as the only dependency.**

IPG gains revocation checking, which it does not have today, if it can supply
CRLs or OCSP responses it obtained itself.

## Status against IronPrivacyGuard's requirements

| # | Requirement | State |
| --- | --- | --- |
| 1 | TPM EK-certificate purpose | Done: `Purpose::TpmEndorsementKey`, REQ-X509-080, `tests/endorsement_key.rs` |
| 2 | Fail closed on what is not evaluated | Done for unknown critical extensions and for name-constraint forms with no rule. A wildcard dNSName under a DNS constraint is evaluated for the names it can match, where IPG refused every one |
| 3 | Every name checked; rfc822Name constraints | Done after 0.1.0: REQ-X509-085. rfc822Name constraints are evaluated, for alternative names and subject `emailAddress` attributes. Since then directoryName (REQ-X509-086) and URI (REQ-X509-087) constraints are evaluated too; the remaining forms fail closed |
| 4 | Hard work bounds | Done: every bound comes from the caller's `Limits`, REQ-X509-081 |
| 5 | No network | Done: nothing is fetched |
| 6 | Caller-supplied time and anchors | Done, except that `RootStore::from_system` exists behind the `std` feature and is used only when called |
| 7 | Key-form trust anchors with name constraints | Done: `RootStore::add(TrustAnchor::Key { .. })`, REQ-X509-082 |
| 8 | No unsafe code, IronCrypto the only dependency | Done |

Asked for since: the report names the accepted anchor by subject and key
(done, REQ-X509-083), and a leaf that is itself an anchor is not accepted for
an endorsement key unless the caller asks (done, REQ-X509-084). Still needed
before IronPrivacyGuard can adopt it: a published crate.

## Requirements from IronSocketLayer

To be written by IronSocketLayer's session when it extracts the validator.
Known from its 0.3.3 behaviour:

- OCSP stapling and CRL checking, as offline inputs.
- A report of how a chain validated (`ChainReport`), equal for a key-form
  anchor and the same root added as a certificate.
- Signature schemes: ECDSA P-256/P-384/P-521, RSA PKCS#1 v1.5 on certificate
  links, RSA-PSS, Ed25519; RSA keys of at least 2048 bits.
- `no_std` with `alloc`.

## Open questions

- Whether `ic-pkix` issuance moves into IronPKI or IronPKI depends on it.
- Whether TPM key-attestation verification (IPG's `src/attest.rs`) belongs
  here or stays in IPG.
- How certificate policies are handled. IPG does not process the policy tree.
  Decided since: IronPKI processes them for RFC 5280's default inputs
  (REQ-X509-088), so a path on which a CA requires an explicit policy and
  none is valid is refused, where it used to be refused as unsupported
  only if the requirement was marked critical.
- Decided 2026-10-10: IronPKI offers a commercial licence alongside
  AGPL-3.0-or-later, with a CLA, as IronSocketLayer and IronCrypto do.
