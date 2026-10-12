# Changelog

## 0.2.1 (2026-10-11)

Two defects in how certificate policy processing bounds its work, both in
0.1.3 and 0.2.0. Neither accepted a path it should not have. No API
change.

### Fixed
- Paths RFC 5280 accepts were refused as too involved. The work was
  counted in evaluations, 8,192 to a path, and ordinary paths needed
  more: five certificates listing 30 policies each, with a caller naming
  64 policies, and no mappings or anyPolicy anywhere. Work is now counted
  by list entries examined, a million to a path; a policy the caller names
  that the path never mentions is dismissed for the cost of looking.
  Eight certificates of 100 policies each with 64 named take a tenth of
  the budget. A path whose mappings fan in at level after
  level can still exhaust it and be refused: nothing is remembered
  between questions, so such a path multiplies them.
- The bound did not bound the time. Scans for anyPolicy were not counted,
  and a certificate could list one policy 256 times, so a path under a
  trusted anchor could be made to take 170 ms for one evaluation at the
  default path length, and 1.2 s at 64 certificates. Whether a level has
  an anyPolicy node is now worked out once for the path, every scan is
  counted by its length, and exhausting the budget takes about 15 ms on
  the same machine.

### Changed
- A certificate that lists a policy twice no longer parses (RFC 5280
  section 4.2.1.4: a policy appears once), and neither does one whose
  policy qualifiers are not each an identifier and one value. Both were
  accepted before (REQ-X509-089).

### Verification
- These were found by a second reading of `src/x509_policy.rs` against
  RFC 5280's text, made by another instance of the model that wrote it and
  given the code and the RFC only. It is not an independent review. It
  wrote a reference of its own, compared 18 million paths drawn at random
  and found no wrong verdict; it found the two defects above and that the
  parser accepted what is now refused.
- The paths it found refused are tests, with the steps each takes; the
  work for a path is exposed to the tests, and one path's cost is pinned
  to the step.
- The comparison with the tree in the tests draws wider paths, as that
  reading asked: up to eight certificates over six policies, lists in any
  order, and a caller's list with duplicates, policies no certificate has
  and anyPolicy. 400,000 paths; those that exhaust the budget are counted
  and held to fewer than one in a thousand.

## 0.2.0 (2026-10-11)

A caller can say which certificate policies it accepts. One breaking
change: `VerifyOptions`, `ChainReport` and `FixedChainReport` can no
longer be built or matched field by field outside this crate.

### Added
- `VerifyOptions::policy`, a `PolicyOptions` (REQ-X509-090): the inputs of
  RFC 5280 section 6.1.1. `acceptable` names up to 64 policies the caller
  accepts, by the contents of their identifiers; `require_explicit`
  requires a valid policy from the start of the path; `inhibit_mapping`
  and `inhibit_any` inhibit policy mapping and anyPolicy from the start.
  `VerifyOptions::new` sets `PolicyOptions::any()`, RFC 5280's defaults,
  under which nothing changes from 0.1.3.
- `PolicyOptions::require(&[..])`, for a caller that means "only these
  policies". Naming policies requires none by itself, as the RFC has it: a
  path without policies is still accepted unless one is required.
- `ChainReport::policy` and `FixedChainReport::policy`, a `PolicyOutcome`:
  whether a policy was required of the path, and which of the caller's
  policies are valid for it, one bit for each.
- The caller's policies are compared in the trust anchor's own domain
  (RFC 5280 section 6.1.5 (g)): under a policy mapping, the policy to name
  is the one the anchor's side knows, not the one the leaf lists.

### Changed
- `VerifyOptions`, `ChainReport` and `FixedChainReport` are
  `#[non_exhaustive]`, so that a field can be added without breaking
  callers again. Build options with `VerifyOptions::new` and set fields
  after; read reports by field.
- Policy inputs that cannot be evaluated are `invalid-config`, before
  anything is parsed: more than 64 policies, or one that is not an object
  identifier's contents.

### Verification
- The reference in the tests, RFC 5280's policy tree written out, gains
  the caller's inputs and the intersection of section 6.1.5 (g). The
  comparison over 300,000 paths draws inputs for half of them and compares
  the whole outcome: accepted or refused, whether a policy was required,
  and which of the caller's policies are valid.
- 20 more OpenSSL-issued paths are judged with a caller's inputs, given to
  OpenSSL as `-policy`, `-explicit_policy`, `-inhibit_map` and
  `-inhibit_any`: 46 in all, the same verdict from OpenSSL and from both
  validators on each.
- Fuzzing under AddressSanitizer, without a finding: both targets for 301
  s each with the caller's policy inputs varied, and `pki` for 1,801 s
  (8,220,571 runs). `pki_differential` also ran 1,801 s on 0.1.3 as
  released (4,467,003 runs).

## 0.1.3 (2026-10-11)

Certificate policies are processed, the CNSA profiles' key rule covers
every certificate presented, and OCSP responses built here use SHA-384
certificate identifiers. Two functions are added; nothing is removed.

### Added
- `x509::check_cnsa1_keys` and `x509::check_cnsa2_keys` (REQ-CFG-009): the
  key of every certificate given, whether a path uses it or not, must be
  one of its CNSA suite: P-384 or RSA of 3072 or 4096 bits (RFC 8603
  section 4.1), or ML-DSA-87 or ML-KEM-1024
  (draft-jenkins-cnsa2-pkix-profile-05 section 4). `check_cnsa1_rsa_keys`
  remains, for the RSA rule alone.

### Changed
- Certificate policies are processed (REQ-X509-088), as RFC 5280 section
  6.1 has it for a caller that accepts any policy and requires none at the
  start. A path is refused with `certificate-usage` when a certificate on
  it requires an explicit policy (`policyConstraints`) and, where that
  takes effect, no policy is valid down to the leaf; `policyMappings`,
  inhibited mapping, `inhibitAnyPolicy` and the exemption of self-issued
  certificates are applied. Two things change for existing callers:
  - a critical `policyConstraints`, `policyMappings` or `inhibitAnyPolicy`
    no longer refuses the path as an unknown critical extension;
  - a path that requires an explicit policy and has none valid is refused,
    where it was accepted if the requirement was not marked critical.
  The trust anchor's own policy extensions are not processed. A caller
  cannot yet name the policies it accepts or require one itself. The work
  is bounded: a path whose policies need more than 8,192 evaluations (a
  bound that 0.2.1 replaces, having refused paths it should not have) is
  refused, as is one of more than 64 certificates.
- The four policy extensions are held to their encodings when a
  certificate is parsed (REQ-X509-089): `certificatePolicies` and
  `policyMappings` are nonempty lists of at most 256 entries, a mapping
  names anyPolicy on neither side, `policyConstraints` holds at least one
  count, and counts are minimal nonnegative integers. `certificatePolicies`
  was not examined before, so a certificate with a malformed one, which
  used to parse, no longer does.
- An OCSP response built here identifies the certificate with SHA-384
  hashes, where it used SHA-256 (REQ-OCSP-035). The CNSA certificate
  profiles allow no shorter hash outside a signature. Verification is
  unchanged: SHA-256, SHA-384 and SHA-512 CertIDs are checked in full,
  SHA-1 by serial and signature. A verifier that looks a certificate up by
  one hash only must now be asked for SHA-384 (`openssl ocsp -sha384`).

### Verification
- The differential fuzz fixtures carry URI and directory-name constraints,
  names of both forms and every policy extension. Both targets ran five
  minutes each with policy processing in place, without a finding. 0.1.2's
  own validator change had not been fuzzed before it was published; it was
  afterwards, three minutes a target, without a finding.

## 0.1.2 (2026-10-10)

directoryName and URI name constraints are evaluated, and the validator is
compared with OpenSSL 3.5. No API change.

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
- Certificate policies judged beside OpenSSL: 26 OpenSSL-issued paths with
  policies, mappings, requireExplicitPolicy, inhibitPolicyMapping and
  inhibitAnyPolicy get the same verdict from OpenSSL (told
  `-policy anyPolicy`, RFC 5280's default) and from both validators here.
- Policy processing here does not build RFC 5280's policy tree, because
  one of the two validators does not allocate. A test writes the tree out
  as the RFC does and compares verdicts on 300,000 paths of one to five
  certificates drawn from a fixed sequence; they agree on every one.
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
