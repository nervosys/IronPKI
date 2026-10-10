# IronPKI

The IronSecurity stack's certificate layer: one X.509 path validator and
issuer, built on IronCrypto.

**Status: extraction in progress.** `ironpki::x509` is IronSocketLayer
0.3.4's certificate code, moved here with its 217 tests: parsing, path
validation, name matching, CRLs, OCSP responses and issuance. It validates
for a `Purpose`, including a TPM endorsement key, within the caller's
`Limits`, against the caller's `TrustAnchor`s. Nothing depends on it yet, and
the crate is not published.

It has not been independently reviewed, and neither it nor IronCrypto is
FIPS 140-3 validated.

## Why it exists

The stack has two path validators today: IronSocketLayer's, used for TLS, and
IronPrivacyGuard's, used for TPM endorsement-key certificates. Certificate
encoding and issuance are in IronCrypto's `ic-pkix`. IronPKI is where they
become one implementation.

## What is here

| Item | Purpose |
| --- | --- |
| `Purpose` | What a path is validated for: TLS server, TLS client or TPM endorsement key, with its extended-key-usage OID |
| `TrustAnchor` | A caller-chosen anchor: a certificate, or a key-form anchor with its name constraints |
| `Limits` | Hard bounds on path length, candidates, anchors, signature checks and certificate size, with `DEFAULT` (offline) and `ONLINE` (handshake) presets |
| `Revocation` | Whether revocation is not checked, checked if supplied, or required |

The crate is `no_std` with `alloc` without its default `std` feature, forbids
unsafe code, and depends only on IronCrypto (`ic-core`, `ic-sig`, `ic-pkix`,
`ic-hash`, 0.2.20 or later). Signatures are verified by `ic-sig`; nothing
here implements a primitive.

## Plan

Done: IronSocketLayer's validator moved here and passing its tests.
Done: validation for a `Purpose`, with the TPM endorsement-key leaf rules,
checked against certificates made with PyCA `cryptography`.
Done: `TrustAnchor` and `Limits` in the validator's interface; a report that
names its anchor by subject and key; pinning a leaf as an explicit option.
Done: a traceability matrix, [docs/TRACEABILITY.md](docs/TRACEABILITY.md), of
146 requirements and the tests that verify them, enforced by a test.
Next: evaluating rfc822Name constraints, which
fail a path closed today; then IronSocketLayer and IronPrivacyGuard depend on
this crate in place of their own copies.
[docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) lists what IronPrivacyGuard needs
before it can move onto the shared validator.

## Checks

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --workspace --no-default-features
python scripts/check-first-party-only.py --all-features
cargo build --no-default-features --target thumbv7em-none-eabihf
```

## Licence

AGPL-3.0-or-later; see [LICENSE](LICENSE). Whether a commercial licence is
also offered is the maintainer's decision and is not stated here.
