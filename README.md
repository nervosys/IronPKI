# IronPKI

The IronSecurity stack's certificate layer: one X.509 path validator and
issuer, built on IronCrypto.

**Status: extraction in progress.** `ironpki::x509` is IronSocketLayer
0.3.4's certificate code, moved here with its 217 tests: parsing, path
validation, name matching, CRLs, OCSP responses and issuance. It does not yet
use the contract types below, has no TPM endorsement-key purpose, and nothing
depends on it. The crate is not published.

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
Next: its options take `Purpose`, `TrustAnchor` and `Limits`; the TPM
endorsement-key purpose; the requirement ids and their traceability matrix;
then IronSocketLayer depends on this crate in place of its own copy.
[docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) lists what IronPrivacyGuard needs
before it can move onto the shared validator.

## Checks

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --workspace --no-default-features
python scripts/check-first-party-only.py --all-features
```

## Licence

AGPL-3.0-or-later; see [LICENSE](LICENSE). Whether a commercial licence is
also offered is the maintainer's decision and is not stated here.
