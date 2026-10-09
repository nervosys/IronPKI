# IronPKI

The IronSecurity stack's certificate layer: one X.509 path validator and
issuer, built on IronCrypto.

**Status: scaffold.** IronPKI does not parse or validate a certificate yet.
It holds the contract a shared validator must meet, as tested types, and the
requirements its consumers have. The crate is not published.

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

The crate is `no_std` without its default `std` feature, forbids unsafe code
and has no dependencies yet.

## Plan

The validator is to be extracted from IronSocketLayer by that project's
session, with IronCrypto's issuance joining it.
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
