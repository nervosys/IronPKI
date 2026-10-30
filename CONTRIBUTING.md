# Contributing to IronPKI

## Before anything else

- **Licensing.** Contributions are accepted under the
  [Contributor License Agreement](CLA.md), so they can be distributed under
  both the AGPL v3 and the commercial licence
  ([LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)). Opening a pull request
  indicates agreement; your commit name and email serve as the signature.
- **Security issues** are reported privately: see [SECURITY.md](SECURITY.md).
- **Cryptography belongs in IronCrypto.** A hash, a signature algorithm, a key
  encoding or a signer goes to
  [nervosys/IronCrypto](https://github.com/nervosys/IronCrypto), not here.
  IronPKI verifies through `ic-sig` and signs through `ic_core::sig::Signer`.
- **IronPKI encrypts nothing.** If it ever needs keys encrypted at rest
  (encrypted PKCS#8), it calls IronCrypto's `ic_pkix::pbes2`, once an
  IronCrypto release contains it. It never implements PBES2, PBKDF2, a cipher
  or a MAC itself. `tests/no_encryption.rs` fails if `src/` carries their
  object identifiers or the crate depends directly on `ic-kdf`, `ic-cipher` or
  `ic-mac`.

## Rules

- IronCrypto is the only dependency. `scripts/check-first-party-only.py`
  fails on anything else.
- `no_std` with `alloc` first; anything needing `std` goes behind the `std`
  feature.
- Nothing panics on input. Return an `Error`.
- No `unsafe` code.
- What is not evaluated fails closed: an unknown critical extension, a
  name-constraint form with no matching rule. Nothing is silently ignored.
- Nothing is fetched. Time, trust anchors, CRLs and OCSP responses come from
  the caller.
- Every requirement is traced. Tag new behaviour with a `REQ-AREA-NNN` in its
  doc comment, add the row to [docs/TRACEABILITY.md](docs/TRACEABILITY.md) and
  name the test that verifies it; `tests/traceability.rs` enforces all three.
- Both validators agree. A rule added to `verify_chain` is added to
  `verify_chain_fixed`, and a test runs both.
- Test vectors come from a published standard or from an independent
  implementation, with their provenance recorded beside them.
- Break the thing and confirm the test fails. A test that passes on broken
  code verified nothing.

## Before you open a pull request

```console
$ cargo fmt --all -- --check
$ cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
$ cargo test --locked --workspace --all-features
$ cargo test --locked --workspace --no-default-features
$ cargo build --no-default-features --target thumbv7em-none-eabihf
$ python scripts/check-first-party-only.py --all-features
$ cargo test --locked --test openssl_interop -- --ignored   # if openssl >= 3.5 is present
```

If you changed a parser or either path validator, fuzz it as well (see
[fuzz/README.md](fuzz/README.md)). A crash input becomes a regression test
alongside the fix.

Never claim FIPS 140-3 validation or an independent review, in code,
documentation or commit messages. Neither exists.
