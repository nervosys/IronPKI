# Releasing

Some steps cannot be undone once taken. Everything up to step 3 can be
repeated freely.

## 1. Verify the release commit

From the repository root, on the commit to be released:

```console
$ cargo fmt --all -- --check
$ cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
$ cargo test --locked --workspace --all-features
$ cargo test --locked --workspace --no-default-features
$ cargo build --no-default-features --target thumbv7em-none-eabihf
$ cargo +1.88 build --all-targets          # the declared rust-version
$ python scripts/check-first-party-only.py --all-features
$ cargo package --list                     # read what would be uploaded
```

Check that `Cargo.toml` requires the IronCrypto version the release was
tested against, and that the version is published. Move "Unreleased" in
[CHANGELOG.md](../CHANGELOG.md) under the version and date.

Check what is claimed: no FIPS 140-3 validation and no independent review.
The README, [SECURITY.md](../SECURITY.md) and the crate description must say
so and claim nothing more.

## 2. Export question (first public release only)

Before the repository is made public or the crate is published for the first
time, the owner decides the question in [EXPORT.md](EXPORT.md) and, if a
notice is sent, records it in `docs/export/notification.md`. Later releases
at the same location skip this step.

## 3. Publish (cannot be undone)

1. Set `publish = true` in `Cargo.toml` and commit it.
2. `cargo publish`
3. Tag the commit `vX.Y.Z` and push the tag.
4. Make the repository public, if it is not.

A yanked crate stays in the index and in every mirror, and a repository that
was public has been cloned. Publishing is permanent.
