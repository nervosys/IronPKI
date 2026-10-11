# ironpki-fuzz

Coverage-guided fuzzing (libFuzzer via `cargo fuzz`) of everything in IronPKI
that reads bytes it did not make. This package is its own workspace, so
`libfuzzer-sys` never enters the library's dependency graph.

| Target | What it reaches |
|---|---|
| `pki` | The certificate parser and its accessors, name matching, both path validators (the input as a leaf and as an intermediate), CRLs, OCSP responses, and trust anchors in both forms, including a key-form anchor's name constraints. It runs under each `Purpose` and with leaf pinning on and off, and fails if the two validators disagree |
| `pki_differential` | The two path validators on a chain whose to-be-signed bytes the fuzzer mutates and the harness signs again, so every signature verifies and every later check runs. It fails if they disagree, down to the error kind |

## Deterministic by construction

The fixtures (`src/lib.rs`) use fixed keys, a fixed clock and a DRBG from a
fixed seed, so a crash input reproduces exactly:
`cargo fuzz run <target> <file>`.

`seed-corpus` writes real inputs for the fuzzer to start from: the fixture
certificates, a CRL, an OCSP response, name constraints, and every certificate
in `tests/vectors` (PyCA-generated shapes this crate's own builder does not
produce). The differential seeds carry a TLS leaf and an endorsement-key leaf,
each through an intermediate and directly under the root. It first checks that
the fixtures still validate, and fails if they do not.

The endorsement-key leaf is there because the harness was checked and found
wanting without it: with the fixed-slot validator deliberately made to demand
`digitalSignature` of every leaf, `pki_differential` ran a minute from TLS
seeds alone and reported nothing, since no seed reached a rule that differs by
purpose. With the endorsement-key seeds it reports the disagreement at once.

## Running

```console
$ cd fuzz
$ cargo run --bin seed-corpus                       # writes corpus/<target>/
$ cd ..
$ cargo +nightly fuzz run --fuzz-dir fuzz -O pki -- -max_total_time=600
```

On Windows with the MSVC toolchain, AddressSanitizer needs its runtime on
`PATH`: the directory with `clang_rt.asan_dynamic-x86_64.dll`, under
`VC/Tools/MSVC/<version>/bin/Hostx64/x64` in the Visual Studio install.
Without it the target exits with `STATUS_DLL_NOT_FOUND`.

A crash input becomes a regression test in `src/` alongside the fix.

## Results so far

Windows 11, nightly, AddressSanitizer, on a loaded machine, 2026-10-10, at
IronPKI 0.1.2, with URI and directory-name constraints and names of both
forms in the differential fixtures. No crashes, no sanitizer reports and no
disagreement between the validators (leak detection is not available with
ASan on Windows):

| Target | Runs | Time |
|---|---:|---:|
| `pki` | 577,299 | 181 s |
| `pki_differential` | 335,113 | 181 s |

These are short runs, and they were made after 0.1.2 was published, not
before. The same two targets ran against this code from
IronSocketLayer before it moved here (525,508 and 267,672 runs in 91 s each,
for its 0.4.0), without a finding.
