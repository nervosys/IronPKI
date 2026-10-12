# ironpki-fuzz

Coverage-guided fuzzing (libFuzzer via `cargo fuzz`) of everything in IronPKI
that reads bytes it did not make. This package is its own workspace, so
`libfuzzer-sys` never enters the library's dependency graph.

| Target | What it reaches |
|---|---|
| `pki` | The certificate parser and its accessors, the certificate-request parser and its signature check, name matching, both path validators (the input as a leaf and as an intermediate), CRLs, OCSP responses, and trust anchors in both forms, including a key-form anchor's name constraints. It runs under each `Purpose` and with leaf pinning on and off, and fails if the two validators disagree |
| `pki_differential` | The two path validators on a chain whose to-be-signed bytes the fuzzer mutates and the harness signs again, so every signature verifies and every later check runs. It runs under each purpose and with the caller's policy inputs varied, and fails if they disagree, down to the error kind and to what they report of policies |

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

Windows 11, nightly, AddressSanitizer, on a loaded machine, 2026-10-12, at
IronPKI 0.3.0 before its release, with a certificate request among the
`pki` seeds and the caller's policy inputs varied in `pki_differential`. No
crashes, no sanitizer reports and no disagreement between the validators
(leak detection is not available with ASan on Windows):

| Target | Runs | Time |
|---|---:|---:|
| `pki` | 1,804,289 | 301 s |
| `pki_differential` | 1,070,017 | 301 s |

Two longer runs, 1,801 s each, without a finding: `pki_differential` on
0.1.3 as released (4,467,003 runs), and `pki` on 0.2.0 before its release
(8,220,571 runs).

The runs in the table are short. 0.1.2's own change to the validator was fuzzed only
after it was published (three minutes a target, without a finding). The
same two targets ran against this code from
IronSocketLayer before it moved here (525,508 and 267,672 runs in 91 s each,
for its 0.4.0), without a finding.
