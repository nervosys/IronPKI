# PKITS: certificate policy cases

The certificates in `certs/` are from NIST's Public Key Interoperability Test
Suite (PKITS), unchanged: `PKITS_data.zip`, downloaded 2026-10-12 from
<https://csrc.nist.gov/projects/pki-testing> (SHA-256
`592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665`), the 2011
edition with SHA-256 RSA signatures, valid from 2010 to 2030. Only the 144
certificates that sections 4.8 to 4.12 use are copied. CRLs are not: these
cases do not turn on revocation.

The cases in `pkits-policies.json` are the 88 subparts of those sections,
with the suite's inputs (initial-policy-set, initial-explicit-policy,
initial-policy-mapping-inhibit, initial-any-policy-inhibit) and expected
results (whether the path validates, and the user-constrained-policy-set).
They were extracted by a script from BoringSSL's machine-readable encoding of
the suite, `pki/testdata/nist-pkits/pkits_testcases-inl.h` at
<https://boringssl.googlesource.com/boringssl> main, fetched 2026-10-12
(SHA-256 `787949eaf716e5e10b57f3a09765d643fa52fb3f7e14330219c27331a834af22`),
whose harness gives no case in these sections an expectation different from
the PKITS document. The defaults where a case sets nothing are the
harness's: initial-policy-set anyPolicy, user-constrained-policy-set
{NIST-test-policy-1}. Cases 4.8.1, 4.8.2, 4.8.6 and 4.10.7 were checked by
hand against `PKITS.pdf` from the same page.

The policy identifiers are those of PKITS section 3.1:
NIST-test-policy-n is 2.16.840.1.101.3.2.1.48.n.

`tests/pkits.rs` runs them. Eight cases are judged by rules outside policy
processing, and are named there with the rule. In six (the three subparts
of 4.8.6, and 4.8.7, 4.8.8 and 4.12.10) the last certificate is a CA
certificate, which this crate never accepts as an end entity, so the
path is refused before its policies are looked at: two the suite would
accept, four it would refuse for their policies. 4.10.7 and 4.10.8 are
refused as the suite says, but at parse. That leaves 80 cases that test
policy processing.

What these cases cover, measured: of 30 deliberate breaks of the policy
rules, they catch 18. None of them maps a policy under anyPolicy, so the
rules for that are held by the generated comparisons in
`src/x509_policy.rs`, which catch all 30.
