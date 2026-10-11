# Test vectors

Everything here was generated with PyCA `cryptography` by IronPrivacyGuard's
scripts, from throwaway keys that were never saved, and is copied unchanged.
No real TPM, manufacturer CA or public CA is involved. Valid cases are valid
from 2020 to 2050 and are judged at Unix time 1,800,000,000.

| File | From IronPrivacyGuard at | Generator | Cases |
|---|---|---|---|
| `attestation-certificate-policy.json` | 1e12250 | `tests/interop/attestation_certificate_vectors.py` | 10 endorsement-key certificates |
| `x509-server-identity.json` | 1ffc55e | `tests/interop/x509_server_vectors.py` | 41 TLS server certificates, each with the name it is checked for |
| `x509-paths.json` | 1ffc55e | `tests/interop/x509_path_vectors.py` | 30 paths |
| `x509-signatures.json` | 1ffc55e | `tests/interop/x509_signature_vectors.py` | 22 certificate signatures, each with its issuer's key |

The last three record `accepted`, the verdict of IronPrivacyGuard's own
validator, which this crate replaced there. `tests/pyca_vectors.rs` and
`src/hardening_tests.rs` hold this crate to it, and name the five cases
where it differs on purpose.

## The endorsement-key file

`attestation-certificate-policy.json` is copied unchanged from IronPrivacyGuard
(`tests/vectors/`, at commit 1e12250). Its certificates were generated with
PyCA `cryptography` by IronPrivacyGuard's
`tests/interop/attestation_certificate_vectors.py`: a throwaway P-384 CA whose
private key was never saved, issuing certificates for the RSA endorsement key of
a software TPM. No real TPM or manufacturer CA is involved, and valid cases are
valid from 2020 to 2050.

The `expected` field is IronPrivacyGuard's verdict for its whole attestation
check, which also binds the certificate to a TPM's public key. IronPKI
validates the path only, so `tests/endorsement_key.rs` states what it expects
of each case itself.
