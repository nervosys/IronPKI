# Test vectors

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
