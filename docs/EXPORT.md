# Export control: the notification, ready to send

Nothing in this repository goes public, by repository visibility or by a
crates.io publish, before the owner has decided the question below and, if a
notice is to be sent, sent it and recorded it under `docs/export/`.
`Cargo.toml` keeps `publish = false` until then.

**This is not legal advice.** A non-lawyer prepared it from the regulation
text, so that counsel has something concrete to correct. It follows
IronSocketLayer's and IronCrypto's `docs/EXPORT.md`, which set out the
reasoning in more detail.

---

## 1. The determination

The requirement is **15 CFR §742.15(b)**:

- **§742.15(b)(1):** publicly available encryption source code is, in
  general, not subject to the EAR.
- **§742.15(b)(2):** the email notification to BIS and the ENC Encryption
  Request Coordinator applies to publicly available encryption source code
  that provides or performs **"non-standard cryptography"**: proprietary or
  unpublished cryptographic functionality.

**IronPKI implements no cryptography at all.** It parses and validates X.509
certificates, CRLs and OCSP responses, and writes them. Every signature it
checks is checked by IronCrypto's `ic-sig`, every signature it makes is made
by whatever `ic_core::sig::Signer` the caller holds, and every hash is
IronCrypto's `ic-hash`. It encrypts and decrypts nothing. The formats are
published standards (section 2).

Two readings follow, and the owner chooses between them:

- **No notice is needed.** IronPKI uses signatures for authentication only,
  and contains no encryption. Whether it is "encryption source code" at all is
  the question for counsel; if it is, it is standard, so §742.15(b)(2) does
  not apply.
- **Send one anyway**, as was decided for IronSocketLayer and IronCrypto on
  2026-10-05, because the failure modes are not symmetric: not notifying when
  it was required cannot be corrected after publication, and notifying when
  it was not costs an email.

A notification identifies the internet location of the source code, not a
version. IronPKI is a new location: a repository and a crate that the earlier
notices for IronSocketLayer and IronCrypto did not name. The certificate code
itself was named in IronSocketLayer's notice ("X.509 path validation and
issuance (RFC 5280); CRLs; ML-DSA in X.509 (RFC 9881)"), at IronSocketLayer's
location.

**Commercial distribution is a different question**, as for the other two
projects: object code, or source that is not publicly available, needs its own
classification with counsel before any such sale.

---

## 2. The notification

Send it from an address that will still receive mail in a year, to both
recipients in one message.

**To:** `crypt@bis.doc.gov`, `enc@nsa.gov`
**Subject:** `Notification of publicly available encryption source code — 15 CFR 742.15(b) — IronPKI`

```text
To the Bureau of Industry and Security and the ENC Encryption Request
Coordinator:

This is a notification under 15 CFR 742.15(b) of the internet location of
publicly available source code.

SUBMITTER
  Entity:          Nervosys
  Contact:         <name>, <title>
  Email:           <address that will remain monitored>
  Telephone:       <number>
  Postal address:  <address>

ITEM
  Name:            IronPKI (crate ironpki)
  Description:     An open-source X.509 certificate library written in Rust,
                   distributed as source code: path validation, certificate
                   revocation lists, OCSP responses and certificate issuance.
                   It implements no cryptographic primitive and performs no
                   encryption; signatures are verified and made by the
                   separately notified IronCrypto library
                   (https://github.com/nervosys/IronCrypto). The code was
                   previously part of the separately notified IronSocketLayer
                   library (https://github.com/nervosys/IronSocketLayer).
  Classification:  ECCN 5D002 (encryption source code), stated for
                   consistency with those two notifications
  Licence:         AGPL-3.0-or-later

INTERNET LOCATION
  https://github.com/nervosys/IronPKI
  https://crates.io/crates/ironpki

  The source code is or will be publicly available at those URLs without
  restriction on access and without charge.

CRYPTOGRAPHIC FUNCTIONALITY
  IronPKI implements published formats only, and contains no proprietary or
  unpublished cryptographic functionality.

    Certificates    X.509 certificates and path validation (RFC 5280),
                    including name constraints; issuance
    Revocation      Certificate revocation lists (RFC 5280); OCSP responses
                    (RFC 6960)
    Signatures      Verified through IronCrypto: ECDSA (FIPS 186-5), Ed25519
                    (RFC 8032), RSASSA-PSS and PKCS#1 v1.5 (RFC 8017), ML-DSA
                    (FIPS 204) in X.509 (RFC 9881)
    Purposes        TLS server and client certificates; TPM endorsement-key
                    certificates (TCG EK Credential Profile)

  IronPKI is not FIPS 140-3 validated and holds no CMVP certificate. The
  standards above are cited to identify what is implemented, not to claim
  validation.

This notification is submitted before the source code is made publicly
available.

<name>
<title>, Nervosys
<date>
```

### Before sending, confirm

- [ ] The URLs are where the code will actually be.
- [ ] The repository is still private and the crate unpublished, so that the
      notice precedes publication.
- [ ] The list of what is implemented still matches the code.

### After sending

Record it in `docs/export/notification.md`: the date and time, the address it
was sent from, the recipients, the subject and body as sent, and the commit at
the time. IronSocketLayer's record shows what goes missing when that is
written down later.
