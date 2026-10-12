//! The two path validators, `x509::verify_chain` and
//! `x509::verify_chain_fixed`, must reach the same verdict, down to the
//! error kind and, where both accept, to what they report of policies. The
//! fuzzer mutates the to-be-signed bytes of an intermediate
//! (with name constraints) and a leaf; the harness re-signs them with the
//! fixture keys, so signatures always verify and every later check runs.
#![no_main]

use ironpki::Purpose;
use ironpki::x509::{self, VerifyOptions};
use ironpki_fuzz::{ALGORITHMS, LIMITS, NOW, diff_pki, sign_tbs};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let sel = data[0];
    let n = usize::from(u16::from_be_bytes([data[1], data[2]]));
    let rest = &data[3..];
    if n > rest.len() {
        return;
    }
    let (int_tbs, leaf_tbs) = rest.split_at(n);
    let d = diff_pki();
    let purpose = match sel >> 1 & 3 {
        0 => Purpose::TlsServer,
        1 => Purpose::TlsClient,
        _ => Purpose::TpmEndorsementKey,
    };
    let mut opts = VerifyOptions::new(NOW, purpose, ALGORITHMS, LIMITS);
    // The caller's policy inputs: two of the fixtures' policies named, and
    // each initial flag.
    if sel & 0x08 != 0 {
        opts.policy.acceptable = &[&[0x2a, 0x03, 0x01], &[0x2a, 0x03, 0x03]];
    }
    opts.policy.require_explicit = sel & 0x10 != 0;
    opts.policy.inhibit_mapping = sel & 0x20 != 0;
    opts.policy.inhibit_any = sel & 0x40 != 0;
    let (leaf, ints) = if sel & 1 == 0 {
        (
            sign_tbs(leaf_tbs, &d.int_key),
            vec![sign_tbs(int_tbs, &d.root_key)],
        )
    } else {
        (sign_tbs(leaf_tbs, &d.root_key), Vec::new())
    };
    let ints: Vec<&[u8]> = ints.iter().map(Vec::as_slice).collect();
    let owned = x509::verify_chain(&leaf, &ints, &d.roots, &opts)
        .map(|r| r.policy)
        .map_err(|e| e.kind());
    let fixed = x509::verify_chain_fixed(&leaf, &ints, &d.roots, &opts)
        .map(|r| r.policy)
        .map_err(|e| e.kind());
    assert_eq!(owned, fixed, "the path validators disagree");
});
