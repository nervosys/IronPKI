//! NIST's Public Key Interoperability Test Suite (PKITS), sections 4.8 to
//! 4.12: certificate policies, requireExplicitPolicy, policy mappings,
//! inhibitPolicyMapping and inhibitAnyPolicy. 88 cases over 144
//! certificates, judged by both validators. Provenance: tests/vectors/pkits.
//! Eight cases are judged differently or for another reason, by rules
//! outside policy processing, and are named with the rule.

use std::path::Path;

use ironpki::sign::VERIFY_ALGORITHMS;
use ironpki::x509::{PolicyOptions, RootStore, VerifyOptions, verify_chain, verify_chain_fixed};
use ironpki::{ErrorKind, Limits, Purpose};

/// 2026-10-01, inside the 2010 to 2030 validity of the PKITS certificates.
const NOW: u64 = 1_790_812_800;

const ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x20, 0x00];

/// Cases this crate judges differently from the suite, each for a rule
/// outside policy processing, with the error it gives instead.
const DIFFERENCES: &[(&str, ErrorKind, &str)] = &[
    (
        "4.8.6 Overlapping Policies Test6 (Subpart 1)",
        ErrorKind::CertificateUsage,
        "REQ-X509-006: the suite's end-entity certificate is a CA certificate, which this crate          never accepts as an end entity",
    ),
    (
        "4.8.6 Overlapping Policies Test6 (Subpart 2)",
        ErrorKind::CertificateUsage,
        "REQ-X509-006, as above",
    ),
    (
        "4.8.6 Overlapping Policies Test6 (Subpart 3)",
        ErrorKind::CertificateUsage,
        "REQ-X509-006: refused, as the suite says, but for being a CA, not for its policies",
    ),
    (
        "4.8.7 Different Policies Test7",
        ErrorKind::CertificateUsage,
        "REQ-X509-006, as above",
    ),
    (
        "4.8.8 Different Policies Test8",
        ErrorKind::CertificateUsage,
        "REQ-X509-006, as above",
    ),
    (
        "4.12.10 Invalid Self-Issued inhibitAnyPolicy Test10",
        ErrorKind::CertificateUsage,
        "REQ-X509-006, as above",
    ),
    (
        "4.10.7 Invalid Mapping From anyPolicy Test7",
        ErrorKind::UnknownCa,
        "REQ-X509-089: refused, as the suite says, but at parse: a policyMappings naming          anyPolicy is malformed, so the mapping CA is no candidate and no path remains",
    ),
    (
        "4.10.8 Invalid Mapping To anyPolicy Test8",
        ErrorKind::UnknownCa,
        "REQ-X509-089, as above",
    ),
];

/// The contents of a PKITS policy's identifier: NIST-test-policy-n is
/// 2.16.840.1.101.3.2.1.48.n (PKITS section 3.1).
fn policy(name: &str) -> Vec<u8> {
    if name == "anyPolicy" {
        return ANY_POLICY.to_vec();
    }
    let n: u8 = name
        .strip_prefix("NIST-test-policy-")
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("unknown policy {name}"));
    vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, n]
}

fn policies(list: &str) -> Vec<Vec<u8>> {
    list.split(',')
        .filter(|p| !p.is_empty())
        .map(policy)
        .collect()
}

fn certificate(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/pkits/certs")
        .join(format!("{name}.crt"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// REQ-X509-088, REQ-X509-090: every case of PKITS sections 4.8 to 4.12
/// gets the verdict the suite gives, in both validators, with the suite's
/// inputs. Where the case names policies and the path validates, the
/// policies reported valid are the suite's user-constrained-policy-set.
#[test]
fn pkits_policy_cases_are_judged_as_the_suite_says() {
    let vectors = ic_json::parse(include_str!("vectors/pkits/pkits-policies.json")).unwrap();
    let cases = vectors.get("cases").unwrap().as_array().unwrap();
    assert_eq!(cases.len(), 88);
    let text =
        |case: &ic_json::Json, key: &str| case.get(key).unwrap().as_str().unwrap().to_owned();
    let flag = |case: &ic_json::Json, key: &str| case.get(key).unwrap().as_bool().unwrap();
    let mut wrong = Vec::new();
    let mut compared_sets = 0;
    let mut differences = 0;
    for case in cases {
        let name = text(case, "name");
        let certs: Vec<Vec<u8>> = case
            .get("certs")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|c| certificate(c.as_str().unwrap()))
            .collect();
        let (anchor, rest) = certs.split_first().unwrap();
        let (leaf, ints) = rest.split_last().unwrap();
        let ints: Vec<&[u8]> = ints.iter().map(Vec::as_slice).collect();
        let mut roots = RootStore::new();
        roots.add_der(anchor).unwrap();

        let initial = policies(&text(case, "initial_policy_set"));
        let named: Vec<&[u8]> = initial.iter().map(Vec::as_slice).collect();
        let mut opts =
            VerifyOptions::new(NOW, Purpose::TlsClient, VERIFY_ALGORITHMS, Limits::DEFAULT);
        let mut policy = PolicyOptions::any();
        policy.acceptable = &named;
        policy.require_explicit = flag(case, "initial_explicit_policy");
        policy.inhibit_mapping = flag(case, "initial_policy_mapping_inhibit");
        policy.inhibit_any = flag(case, "initial_inhibit_any_policy");
        opts.policy = policy;

        let owned = verify_chain(leaf, &ints, &roots, &opts);
        let fixed = verify_chain_fixed(leaf, &ints, &roots, &opts);
        assert_eq!(
            owned.as_ref().map(|r| r.policy).map_err(|e| e.kind()),
            fixed.as_ref().map(|r| r.policy).map_err(|e| e.kind()),
            "{name}: the two validators disagree"
        );
        if let Some((_, kind, _)) = DIFFERENCES.iter().find(|(n, _, _)| *n == name) {
            differences += 1;
            assert_eq!(
                owned.as_ref().err().map(|e| e.kind()),
                Some(*kind),
                "{name}"
            );
            continue;
        }
        let expected = flag(case, "should_validate");
        match &owned {
            Ok(report) => {
                if !expected {
                    wrong.push(format!("{name}: accepted, the suite refuses it"));
                    continue;
                }
                // The suite's user-constrained-policy-set, for the policies
                // named; anyPolicy named means any, which reports none.
                if !initial.is_empty() && !initial.iter().any(|p| p == ANY_POLICY) {
                    compared_sets += 1;
                    let constrained = policies(&text(case, "user_constrained_policy_set"));
                    for (i, p) in initial.iter().enumerate() {
                        let theirs = constrained.contains(p);
                        if report.policy.is_valid(i) != theirs {
                            wrong.push(format!(
                                "{name}: policy {i} reported valid {}, the suite says {theirs}",
                                report.policy.is_valid(i)
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                if expected {
                    wrong.push(format!(
                        "{name}: refused, {} ({}); the suite accepts it",
                        e.kind().id(),
                        e.context()
                    ));
                } else if e.kind() != ErrorKind::CertificateUsage
                    || e.context() != "no certificate policy is valid where one is required"
                {
                    wrong.push(format!(
                        "{name}: refused for another reason, {} ({})",
                        e.kind().id(),
                        e.context()
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of 88:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert_eq!(differences, DIFFERENCES.len());
    assert_eq!(compared_sets, 19, "accepted cases with named policies");
}
