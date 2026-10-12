//! Certificate policy processing: RFC 5280 section 6.1, for the inputs a
//! caller gives who names no policy of its own.
//!
//! Those inputs are the defaults: any policy is acceptable
//! (user-initial-policy-set is anyPolicy), no explicit policy is required at
//! the start, and neither policy mapping nor anyPolicy is inhibited at the
//! start. A path then fails on policy grounds in one way only: some
//! certificate on it requires an explicit policy (`policyConstraints`), and
//! by the time the requirement takes effect no policy is valid for the whole
//! path. Whether one is depends on `certificatePolicies`, `policyMappings`
//! and `inhibitAnyPolicy` all the way down, which is what is computed here.
//!
//! # No tree
//!
//! RFC 5280 describes the computation as a tree that is grown and pruned.
//! Both path validators call this, and one of them does not allocate, so
//! the tree is not built. With these inputs the outcome depends only on
//! whether the tree's last level is empty, and whether a policy has a node
//! on a level is a function of the level above:
//!
//! - a policy a certificate asserts has a node if a node above expects it,
//!   or if the level above has an anyPolicy node (6.1.3 (d) (1));
//! - where a certificate asserts anyPolicy and may, every policy a node
//!   above expects has a node (6.1.3 (d) (2));
//! - a node expects its own policy, unless the certificate maps that policy:
//!   then it expects what the policy is mapped to, or, where mapping is
//!   inhibited, it is deleted (6.1.4 (b)).
//!
//! A level with an anyPolicy node is settled by that alone: every policy a
//! certificate below it lists has a node, and so does anyPolicy if the
//! certificate asserts it. That is asked first at each step, so the rules
//! for a single policy are only ever applied to a level without an
//! anyPolicy node, and need not provide for one: not for the node a mapping
//! creates under anyPolicy, and not for the expectations of the anyPolicy
//! node itself.
//!
//! These are evaluated on demand, by rescanning the borrowed extensions.
//! A level's nodes are enumerated only when an anyPolicy assertion needs
//! them.
//!
//! # Bounds
//!
//! Nothing is remembered between questions, so a path can be made on
//! which the same question is asked very many times: mappings that fan in
//! at every level multiply the ways down. The work is therefore counted,
//! one step for each list entry examined, and a path is given [`BUDGET`]
//! steps for everything asked of it, beyond which it is refused. A
//! certificate has at most [`MAX_POLICIES`] policies and as many mappings,
//! and a path at most [`MAX_LEVELS`] certificates. A path on which many
//! policies are mapped into few, level after level, can exhaust the budget
//! although RFC 5280 would accept it; it is then refused, not accepted.

use super::{Der, T_INTEGER, T_OID, T_SEQUENCE, bad, check_oid_encoding, small_uint};
use crate::error::{Error, ErrorKind, Result};

/// anyPolicy, 2.5.29.32.0.
const ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x20, 0x00];

/// The most policies one `certificatePolicies` may list, and the most pairs
/// one `policyMappings` may hold.
pub(super) const MAX_POLICIES: usize = 256;

/// Steps one path is given before it is refused: list entries examined,
/// over every question asked of the path.
const BUDGET: u32 = 1_000_000;

/// The most certificates below the anchor a path may have here.
const MAX_LEVELS: usize = 64;

/// The policy extensions of one certificate, as borrowed encodings.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Policies<'a> {
    /// The contents of `certificatePolicies`: PolicyInformation values.
    pub(super) policies: Option<&'a [u8]>,
    /// The contents of `policyMappings`: issuer and subject domain pairs.
    pub(super) mappings: Option<&'a [u8]>,
    /// `policyConstraints.requireExplicitPolicy`.
    pub(super) require_explicit: Option<u64>,
    /// `policyConstraints.inhibitPolicyMapping`.
    pub(super) inhibit_mapping: Option<u64>,
    /// `inhibitAnyPolicy`.
    pub(super) inhibit_any: Option<u64>,
}

/// REQ-X509-089: `certificatePolicies` is a nonempty list of policies, each
/// an identifier and, optionally, a nonempty list of qualifiers; no policy
/// twice, and a qualifier an identifier and one value, what it says not
/// examined. Returns the list's contents.
pub(super) fn parse_certificate_policies(value: &[u8]) -> Result<&[u8]> {
    let mut outer = Der::new(value);
    let body = outer.expect(T_SEQUENCE)?;
    outer.finish()?;
    if body.is_empty() {
        return Err(bad("empty certificatePolicies"));
    }
    let mut list = Der::new(body);
    let mut count = 0;
    while !list.is_empty() {
        count += 1;
        if count > MAX_POLICIES {
            return Err(bad("too many certificate policies"));
        }
        let before = body.len() - list.rest().len();
        let mut information = list.nested(T_SEQUENCE)?;
        let policy = information.expect(T_OID)?;
        check_oid_encoding(policy)?;
        // RFC 5280 section 4.2.1.4: a policy appears once. Bounded by the
        // count above: at most 256 entries, each against those before it.
        if PolicyIter(Der::new(&body[..before])).any(|earlier| earlier == policy) {
            return Err(bad("a certificate policy appears twice"));
        }
        if !information.is_empty() {
            let mut qualifiers = information.nested(T_SEQUENCE)?;
            if qualifiers.is_empty() {
                return Err(bad("empty policy qualifiers"));
            }
            // PolicyQualifierInfo: an identifier and one value of any type.
            while !qualifiers.is_empty() {
                let mut qualifier = qualifiers.nested(T_SEQUENCE)?;
                check_oid_encoding(qualifier.expect(T_OID)?)?;
                qualifier.any()?;
                qualifier.finish()?;
            }
        }
        information.finish()?;
    }
    Ok(body)
}

/// REQ-X509-089: `policyMappings` is a nonempty list of pairs of policy
/// identifiers, neither of them anyPolicy (RFC 5280 section 4.2.1.5).
/// Returns the list's contents.
pub(super) fn parse_policy_mappings(value: &[u8]) -> Result<&[u8]> {
    let mut outer = Der::new(value);
    let body = outer.expect(T_SEQUENCE)?;
    outer.finish()?;
    if body.is_empty() {
        return Err(bad("empty policyMappings"));
    }
    let mut list = Der::new(body);
    let mut count = 0;
    while !list.is_empty() {
        count += 1;
        if count > MAX_POLICIES {
            return Err(bad("too many policy mappings"));
        }
        let mut pair = list.nested(T_SEQUENCE)?;
        for _ in 0..2 {
            let policy = pair.expect(T_OID)?;
            check_oid_encoding(policy)?;
            if policy == ANY_POLICY {
                return Err(bad("anyPolicy in a policy mapping"));
            }
        }
        pair.finish()?;
    }
    Ok(body)
}

/// REQ-X509-089: `policyConstraints` holds requireExplicitPolicy,
/// inhibitPolicyMapping or both, in that order, as counts of certificates.
/// Returns them in that order.
pub(super) fn parse_policy_constraints(value: &[u8]) -> Result<(Option<u64>, Option<u64>)> {
    let mut outer = Der::new(value);
    let mut body = outer.nested(T_SEQUENCE)?;
    outer.finish()?;
    let require_explicit = body.optional(0x80)?.map(small_uint).transpose()?;
    let inhibit_mapping = body.optional(0x81)?.map(small_uint).transpose()?;
    body.finish()?;
    if require_explicit.is_none() && inhibit_mapping.is_none() {
        return Err(bad("empty policyConstraints"));
    }
    Ok((require_explicit, inhibit_mapping))
}

/// REQ-X509-089: `inhibitAnyPolicy` is a count of certificates.
pub(super) fn parse_inhibit_any_policy(value: &[u8]) -> Result<u64> {
    let mut outer = Der::new(value);
    let count = small_uint(outer.expect(T_INTEGER)?)?;
    outer.finish()?;
    Ok(count)
}

/// The identifiers a `certificatePolicies` lists. The list was checked when
/// the certificate was parsed, so a fault ends the iteration.
struct PolicyIter<'a>(Der<'a>);

impl<'a> Iterator for PolicyIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.0.is_empty() {
            return None;
        }
        self.0.nested(T_SEQUENCE).ok()?.expect(T_OID).ok()
    }
}

/// The pairs a `policyMappings` holds: issuer domain, then subject domain.
struct MappingIter<'a>(Der<'a>);

impl<'a> Iterator for MappingIter<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let mut pair = self.0.nested(T_SEQUENCE).ok()?;
        Some((pair.expect(T_OID).ok()?, pair.expect(T_OID).ok()?))
    }
}

/// One certificate of a path, as policy processing sees it.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct PolicyCert<'a> {
    /// Its policy extensions.
    pub(super) policies: Policies<'a>,
    /// Whether its issuer and subject are the same name.
    pub(super) self_issued: bool,
}

/// What a visitor is called with: the walk, and a policy with a node.
type Visit<'v, 'p, 'a> = &'v mut dyn FnMut(&mut Walk<'p, 'a>, &'a [u8]) -> Result<bool>;

/// A path under evaluation. Levels are numbered as RFC 5280 numbers
/// certificates: 1 is the certificate the anchor issued, and the last is
/// the leaf. Level 0 is the initial state, a single anyPolicy node.
struct Walk<'p, 'a> {
    certs: &'p [PolicyCert<'a>],
    /// Bit `j - 1`: certificate `j` may assert anyPolicy (6.1.3 (d) (2)).
    any_allowed: u64,
    /// Bit `j - 1`: certificate `j` lists anyPolicy.
    lists_any: u64,
    /// Bit `j - 1`: level `j` has an anyPolicy node, which it has when
    /// every certificate down to it lists anyPolicy and may assert it.
    any_nodes: u64,
    /// Bit `j - 1`: certificate `j` may map policies (6.1.4 (b)).
    mapping_allowed: u64,
    /// Steps left: see the module's notes on bounds.
    budget: u32,
}

impl<'p, 'a> Walk<'p, 'a> {
    /// Count `steps` list entries examined, and refuse the path when its
    /// budget is spent.
    fn charge(&mut self, steps: usize) -> Result<()> {
        let steps = u32::try_from(steps).unwrap_or(u32::MAX);
        self.budget = self.budget.checked_sub(steps).ok_or(Error::new(
            ErrorKind::UnsupportedCertificate,
            "certificate policies too involved to evaluate",
        ))?;
        Ok(())
    }

    fn policies(&self, level: usize) -> PolicyIter<'a> {
        PolicyIter(Der::new(
            self.certs[level - 1].policies.policies.unwrap_or(&[]),
        ))
    }

    /// The mappings that take effect below `level`. The leaf's are never
    /// asked for: mappings matter to the level below, and it has none.
    fn mappings(&self, level: usize) -> MappingIter<'a> {
        MappingIter(Der::new(
            self.certs[level - 1].policies.mappings.unwrap_or(&[]),
        ))
    }

    fn may_map(&self, level: usize) -> bool {
        self.mapping_allowed >> (level - 1) & 1 == 1
    }

    /// Whether certificate `level` asserts anyPolicy and may.
    fn by_any(&self, level: usize) -> bool {
        (self.any_allowed & self.lists_any) >> (level - 1) & 1 == 1
    }

    /// Whether `level` has an anyPolicy node.
    fn any_node(&self, level: usize) -> bool {
        level == 0 || self.any_nodes >> (level - 1) & 1 == 1
    }

    /// Whether certificate `level` lists `policy`.
    fn asserts(&mut self, level: usize, policy: &[u8]) -> Result<bool> {
        let mut examined = 1;
        let mut found = false;
        for listed in self.policies(level) {
            examined += 1;
            if listed == policy {
                found = true;
                break;
            }
        }
        self.charge(examined)?;
        Ok(found)
    }

    /// Whether certificate `level` maps `policy` to anything.
    fn maps(&mut self, level: usize, policy: &[u8]) -> Result<bool> {
        let mut examined = 1;
        let mut found = false;
        for (issuer, _) in self.mappings(level) {
            examined += 1;
            if issuer == policy {
                found = true;
                break;
            }
        }
        self.charge(examined)?;
        Ok(found)
    }

    /// Whether `policy` has a node on `level` (6.1.3 (d)): the certificate
    /// lists it and the level above has an anyPolicy node or expects it, or
    /// the certificate asserts anyPolicy, may, and the level above expects
    /// it.
    ///
    /// A policy the certificate maps where mapping is inhibited loses its
    /// node (6.1.4 (b)). That is [`Self::expected`]'s to apply: a deleted
    /// node differs from a kept one only in what the level below may take
    /// from it, which is nothing.
    fn node(&mut self, level: usize, policy: &'a [u8]) -> Result<bool> {
        let listed = self.asserts(level, policy)?;
        if !listed && !self.by_any(level) {
            return Ok(false);
        }
        if listed && self.any_node(level - 1) {
            return Ok(true);
        }
        self.expected(level - 1, policy)
    }

    /// Whether some node on `level` expects `policy` of the level below,
    /// once the certificate's mappings have taken effect (6.1.4 (b)): a
    /// node expects its own policy unless the certificate maps it, and
    /// then, where mapping is allowed, what it is mapped to.
    fn expected(&mut self, level: usize, policy: &'a [u8]) -> Result<bool> {
        if level == 0 {
            return Ok(false);
        }
        if !self.maps(level, policy)? && self.node(level, policy)? {
            return Ok(true);
        }
        if self.may_map(level) {
            for (issuer, subject) in self.mappings(level) {
                self.charge(1)?;
                if subject == policy && self.node(level, issuer)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether `visit` accepts some policy, other than anyPolicy, with a
    /// node on `level`. A policy may be visited more than once. At the
    /// leaf's level the policies visited are exactly those with a node.
    /// Above it they include a policy whose node an inhibited mapping
    /// deleted; [`Self::some_expected`] passes on what such a policy would
    /// have been mapped to, and its caller, which checks each policy it is
    /// handed against its own level, finds nothing above expecting it.
    fn some_node(&mut self, level: usize, visit: Visit<'_, 'p, 'a>) -> Result<bool> {
        for policy in self.policies(level) {
            self.charge(1)?;
            if policy != ANY_POLICY && self.node(level, policy)? && visit(self, policy)? {
                return Ok(true);
            }
        }
        if self.by_any(level)
            && self.some_expected(level - 1, &mut |walk, policy| {
                Ok(walk.node(level, policy)? && visit(walk, policy)?)
            })?
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Whether `visit` accepts some policy, other than anyPolicy, that a
    /// node on `level` could expect of the level below. `visit` decides
    /// whether its own level has a node for it.
    fn some_expected(&mut self, level: usize, visit: Visit<'_, 'p, 'a>) -> Result<bool> {
        if level == 0 {
            return Ok(false);
        }
        self.some_node(level, &mut |walk, policy| {
            if !walk.maps(level, policy)? {
                return visit(walk, policy);
            }
            for (issuer, subject) in walk.mappings(level) {
                walk.charge(1)?;
                if issuer == policy && visit(walk, subject)? {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}

/// REQ-X509-088: process the certificate policies of a path (RFC 5280
/// section 6.1) for a caller that accepts any policy and requires none at
/// the start. `certs` are the certificates below the trust anchor, the one
/// it issued first and the leaf last.
///
/// The path is refused when a certificate on it requires an explicit policy
/// and, where that takes effect, no policy is valid: `certificate-usage`.
/// Policy mappings, the inhibiting of mapping and of anyPolicy, and the
/// exemption of self-issued certificates from the counts are all applied.
/// A path too long or too involved to evaluate within bounds is refused.
pub(super) fn check(certs: &[PolicyCert<'_>]) -> Result<()> {
    check_within(certs, BUDGET).map(|_| ())
}

/// [`check`] within `budget` steps; the steps left over.
fn check_within(certs: &[PolicyCert<'_>], budget: u32) -> Result<u32> {
    let n = certs.len();
    if n > MAX_LEVELS {
        return Err(Error::new(
            ErrorKind::CapacityExceeded,
            "certificate path too long for policy processing",
        ));
    }
    // 6.1.2: each count starts beyond the path's end, which is "not set".
    let unset = n as u64 + 1;
    let (mut explicit, mut mapping, mut inhibit) = (unset, unset, unset);
    let (mut any_allowed, mut mapping_allowed) = (0u64, 0u64);
    let (mut lists_any, mut any_nodes, mut any_so_far) = (0u64, 0u64, true);
    for (i, cert) in certs.iter().enumerate() {
        let last = i + 1 == n;
        let may_assert_any = inhibit > 0 || (!last && cert.self_issued);
        if may_assert_any {
            any_allowed |= 1 << i;
        }
        let p = &cert.policies;
        // One pass over each list, here, so that no later question about
        // anyPolicy scans one.
        let any =
            PolicyIter(Der::new(p.policies.unwrap_or(&[]))).any(|policy| policy == ANY_POLICY);
        if any {
            lists_any |= 1 << i;
        }
        any_so_far &= any && may_assert_any;
        if any_so_far {
            any_nodes |= 1 << i;
        }
        if last {
            // 6.1.5 (a), (b).
            explicit = explicit.saturating_sub(1);
            if p.require_explicit == Some(0) {
                explicit = 0;
            }
            break;
        }
        if mapping > 0 {
            mapping_allowed |= 1 << i;
        }
        // 6.1.4 (h), (i), (j).
        if !cert.self_issued {
            explicit = explicit.saturating_sub(1);
            mapping = mapping.saturating_sub(1);
            inhibit = inhibit.saturating_sub(1);
        }
        explicit = explicit.min(p.require_explicit.unwrap_or(u64::MAX));
        mapping = mapping.min(p.inhibit_mapping.unwrap_or(u64::MAX));
        inhibit = inhibit.min(p.inhibit_any.unwrap_or(u64::MAX));
    }
    // 6.1.5 (g): a policy is required only once the count reaches zero, and
    // a count at zero stays there, so the last level decides.
    if n == 0 || explicit > 0 {
        return Ok(budget);
    }
    let mut walk = Walk {
        certs,
        any_allowed,
        lists_any,
        any_nodes,
        mapping_allowed,
        budget,
    };
    if walk.any_node(n) || walk.some_node(n, &mut |_, _| Ok(true))? {
        return Ok(walk.budget);
    }
    Err(Error::new(
        ErrorKind::CertificateUsage,
        "no certificate policy is valid where one is required",
    ))
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::sign::push_tlv;

    /// A certificate's policy extensions in the abstract. Policy 0 is
    /// anyPolicy; the others are small private identifiers.
    #[derive(Debug, Clone, Default)]
    struct Spec {
        policies: Option<Vec<u8>>,
        mappings: Vec<(u8, u8)>,
        require_explicit: Option<u64>,
        inhibit_mapping: Option<u64>,
        inhibit_any: Option<u64>,
        self_issued: bool,
    }

    fn oid(id: u8) -> Vec<u8> {
        if id == 0 {
            ANY_POLICY.to_vec()
        } else {
            vec![0x2a, id]
        }
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_tlv(&mut out, tag, body);
        out
    }

    /// The encodings `check` reads, for one specification.
    struct Encoded {
        policies: Option<Vec<u8>>,
        mappings: Option<Vec<u8>>,
    }

    fn encode(spec: &Spec) -> Encoded {
        Encoded {
            policies: spec.policies.as_ref().map(|list| {
                list.iter()
                    .flat_map(|id| tlv(T_SEQUENCE, &tlv(T_OID, &oid(*id))))
                    .collect()
            }),
            mappings: (!spec.mappings.is_empty()).then(|| {
                spec.mappings
                    .iter()
                    .flat_map(|(issuer, subject)| {
                        tlv(
                            T_SEQUENCE,
                            &[tlv(T_OID, &oid(*issuer)), tlv(T_OID, &oid(*subject))].concat(),
                        )
                    })
                    .collect()
            }),
        }
    }

    fn verdict(path: &[Spec]) -> Result<()> {
        verdict_within(path, BUDGET).map(|_| ())
    }

    /// The verdict within `budget` steps, and the steps it took.
    fn verdict_within(path: &[Spec], budget: u32) -> Result<u32> {
        let encoded: Vec<Encoded> = path.iter().map(encode).collect();
        let certs: Vec<PolicyCert<'_>> = path
            .iter()
            .zip(&encoded)
            .map(|(spec, e)| PolicyCert {
                policies: Policies {
                    policies: e.policies.as_deref(),
                    mappings: e.mappings.as_deref(),
                    require_explicit: spec.require_explicit,
                    inhibit_mapping: spec.inhibit_mapping,
                    inhibit_any: spec.inhibit_any,
                },
                self_issued: spec.self_issued,
            })
            .collect();
        check_within(&certs, budget).map(|left| budget - left)
    }

    /// A node of RFC 5280's valid_policy_tree.
    struct Node {
        depth: usize,
        valid: u8,
        expected: BTreeSet<u8>,
        parent: Option<usize>,
        alive: bool,
    }

    /// RFC 5280 section 6.1 as it is written, with the tree: 6.1.2
    /// initialisation, 6.1.3 (d) to (f) and 6.1.4 (b), (h) to (j) for each
    /// certificate, and 6.1.5 (a), (b) and (g), for a user-initial-policy-set
    /// of anyPolicy and no initial flags. `true` when the path is accepted.
    fn by_the_tree(path: &[Spec]) -> bool {
        let n = path.len();
        let mut nodes = vec![Node {
            depth: 0,
            valid: 0,
            expected: BTreeSet::from([0]),
            parent: None,
            alive: true,
        }];
        let (mut explicit, mut mapping, mut inhibit) = (n as u64 + 1, n as u64 + 1, n as u64 + 1);
        // Delete childless nodes above `depth`, until none is left.
        let prune = |nodes: &mut Vec<Node>, depth: usize| loop {
            let childless: Vec<usize> = (0..nodes.len())
                .filter(|&k| {
                    nodes[k].alive
                        && nodes[k].depth < depth
                        && !nodes.iter().any(|c| c.alive && c.parent == Some(k))
                })
                .collect();
            if childless.is_empty() {
                break;
            }
            for k in childless {
                nodes[k].alive = false;
            }
        };
        for (index, cert) in path.iter().enumerate() {
            let i = index + 1;
            let tree = nodes[0].alive;
            // (d), (e)
            match &cert.policies {
                Some(policies) if tree => {
                    for &p in policies.iter().filter(|p| **p != 0) {
                        let expecting: Vec<usize> = (0..nodes.len())
                            .filter(|&k| {
                                nodes[k].alive
                                    && nodes[k].depth == i - 1
                                    && nodes[k].expected.contains(&p)
                            })
                            .collect();
                        let parents = if expecting.is_empty() {
                            (0..nodes.len())
                                .filter(|&k| {
                                    nodes[k].alive && nodes[k].depth == i - 1 && nodes[k].valid == 0
                                })
                                .collect()
                        } else {
                            expecting
                        };
                        for parent in parents {
                            nodes.push(Node {
                                depth: i,
                                valid: p,
                                expected: BTreeSet::from([p]),
                                parent: Some(parent),
                                alive: true,
                            });
                        }
                    }
                    if policies.contains(&0) && (inhibit > 0 || (i < n && cert.self_issued)) {
                        for parent in 0..nodes.len() {
                            if !nodes[parent].alive || nodes[parent].depth != i - 1 {
                                continue;
                            }
                            for value in nodes[parent].expected.clone() {
                                let has_child = nodes.iter().any(|c| {
                                    c.alive && c.parent == Some(parent) && c.valid == value
                                });
                                if !has_child {
                                    nodes.push(Node {
                                        depth: i,
                                        valid: value,
                                        expected: BTreeSet::from([value]),
                                        parent: Some(parent),
                                        alive: true,
                                    });
                                }
                            }
                        }
                    }
                    prune(&mut nodes, i);
                }
                _ => nodes[0].alive = false,
            }
            // (f)
            if explicit == 0 && !nodes[0].alive {
                return false;
            }
            if i == n {
                break;
            }
            // 6.1.4 (b)
            let issuers: BTreeSet<u8> = cert.mappings.iter().map(|m| m.0).collect();
            for issuer in issuers {
                let subjects: BTreeSet<u8> = cert
                    .mappings
                    .iter()
                    .filter(|m| m.0 == issuer)
                    .map(|m| m.1)
                    .collect();
                let at = |nodes: &Vec<Node>, valid: u8| -> Vec<usize> {
                    (0..nodes.len())
                        .filter(|&k| {
                            nodes[k].alive && nodes[k].depth == i && nodes[k].valid == valid
                        })
                        .collect()
                };
                let named = at(&nodes, issuer);
                if mapping > 0 {
                    if named.is_empty() {
                        for any in at(&nodes, 0) {
                            let parent = nodes[any].parent;
                            nodes.push(Node {
                                depth: i,
                                valid: issuer,
                                expected: subjects.clone(),
                                parent,
                                alive: true,
                            });
                        }
                    } else {
                        for k in named {
                            nodes[k].expected = subjects.clone();
                        }
                    }
                } else {
                    for k in named {
                        nodes[k].alive = false;
                    }
                    prune(&mut nodes, i);
                }
            }
            // (h), (i), (j)
            if !cert.self_issued {
                explicit = explicit.saturating_sub(1);
                mapping = mapping.saturating_sub(1);
                inhibit = inhibit.saturating_sub(1);
            }
            if let Some(r) = cert.require_explicit
                && r < explicit
            {
                explicit = r;
            }
            if let Some(r) = cert.inhibit_mapping
                && r < mapping
            {
                mapping = r;
            }
            if let Some(r) = cert.inhibit_any
                && r < inhibit
            {
                inhibit = r;
            }
        }
        // 6.1.5 (a), (b), (g)
        explicit = explicit.saturating_sub(1);
        if path[n - 1].require_explicit == Some(0) {
            explicit = 0;
        }
        explicit > 0 || nodes[0].alive
    }

    fn cert(policies: &[u8]) -> Spec {
        Spec {
            policies: Some(policies.to_vec()),
            ..Spec::default()
        }
    }

    fn refused(path: &[Spec]) -> bool {
        let ours = verdict(path);
        assert_eq!(ours.is_ok(), by_the_tree(path), "{path:?}");
        match ours {
            Ok(()) => false,
            Err(e) => {
                assert_eq!(e.kind(), ErrorKind::CertificateUsage);
                true
            }
        }
    }

    /// REQ-X509-088: without a requirement for an explicit policy, no
    /// arrangement of policies refuses a path; with one, a policy must be
    /// valid from the certificate below the requirement to the leaf.
    #[test]
    fn an_explicit_policy_is_required_only_where_a_certificate_says_so() {
        // Nothing requires a policy.
        assert!(!refused(&[Spec::default(), Spec::default()]));
        assert!(!refused(&[cert(&[1]), cert(&[2])]));
        // The CA requires one at once: its own certificate is exempt (the
        // count is taken after it), the leaf is not.
        let ca = |policies: &[u8], skip| Spec {
            require_explicit: Some(skip),
            ..cert(policies)
        };
        assert!(!refused(&[ca(&[1], 0), cert(&[1])]));
        assert!(refused(&[ca(&[1], 0), cert(&[2])]));
        assert!(refused(&[ca(&[1], 0), Spec::default()]));
        assert!(refused(&[
            Spec {
                require_explicit: Some(0),
                ..Spec::default()
            },
            cert(&[1])
        ]));
        // A count defers the requirement by that many certificates, and a
        // path that ends before it takes effect is not held to it. The end
        // of the path counts as one (6.1.5 (a)).
        assert!(refused(&[ca(&[1], 1), cert(&[2])]));
        assert!(!refused(&[ca(&[1], 2), cert(&[2])]));
        assert!(refused(&[ca(&[1], 2), cert(&[2]), cert(&[2])]));
        assert!(!refused(&[ca(&[1], 2), cert(&[1]), cert(&[1])]));
        // A leaf that requires a policy of itself.
        assert!(!refused(&[cert(&[1]), ca(&[1], 0)]));
        assert!(refused(&[cert(&[1]), ca(&[2], 0)]));
        assert!(!refused(&[cert(&[1]), ca(&[2], 1)]));
        // The policy must hold at every level, not only the last.
        assert!(refused(&[ca(&[1], 0), cert(&[2]), cert(&[1])]));
        assert!(!refused(&[ca(&[1, 2], 0), cert(&[1, 2]), cert(&[2])]));
    }

    /// REQ-X509-088: anyPolicy stands for every policy, until it is
    /// inhibited; a self-issued certificate may still assert it, and is not
    /// counted.
    #[test]
    fn any_policy_stands_for_every_policy_until_it_is_inhibited() {
        let top = |policies: &[u8], inhibit_any| Spec {
            require_explicit: Some(0),
            inhibit_any,
            ..cert(policies)
        };
        assert!(!refused(&[top(&[1], None), cert(&[0])]));
        assert!(!refused(&[top(&[0], None), cert(&[2])]));
        assert!(!refused(&[top(&[0], None), cert(&[0]), cert(&[0])]));
        // Inhibited at once: anyPolicy below asserts nothing.
        assert!(refused(&[top(&[1], Some(0)), cert(&[0])]));
        assert!(!refused(&[top(&[1], Some(0)), cert(&[0, 1])]));
        // Inhibited after one more certificate.
        assert!(!refused(&[top(&[1], Some(1)), cert(&[0]), cert(&[1])]));
        assert!(refused(&[top(&[1], Some(1)), cert(&[0]), cert(&[0])]));
        // A self-issued certificate is exempt, and does not use up the count.
        let rollover = Spec {
            self_issued: true,
            ..cert(&[0])
        };
        assert!(!refused(&[
            top(&[1], Some(0)),
            rollover.clone(),
            cert(&[1])
        ]));
        assert!(refused(&[top(&[1], Some(0)), rollover.clone(), cert(&[0])]));
        assert!(!refused(&[
            top(&[1], Some(1)),
            rollover,
            cert(&[0]),
            cert(&[1])
        ]));
        // The leaf is never exempt for being self-issued.
        assert!(refused(&[
            top(&[1], Some(0)),
            Spec {
                self_issued: true,
                ..cert(&[0])
            }
        ]));
    }

    /// REQ-X509-088: a mapping makes the subject domain's policy stand for
    /// the issuer domain's below the mapping certificate, and the mapped
    /// policy no longer stands for itself; inhibited, the mapped policy is
    /// lost.
    #[test]
    fn policy_mappings_translate_and_can_be_inhibited() {
        let top = |inhibit_mapping| Spec {
            require_explicit: Some(0),
            inhibit_mapping,
            ..cert(&[1])
        };
        let bridge = |policies: &[u8], mappings: &[(u8, u8)]| Spec {
            mappings: mappings.to_vec(),
            ..cert(policies)
        };
        assert!(!refused(&[top(None), bridge(&[1], &[(1, 2)]), cert(&[2])]));
        assert!(refused(&[top(None), bridge(&[1], &[(1, 2)]), cert(&[1])]));
        assert!(refused(&[top(None), bridge(&[1], &[(1, 2)]), cert(&[3])]));
        assert!(!refused(&[
            top(None),
            bridge(&[1], &[(1, 2), (1, 3)]),
            cert(&[3])
        ]));
        // Mapped twice.
        assert!(!refused(&[
            top(None),
            bridge(&[1], &[(1, 2)]),
            bridge(&[2], &[(2, 3)]),
            cert(&[3])
        ]));
        // A mapping from a policy the certificate does not hold maps nothing.
        assert!(refused(&[top(None), bridge(&[1], &[(3, 2)]), cert(&[2])]));
        assert!(!refused(&[top(None), bridge(&[1], &[(3, 2)]), cert(&[1])]));
        // Under anyPolicy the mapped policy is held.
        let any_top = Spec {
            require_explicit: Some(0),
            ..cert(&[0])
        };
        assert!(!refused(&[
            any_top.clone(),
            bridge(&[0], &[(3, 2)]),
            cert(&[2])
        ]));
        assert!(!refused(&[any_top, bridge(&[0], &[(3, 2)]), cert(&[1])]));
        // Inhibited at once: the mapped policy is deleted, not kept.
        assert!(refused(&[
            top(Some(0)),
            bridge(&[1], &[(1, 2)]),
            cert(&[2])
        ]));
        assert!(refused(&[
            top(Some(0)),
            bridge(&[1], &[(1, 2)]),
            cert(&[1])
        ]));
        let top_of_two = Spec {
            require_explicit: Some(0),
            inhibit_mapping: Some(0),
            ..cert(&[1, 3])
        };
        assert!(!refused(&[
            top_of_two,
            bridge(&[1, 3], &[(1, 2)]),
            cert(&[3])
        ]));
        // Inhibited one certificate later: the first mapping stands.
        assert!(!refused(&[
            top(Some(1)),
            bridge(&[1], &[(1, 2)]),
            cert(&[2])
        ]));
        assert!(refused(&[
            top(Some(1)),
            bridge(&[1], &[(1, 2)]),
            bridge(&[2], &[(2, 3)]),
            cert(&[3])
        ]));
        // The leaf's own mappings take no effect.
        assert!(!refused(&[top(None), bridge(&[1], &[(1, 2)])]));
    }

    /// REQ-X509-088: the verdict is RFC 5280's on every path tried: 400,000
    /// paths drawn from a fixed sequence, each judged here and by the tree
    /// as the RFC writes it. Two shapes are drawn: up to five certificates
    /// over three policies, and up to eight over six, with lists in any
    /// order and mappings that repeat, fan in and map a policy to itself. A
    /// path that exhausts the budget is not compared; few do, and the count
    /// is held to that.
    #[test]
    fn the_verdict_is_the_trees_on_paths_drawn_at_random() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) % bound
        };
        let (mut accepted, mut refused_count, mut over_budget) = (0u32, 0u32, 0u32);
        for case in 0..400_000u32 {
            let wide = case % 2 == 1;
            let (longest, universe, most_mappings) = if wide { (8, 6, 5) } else { (5, 3, 3) };
            let n = 1 + next(longest) as usize;
            let path: Vec<Spec> = (0..n)
                .map(|_| {
                    let policies = (next(8) != 0).then(|| {
                        let mut list: Vec<u8> =
                            (0..=universe as u8).filter(|_| next(3) == 0).collect();
                        if list.is_empty() {
                            list.push(1 + next(universe) as u8);
                        }
                        for i in (1..list.len()).rev() {
                            list.swap(i, next(i as u64 + 1) as usize);
                        }
                        list
                    });
                    let mut mappings = Vec::new();
                    for _ in 0..next(most_mappings + 1) {
                        if next(2) == 0 {
                            mappings.push((1 + next(universe) as u8, 1 + next(universe) as u8));
                        }
                    }
                    let count = |next: &mut dyn FnMut(u64) -> u64, often: u64| {
                        (next(often) == 0).then(|| next(3))
                    };
                    Spec {
                        policies,
                        mappings,
                        require_explicit: count(&mut next, 2),
                        inhibit_mapping: count(&mut next, 4),
                        inhibit_any: count(&mut next, 4),
                        self_issued: next(6) == 0,
                    }
                })
                .collect();
            match verdict(&path) {
                Ok(()) => {
                    assert!(by_the_tree(&path), "{path:?}");
                    accepted += 1;
                }
                Err(e) if e.kind() == ErrorKind::UnsupportedCertificate => over_budget += 1,
                Err(e) => {
                    assert_eq!(e.kind(), ErrorKind::CertificateUsage, "{path:?}");
                    assert!(!by_the_tree(&path), "{path:?}");
                    refused_count += 1;
                }
            }
        }
        // Both verdicts are well represented, or the comparison shows little.
        assert!(
            accepted > 100_000 && refused_count > 50_000,
            "{accepted} {refused_count}"
        );
        assert!(over_budget < 40, "{over_budget} paths exhausted the budget");
    }

    /// REQ-X509-088: the bound is on work done, whatever the lists' size,
    /// as 0.1.3's count of evaluations was not: certificates listing many
    /// policies made each evaluation scan long lists uncounted. Mappings
    /// that fan in, with no policy valid so that every way down is tried,
    /// cost the budget and no more; a plain path costs a few steps, pinned.
    #[test]
    fn the_budget_bounds_the_work_whatever_the_lists_hold() {
        let all: Vec<u8> = (1..=127).collect();
        let fan_in: Vec<(u8, u8)> = (1..=16u8)
            .flat_map(|a| (1..=16u8).map(move |b| (a, b)))
            .collect();
        let mut path = vec![Spec {
            require_explicit: Some(0),
            ..Spec::default()
        }];
        for _ in 0..6 {
            path.push(Spec {
                mappings: fan_in.clone(),
                ..cert(&all)
            });
        }
        path.push(cert(&[1]));
        for budget in [0, 1, 1_000, BUDGET] {
            let e = verdict_within(&path, budget).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::UnsupportedCertificate, "{budget}");
        }
        let plain = [
            Spec {
                require_explicit: Some(0),
                ..cert(&[1])
            },
            cert(&[1]),
        ];
        let steps = verdict_within(&plain, BUDGET).unwrap();
        // One for the leaf's list entry, two to find the policy in the
        // leaf's list, one to find that the first certificate does not map
        // it, two to find it in the first certificate's list.
        assert_eq!(steps, 6);
        verdict_within(&plain, steps).unwrap();
        verdict_within(&plain, steps - 1).unwrap_err();
        let mut mapped = plain.clone();
        mapped[0].mappings = vec![(2, 3), (2, 3), (2, 3)];
        assert_eq!(verdict_within(&mapped, BUDGET).unwrap(), 9);
        // Long lists of distinct policies: every certificate lists 127 and
        // anyPolicy last, and only the leaf's last is valid above.
        let mut long: Vec<Spec> = (0..7)
            .map(|_| {
                let mut list = all.clone();
                list.push(0);
                cert(&list)
            })
            .collect();
        long[0].require_explicit = Some(0);
        long.push(cert(&all));
        let steps = verdict_within(&long, BUDGET).unwrap();
        assert!(steps < 1_000, "{steps}");
        // A valid path that takes more than 0.1.3's 8,192: the certificate
        // the anchor issued holds only the leaf's last policy, so each of
        // the leaf's others is followed to the top before it is dropped.
        let mut narrow = vec![cert(&all); 8];
        narrow[0] = Spec {
            require_explicit: Some(0),
            ..cert(&[127])
        };
        let steps = verdict_within(&narrow, BUDGET).unwrap();
        assert!(steps > 8_192 && steps < BUDGET / 5, "{steps}");
    }

    /// REQ-X509-088: the work is bounded. Mappings that fan in at every
    /// level, which would take a number of evaluations exponential in the
    /// path's length, are refused within the budget and not evaluated; a
    /// path beyond the levels held is refused as over capacity.
    #[test]
    fn a_path_too_involved_or_too_long_is_refused() {
        let fan_in: Vec<(u8, u8)> = (1..=40u8)
            .flat_map(|a| (1..=40u8).map(move |b| (a, b)))
            .take(MAX_POLICIES)
            .collect();
        let all: Vec<u8> = (1..=40).collect();
        // No policy at the top, so none is valid below, which the search
        // can learn only by trying every way down.
        let mut path = vec![Spec {
            require_explicit: Some(0),
            ..Spec::default()
        }];
        for _ in 0..6 {
            path.push(Spec {
                mappings: fan_in.clone(),
                ..cert(&all)
            });
        }
        path.push(cert(&[1]));
        let e = verdict(&path).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedCertificate);
        assert_eq!(e.context(), "certificate policies too involved to evaluate");

        let long = vec![Spec::default(); MAX_LEVELS];
        verdict(&long).unwrap();
        let e = verdict(&vec![Spec::default(); MAX_LEVELS + 1]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::CapacityExceeded);
        check(&[]).unwrap();
    }
}
