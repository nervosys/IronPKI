//! Certificate policy processing: RFC 5280 section 6.1.
//!
//! The caller's inputs are [`PolicyOptions`]: the policies it accepts
//! (user-initial-policy-set), whether one is required from the start, and
//! whether policy mapping and anyPolicy are inhibited from the start. The
//! defaults are the RFC's: any policy is acceptable, and nothing is required
//! or inhibited.
//!
//! A path fails on policy grounds in one way: an explicit policy is
//! required, by the caller or by a certificate on the path
//! (`policyConstraints`), and where the requirement takes effect no policy
//! the caller accepts is valid for the whole path. Whether one is depends on
//! `certificatePolicies`, `policyMappings` and `inhibitAnyPolicy` all the
//! way down, which is what is computed here.
//!
//! # No tree
//!
//! RFC 5280 describes the computation as a tree that is grown and pruned.
//! Both path validators call this, and one of them does not allocate, so
//! the tree is not built. The outcome depends only on the tree's last
//! level, and whether a policy has a node on a level is a function of the
//! level above:
//!
//! - a policy a certificate asserts has a node if a node above expects it,
//!   or, when none does, if the level above has an anyPolicy node (6.1.3
//!   (d) (1));
//! - where a certificate asserts anyPolicy and may, every policy a node
//!   above expects has a node (6.1.3 (d) (2));
//! - a node expects its own policy, unless the certificate maps that policy:
//!   then it expects what the policy is mapped to, or, where mapping is
//!   inhibited, it is deleted; and a mapped policy with no node gets one
//!   under an anyPolicy node (6.1.4 (b)).
//!
//! # The caller's policies
//!
//! A caller that names policies accepts a path for one of them when a node
//! on the last level descends from a node of that policy whose parent is an
//! anyPolicy node (6.1.5 (g)): the policy is compared in the trust anchor's
//! own domain, before any mapping, not with what the leaf lists. So each
//! rule above also says where a node's ancestry begins: under an anyPolicy
//! node it begins with the node itself, and otherwise it is its parent's.
//! Where the last level has an anyPolicy node, every policy the caller
//! names is valid.
//!
//! These are evaluated on demand, by rescanning the borrowed extensions.
//! A level's nodes are enumerated only when an anyPolicy assertion needs
//! them. The work is bounded: a certificate has at most [`MAX_POLICIES`]
//! policies and as many mappings, a caller names at most
//! [`MAX_ACCEPTABLE`], and a path is given [`BUDGET`] evaluations for all
//! of them together, beyond which it is refused.

use super::{Der, T_INTEGER, T_OID, T_SEQUENCE, bad, check_oid_encoding, small_uint};
use crate::error::{Error, ErrorKind, Result};

/// anyPolicy, 2.5.29.32.0.
const ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x20, 0x00];

/// The most policies one `certificatePolicies` may list, and the most pairs
/// one `policyMappings` may hold.
pub(super) const MAX_POLICIES: usize = 256;

/// Evaluations one path is given before it is refused.
const BUDGET: u32 = 8192;

/// The most certificates below the anchor a path may have here.
const MAX_LEVELS: usize = 64;

/// The most policies a caller may name as acceptable: one bit each in
/// [`PolicyOutcome::valid`].
pub const MAX_ACCEPTABLE: usize = 64;

/// What the caller asks of certificate policies: the inputs of RFC 5280
/// section 6.1.1 (c) to (f). `REQ-X509-090`.
///
/// A policy is named by the contents of its OBJECT IDENTIFIER, without tag
/// or length: `&[0x2a, 0x03, 0x04]` is 1.2.3.4.
///
/// Naming policies does not by itself require one. As the RFC has it, a
/// path with no policies at all is still accepted unless a policy is
/// required, by `require_explicit` or by a certificate on the path. A
/// caller that means "only these policies" wants [`PolicyOptions::require`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyOptions<'s> {
    /// The policies the caller accepts (user-initial-policy-set), at most
    /// [`MAX_ACCEPTABLE`]. Empty, or with anyPolicy among them: any policy.
    pub acceptable: &'s [&'s [u8]],
    /// Require a valid policy from the start of the path
    /// (initial-explicit-policy).
    pub require_explicit: bool,
    /// Allow no policy mapping anywhere on the path
    /// (initial-policy-mapping-inhibit).
    pub inhibit_mapping: bool,
    /// Give anyPolicy no meaning anywhere on the path
    /// (initial-any-policy-inhibit).
    pub inhibit_any: bool,
}

impl<'s> PolicyOptions<'s> {
    /// RFC 5280's defaults: any policy is acceptable, none is required, and
    /// nothing is inhibited.
    pub const fn any() -> Self {
        Self {
            acceptable: &[],
            require_explicit: false,
            inhibit_mapping: false,
            inhibit_any: false,
        }
    }

    /// Accept only a path for which one of `acceptable` is valid: the
    /// policies named, and a policy required from the start.
    pub const fn require(acceptable: &'s [&'s [u8]]) -> Self {
        Self {
            acceptable,
            require_explicit: true,
            inhibit_mapping: false,
            inhibit_any: false,
        }
    }

    /// Whether any policy is acceptable.
    fn accepts_any(&self) -> bool {
        self.acceptable.is_empty() || self.acceptable.contains(&ANY_POLICY)
    }

    /// Refuse inputs that cannot be evaluated: too many policies, or one
    /// that is not an OBJECT IDENTIFIER's contents.
    pub fn validate(&self) -> Result<()> {
        if self.acceptable.len() > MAX_ACCEPTABLE {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "too many acceptable certificate policies",
            ));
        }
        for policy in self.acceptable {
            check_oid_encoding(policy).map_err(|_| {
                Error::new(
                    ErrorKind::InvalidConfig,
                    "an acceptable certificate policy is not an object identifier",
                )
            })?;
        }
        Ok(())
    }
}

/// What policy processing established for an accepted path.
/// `REQ-X509-090`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyOutcome {
    /// Whether a valid policy was required of this path, by the caller or
    /// by a certificate on it.
    pub required: bool,
    /// Bit `i`: the caller's `acceptable[i]` is valid for the path. Zero
    /// when the caller named no policies, and for a pinned leaf, which has
    /// no path.
    pub valid: u64,
}

impl PolicyOutcome {
    /// Whether the caller's `acceptable[index]` is valid for the path.
    pub fn is_valid(&self, index: usize) -> bool {
        index < MAX_ACCEPTABLE && self.valid >> index & 1 == 1
    }
}

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
/// an identifier and, optionally, a nonempty list of qualifiers, which are
/// not examined. Returns the list's contents.
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
        let mut information = list.nested(T_SEQUENCE)?;
        check_oid_encoding(information.expect(T_OID)?)?;
        if !information.is_empty() && information.expect(T_SEQUENCE)?.is_empty() {
            return Err(bad("empty policy qualifiers"));
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
    /// Bit `j - 1`: certificate `j` may map policies (6.1.4 (b)).
    mapping_allowed: u64,
    budget: u32,
}

impl<'p, 'a> Walk<'p, 'a> {
    fn spend(&mut self) -> Result<()> {
        self.budget = self.budget.checked_sub(1).ok_or(Error::new(
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

    fn may_assert_any(&self, level: usize) -> bool {
        self.any_allowed >> (level - 1) & 1 == 1
    }

    fn may_map(&self, level: usize) -> bool {
        self.mapping_allowed >> (level - 1) & 1 == 1
    }

    fn asserts(&self, level: usize, policy: &[u8]) -> bool {
        self.policies(level).any(|p| p == policy)
    }

    fn maps(&self, level: usize, policy: &[u8]) -> bool {
        self.mappings(level).any(|(issuer, _)| issuer == policy)
    }

    /// Whether `level` has an anyPolicy node: every certificate down to it
    /// asserts anyPolicy and may.
    fn any_node(&self, level: usize) -> bool {
        (1..=level).all(|j| self.may_assert_any(j) && self.asserts(j, ANY_POLICY))
    }

    /// Whether certificate `level` gives `policy` a node (6.1.3 (d)): it
    /// lists the policy and the level above has an anyPolicy node or expects
    /// it, or it asserts anyPolicy, may, and the level above expects it.
    ///
    /// Two effects of the certificate's mappings (6.1.4 (b)) are left to
    /// [`Self::expected`], because they change only what the level below
    /// may take from this one: a mapped policy loses its node where mapping
    /// is inhibited, and gains one under an anyPolicy node where it had
    /// none.
    fn node(&mut self, level: usize, policy: &'a [u8]) -> Result<bool> {
        self.spend()?;
        let listed = self.asserts(level, policy);
        let by_any = self.may_assert_any(level) && self.asserts(level, ANY_POLICY);
        if !listed && !by_any {
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
    /// then, where mapping is allowed, what it is mapped to. A mapped
    /// policy has a node wherever the level has an anyPolicy node.
    fn expected(&mut self, level: usize, policy: &'a [u8]) -> Result<bool> {
        if level == 0 {
            return Ok(false);
        }
        if !self.maps(level, policy) && self.node(level, policy)? {
            return Ok(true);
        }
        if self.may_map(level) {
            for (issuer, subject) in self.mappings(level) {
                if subject == policy && (self.any_node(level) || self.node(level, issuer)?) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether `policy` has a node on `level`, by 6.1.3 (d), whose ancestry
    /// begins with a node of `domain`: the node below an anyPolicy node
    /// from which it descends.
    fn descends(&mut self, level: usize, policy: &'a [u8], domain: &[u8]) -> Result<bool> {
        self.spend()?;
        let listed = self.asserts(level, policy);
        let by_any = self.may_assert_any(level) && self.asserts(level, ANY_POLICY);
        if !listed && !by_any {
            return Ok(false);
        }
        // A child of the nodes that expect it: their ancestry.
        if self.expected_of(level - 1, policy, domain)? {
            return Ok(true);
        }
        // A child of the anyPolicy node, which only a listed policy that no
        // node expects is: its ancestry begins with itself.
        Ok(listed
            && policy == domain
            && self.any_node(level - 1)
            && !self.expected(level - 1, policy)?)
    }

    /// Whether some node on `level` with ancestry from `domain` expects
    /// `policy` of the level below.
    fn expected_of(&mut self, level: usize, policy: &'a [u8], domain: &[u8]) -> Result<bool> {
        if level == 0 {
            return Ok(false);
        }
        if !self.maps(level, policy) && self.descends(level, policy, domain)? {
            return Ok(true);
        }
        if self.may_map(level) {
            for (issuer, subject) in self.mappings(level) {
                if subject != policy {
                    continue;
                }
                if self.descends(level, issuer, domain)? {
                    return Ok(true);
                }
                // The node a mapping creates under anyPolicy for a policy
                // that has none: its ancestry begins with itself.
                if issuer == domain && self.any_node(level) && !self.node(level, issuer)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether the last level has a node with ancestry from `domain`
    /// (6.1.5 (g)), when it has no anyPolicy node.
    fn valid_for(&mut self, domain: &[u8]) -> Result<bool> {
        let n = self.certs.len();
        for policy in self.policies(n) {
            if policy != ANY_POLICY && self.descends(n, policy, domain)? {
                return Ok(true);
            }
        }
        if self.may_assert_any(n) && self.asserts(n, ANY_POLICY) {
            return self.some_expected(n - 1, &mut |walk, policy| walk.descends(n, policy, domain));
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
            if policy != ANY_POLICY && self.node(level, policy)? && visit(self, policy)? {
                return Ok(true);
            }
        }
        if self.may_assert_any(level)
            && self.asserts(level, ANY_POLICY)
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
            if !walk.maps(level, policy) {
                return visit(walk, policy);
            }
            for (issuer, subject) in walk.mappings(level) {
                walk.spend()?;
                if issuer == policy && visit(walk, subject)? {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}

/// REQ-X509-088, REQ-X509-090: process the certificate policies of a path
/// (RFC 5280 section 6.1) for the caller's inputs. `certs` are the
/// certificates below the trust anchor, the one it issued first and the
/// leaf last.
///
/// The path is refused when an explicit policy is required, by the caller
/// or by a certificate on the path, and where that takes effect no policy
/// the caller accepts is valid: `certificate-usage`. Policy mappings, the
/// inhibiting of mapping and of anyPolicy, and the exemption of self-issued
/// certificates from the counts are all applied. A path too long or too
/// involved to evaluate within bounds is refused.
pub(super) fn check(
    certs: &[PolicyCert<'_>],
    options: &PolicyOptions<'_>,
) -> Result<PolicyOutcome> {
    options.validate()?;
    let n = certs.len();
    if n > MAX_LEVELS {
        return Err(Error::new(
            ErrorKind::CapacityExceeded,
            "certificate path too long for policy processing",
        ));
    }
    // 6.1.2: each count starts beyond the path's end, which is "not set",
    // or at zero where the caller sets it.
    let unset = |set: bool| if set { 0 } else { n as u64 + 1 };
    let mut explicit = unset(options.require_explicit);
    let mut mapping = unset(options.inhibit_mapping);
    let mut inhibit = unset(options.inhibit_any);
    let (mut any_allowed, mut mapping_allowed) = (0u64, 0u64);
    for (i, cert) in certs.iter().enumerate() {
        let last = i + 1 == n;
        if inhibit > 0 || (!last && cert.self_issued) {
            any_allowed |= 1 << i;
        }
        let p = &cert.policies;
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
    if n == 0 {
        return Ok(PolicyOutcome::default());
    }
    // 6.1.5 (g): a policy is required only once the count reaches zero, and
    // a count at zero stays there, so the last level decides.
    let mut outcome = PolicyOutcome {
        required: explicit == 0,
        valid: 0,
    };
    let mut walk = Walk {
        certs,
        any_allowed,
        mapping_allowed,
        budget: BUDGET,
    };
    let acceptable = if options.accepts_any() {
        if !outcome.required {
            return Ok(outcome);
        }
        walk.any_node(n) || walk.some_node(n, &mut |_, _| Ok(true))?
    } else {
        let any = walk.any_node(n);
        for (i, policy) in options.acceptable.iter().enumerate() {
            if any || walk.valid_for(policy)? {
                outcome.valid |= 1 << i;
            }
        }
        outcome.valid != 0
    };
    if acceptable || !outcome.required {
        return Ok(outcome);
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

    /// The caller's inputs in the abstract: the policies it accepts (none:
    /// any) and the three initial flags.
    #[derive(Debug, Clone, Default)]
    struct Input {
        acceptable: Vec<u8>,
        require_explicit: bool,
        inhibit_mapping: bool,
        inhibit_any: bool,
    }

    fn verdict(path: &[Spec]) -> Result<()> {
        judge(path, &Input::default()).map(|_| ())
    }

    fn judge(path: &[Spec], input: &Input) -> Result<PolicyOutcome> {
        let acceptable: Vec<Vec<u8>> = input.acceptable.iter().map(|id| oid(*id)).collect();
        let acceptable: Vec<&[u8]> = acceptable.iter().map(Vec::as_slice).collect();
        let options = PolicyOptions {
            acceptable: &acceptable,
            require_explicit: input.require_explicit,
            inhibit_mapping: input.inhibit_mapping,
            inhibit_any: input.inhibit_any,
        };
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
        check(&certs, &options)
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
    /// certificate, and 6.1.5 (a), (b) and (g). `None` when the path is
    /// refused; otherwise whether a policy was required, and which of the
    /// caller's policies the intersected tree holds on its last level, by
    /// the policy of the node under an anyPolicy node each descends from.
    fn by_the_tree(path: &[Spec]) -> bool {
        tree(path, &Input::default()).is_some()
    }

    fn tree(path: &[Spec], input: &Input) -> Option<PolicyOutcome> {
        let n = path.len();
        let mut nodes = vec![Node {
            depth: 0,
            valid: 0,
            expected: BTreeSet::from([0]),
            parent: None,
            alive: true,
        }];
        let initial = |set: bool| if set { 0 } else { n as u64 + 1 };
        let mut explicit = initial(input.require_explicit);
        let mut mapping = initial(input.inhibit_mapping);
        let mut inhibit = initial(input.inhibit_any);
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
                return None;
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
        let user = &input.acceptable;
        if nodes[0].alive && !user.is_empty() {
            // (g) (iii) 1: the nodes whose parent is an anyPolicy node.
            let under_any: Vec<usize> = (0..nodes.len())
                .filter(|&k| nodes[k].alive && nodes[k].parent.is_some_and(|p| nodes[p].valid == 0))
                .collect();
            // 2: delete those not acceptable, and all their descendants.
            for &k in &under_any {
                if nodes[k].valid != 0 && !user.contains(&nodes[k].valid) {
                    nodes[k].alive = false;
                }
            }
            loop {
                let orphans: Vec<usize> = (0..nodes.len())
                    .filter(|&k| nodes[k].alive && nodes[k].parent.is_some_and(|p| !nodes[p].alive))
                    .collect();
                if orphans.is_empty() {
                    break;
                }
                for k in orphans {
                    nodes[k].alive = false;
                }
            }
            // 3: an anyPolicy node on the last level becomes a node for each
            // acceptable policy not already under an anyPolicy node.
            let any_leaves: Vec<usize> = (0..nodes.len())
                .filter(|&k| nodes[k].alive && nodes[k].depth == n && nodes[k].valid == 0)
                .collect();
            for leaf in any_leaves {
                for &policy in user {
                    if !under_any.iter().any(|&k| nodes[k].valid == policy) {
                        let parent = nodes[leaf].parent;
                        nodes.push(Node {
                            depth: n,
                            valid: policy,
                            expected: BTreeSet::from([policy]),
                            parent,
                            alive: true,
                        });
                    }
                }
                nodes[leaf].alive = false;
            }
            // 4.
            prune(&mut nodes, n);
        }
        if explicit == 0 && !nodes[0].alive {
            return None;
        }
        // Which acceptable policies the last level descends from.
        let mut valid = 0u64;
        if nodes[0].alive {
            for k in (0..nodes.len()).filter(|&k| nodes[k].alive && nodes[k].depth == n) {
                let mut top = k;
                while let Some(parent) = nodes[top].parent
                    && nodes[parent].valid != 0
                {
                    top = parent;
                }
                for (i, _) in user
                    .iter()
                    .enumerate()
                    .filter(|(_, u)| **u == nodes[top].valid)
                {
                    valid |= 1 << i;
                }
            }
        }
        Some(PolicyOutcome {
            required: explicit == 0,
            valid,
        })
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

    /// REQ-X509-088, REQ-X509-090: the outcome is RFC 5280's on every path
    /// tried: 300,000 paths of one to five certificates drawn from a fixed
    /// sequence, half of them with caller's inputs drawn too, each judged
    /// here and by the tree as the RFC writes it. Accepted or refused,
    /// whether a policy was required, and which of the caller's policies
    /// are valid all agree.
    #[test]
    fn the_verdict_is_the_trees_on_paths_drawn_at_random() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) % bound
        };
        let (mut accepted, mut refused_count) = (0u32, 0u32);
        let (mut named, mut with_valid) = (0u32, 0u32);
        for _ in 0..300_000 {
            let n = 1 + next(5) as usize;
            let path: Vec<Spec> = (0..n)
                .map(|_| {
                    let policies = (next(8) != 0).then(|| {
                        let mut list: Vec<u8> = (0..4u8).filter(|_| next(3) == 0).collect();
                        if list.is_empty() {
                            list.push(1 + next(3) as u8);
                        }
                        list
                    });
                    let mut mappings = Vec::new();
                    for _ in 0..next(4) {
                        if next(2) == 0 {
                            mappings.push((1 + next(3) as u8, 1 + next(3) as u8));
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
            // Half the paths are judged with RFC 5280's default inputs.
            let input = if next(2) == 0 {
                Input::default()
            } else {
                Input {
                    acceptable: (1..=3u8).filter(|_| next(3) == 0).collect(),
                    require_explicit: next(2) == 0,
                    inhibit_mapping: next(4) == 0,
                    inhibit_any: next(4) == 0,
                }
            };
            if !input.acceptable.is_empty() {
                named += 1;
            }
            let ours = judge(&path, &input);
            let theirs = tree(&path, &input);
            match ours {
                Ok(outcome) => {
                    assert_eq!(Some(outcome), theirs, "{path:?} {input:?}");
                    accepted += 1;
                    if outcome.valid != 0 {
                        with_valid += 1;
                    }
                }
                Err(e) => {
                    assert_eq!(e.kind(), ErrorKind::CertificateUsage, "{path:?} {input:?}");
                    assert_eq!(theirs, None, "{path:?} {input:?}");
                    refused_count += 1;
                }
            }
        }
        assert!(
            named > 50_000 && with_valid > 10_000,
            "{named} {with_valid}"
        );
        // Both verdicts are well represented, or the comparison shows little.
        assert!(
            accepted > 50_000 && refused_count > 50_000,
            "{accepted} {refused_count}"
        );
    }

    /// REQ-X509-090: the caller's inputs. Its policies are compared in the
    /// trust anchor's domain, before any mapping; naming them requires
    /// nothing by itself; and each initial flag acts from the first
    /// certificate. Every outcome is also the tree's.
    #[test]
    fn the_callers_inputs_are_applied() {
        let outcome = |path: &[Spec], input: &Input| {
            let ours = judge(path, input).ok();
            assert_eq!(ours, tree(path, input), "{path:?} {input:?}");
            ours.map(|o| (o.required, o.valid))
        };
        let only = |acceptable: &[u8]| Input {
            acceptable: acceptable.to_vec(),
            require_explicit: true,
            ..Input::default()
        };
        let plain = [cert(&[1]), cert(&[1])];
        assert_eq!(outcome(&plain, &only(&[1])), Some((true, 0b1)));
        assert_eq!(outcome(&plain, &only(&[2])), None);
        assert_eq!(outcome(&plain, &only(&[2, 1])), Some((true, 0b10)));
        assert_eq!(outcome(&plain, &only(&[1, 2, 1])), Some((true, 0b101)));
        // Named but not required: accepted, and the report says what held.
        let named = |acceptable: &[u8]| Input {
            acceptable: acceptable.to_vec(),
            ..Input::default()
        };
        assert_eq!(outcome(&plain, &named(&[2])), Some((false, 0)));
        assert_eq!(outcome(&plain, &named(&[1])), Some((false, 0b1)));
        assert_eq!(
            outcome(&[Spec::default(), Spec::default()], &named(&[1])),
            Some((false, 0))
        );
        // Required with any policy acceptable.
        let required = Input {
            require_explicit: true,
            ..Input::default()
        };
        assert_eq!(outcome(&plain, &required), Some((true, 0)));
        assert_eq!(outcome(&[Spec::default()], &required), None);
        assert_eq!(outcome(&[cert(&[1]), cert(&[2])], &required), None);

        // Under a mapping the caller's policy is the issuer domain's, which
        // the leaf does not list, and not the subject domain's, which it does.
        let mapped = [
            Spec {
                mappings: vec![(1, 2)],
                ..cert(&[1])
            },
            cert(&[2]),
        ];
        assert_eq!(outcome(&mapped, &only(&[1])), Some((true, 0b1)));
        assert_eq!(outcome(&mapped, &only(&[2])), None);
        // A policy mapped under anyPolicy has a node of its own, and what
        // it is mapped to descends from that.
        let mapped_under_any = [
            Spec {
                mappings: vec![(3, 2)],
                ..cert(&[0])
            },
            cert(&[2]),
        ];
        assert_eq!(outcome(&mapped_under_any, &only(&[3])), Some((true, 0b1)));
        assert_eq!(outcome(&mapped_under_any, &only(&[2])), None);
        assert_eq!(
            outcome(&mapped_under_any, &only(&[2, 3])),
            Some((true, 0b10))
        );
        // Without the mapping, the leaf's policy begins under anyPolicy.
        assert_eq!(
            outcome(&[cert(&[0]), cert(&[2])], &only(&[2])),
            Some((true, 0b1))
        );
        assert_eq!(outcome(&[cert(&[0]), cert(&[2])], &only(&[1])), None);
        // anyPolicy on the last level: every policy the caller names.
        assert_eq!(
            outcome(&[cert(&[0]), cert(&[0])], &only(&[1, 2])),
            Some((true, 0b11))
        );
        assert_eq!(
            outcome(&[cert(&[1, 0]), cert(&[0])], &only(&[1, 2])),
            Some((true, 0b11))
        );
        // anyPolicy on the leaf alone stands for what is valid above it.
        assert_eq!(
            outcome(&[cert(&[1]), cert(&[0])], &only(&[1, 2])),
            Some((true, 0b1))
        );
        assert_eq!(outcome(&[cert(&[1]), cert(&[0])], &only(&[2])), None);

        // The initial flags.
        let no_mapping = Input {
            inhibit_mapping: true,
            ..only(&[1])
        };
        assert_eq!(outcome(&mapped, &no_mapping), None);
        assert_eq!(outcome(&plain, &no_mapping), Some((true, 0b1)));
        let any_top = [cert(&[0]), cert(&[1])];
        assert_eq!(outcome(&any_top, &only(&[1])), Some((true, 0b1)));
        let no_any = Input {
            inhibit_any: true,
            ..only(&[1])
        };
        assert_eq!(outcome(&any_top, &no_any), None);
        assert_eq!(outcome(&plain, &no_any), Some((true, 0b1)));
        // A self-issued certificate may assert anyPolicy all the same.
        let rollover = [
            Spec {
                self_issued: true,
                ..cert(&[0])
            },
            cert(&[1]),
        ];
        assert_eq!(outcome(&rollover, &no_any), Some((true, 0b1)));
    }

    /// REQ-X509-090: inputs that cannot be evaluated are the caller's
    /// error, and a caller that names anyPolicy accepts any policy.
    #[test]
    fn unusable_policy_inputs_are_invalid_config() {
        let one = [cert(&[1])];
        let certs = |path: &[Spec]| -> Vec<Encoded> { path.iter().map(encode).collect() };
        let encoded = certs(&one);
        let path = [PolicyCert {
            policies: Policies {
                policies: encoded[0].policies.as_deref(),
                ..Policies::default()
            },
            self_issued: false,
        }];
        let p1 = oid(1);
        let many = vec![p1.as_slice(); MAX_ACCEPTABLE + 1];
        let e = check(&path, &PolicyOptions::require(&many)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig);
        let full = &many[..MAX_ACCEPTABLE];
        let outcome = check(&path, &PolicyOptions::require(full)).unwrap();
        assert_eq!(outcome.valid, u64::MAX);
        assert!(outcome.is_valid(0) && outcome.is_valid(63) && !outcome.is_valid(64));
        for not_an_oid in [&[][..], &[0x80, 0x01], &[0x2a, 0x81]] {
            let list = [p1.as_slice(), not_an_oid];
            let e = check(&path, &PolicyOptions::require(&list)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{not_an_oid:?}");
        }
        // anyPolicy among the caller's policies is any policy: nothing is
        // reported valid by name, and a policy the caller did not name does.
        let p2 = oid(2);
        let with_any = [p2.as_slice(), ANY_POLICY];
        let outcome = check(&path, &PolicyOptions::require(&with_any)).unwrap();
        assert_eq!((outcome.required, outcome.valid), (true, 0));
        let without = [p2.as_slice()];
        check(&path, &PolicyOptions::require(&without)).unwrap_err();
        assert_eq!(PolicyOptions::any(), PolicyOptions::default());
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
        check(&[], &PolicyOptions::any()).unwrap();
    }
}
