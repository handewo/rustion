use crate::database::Uuid;
use crate::server::error::ServerError;
use crate::server::extend_policy::{CompiledExtendPolicy, ExtendPolicyReq, verify_extend_policy};
use log::{trace, warn};
use std::sync::Arc;
use {
    crate::database::models::{CasbinRule, CasbinRuleGroup, CommandSet, GroupType},
    petgraph::stable_graph::{NodeIndex, StableDiGraph},
    petgraph::visit::{Bfs, Walker},
    std::collections::HashMap,
};

/// Everything a permission check is decided from: the three role graphs and
/// the `p` rules, read from `casbin_rule` together, and the active command
/// sets, which `p` rules grant like actions.
///
/// The server keeps one in memory, loaded at startup, and replaces it whole on
/// every reload, so a check never pairs new policies with old graphs. Reloads
/// come from the admin TUI after each write to `casbin_rule`, from
/// `flush_privileges` in the admin shell, and, when `policy_reload_interval`
/// is not zero, from a timer.
pub struct Snapshot {
    pub roles: RoleManage,
    pub policies: Vec<Policy>,
    /// Active sets whose config compiles, ordered by name.
    pub command_sets: Vec<Arc<CompiledCommandSet>>,
}

/// A command set with its config compiled once at load.
#[derive(Debug)]
pub struct CompiledCommandSet {
    pub id: Uuid,
    pub name: String,
    pub policy: crate::command::Policy,
}

impl CompiledCommandSet {
    /// `None`, with a warning, when the stored config does not compile. The
    /// editor refuses such a config, so like a bad `v3` it was written by
    /// hand, and the set then grants nothing rather than failing the load.
    fn new(set: CommandSet) -> Option<Self> {
        match crate::command::Policy::from_json(&set.config) {
            Ok(policy) => Some(Self {
                id: set.id,
                name: set.name,
                policy,
            }),
            Err(e) => {
                warn!(
                    "Command set '{}({})' grants nothing: its config is invalid: {}",
                    set.name, set.id, e
                );
                None
            }
        }
    }
}

/// A `p` rule, with its `v3` parsed once at load rather than on every check.
pub struct Policy {
    pub rule: CasbinRule,
    /// `None` when `v3` does not parse or is invalid, and the policy then
    /// grants nothing. The permission editor refuses such a `v3`, so it came
    /// from SQL run by hand, or was saved before a check it now fails (the
    /// per-pattern `sftp_path` regex check). Skipping the rule, rather than
    /// failing the load, keeps one bad row from stopping the server from
    /// starting and every reload from applying, a revoke's included.
    ext: Option<CompiledExtendPolicy>,
}

impl Policy {
    pub fn new(rule: CasbinRule) -> Self {
        let ext = match CompiledExtendPolicy::parse(&rule.v3) {
            Ok(ext) => Some(ext),
            Err(e) => {
                warn!(
                    "Policy {} grants nothing: its extended policy {:?} is invalid: {}",
                    rule.id, rule.v3, e
                );
                None
            }
        };
        Self { rule, ext }
    }
}

impl Snapshot {
    /// `sets` are the active command sets.
    pub fn new(roles: RoleManage, rules: Vec<CasbinRule>, sets: Vec<CommandSet>) -> Self {
        let command_sets: Vec<_> = sets
            .into_iter()
            .filter_map(CompiledCommandSet::new)
            .map(Arc::new)
            .collect();
        Self {
            roles,
            policies: rules.into_iter().map(Policy::new).collect(),
            command_sets,
        }
    }

    /// The command sets some policy grants `sub` on `obj` for this request,
    /// by name. Like [`Self::grants`], whether `obj` is active is left to the
    /// caller.
    pub fn granted_command_sets(
        &self,
        sub: Uuid,
        obj: Uuid,
        ext: &ExtendPolicyReq,
    ) -> Result<Vec<Arc<CompiledCommandSet>>, ServerError> {
        let mut out = Vec::new();
        for set in &self.command_sets {
            if self.grants(sub, obj, set.id, ext)? {
                out.push(set.clone());
            }
        }
        Ok(out)
    }

    /// The policies whose subject is `sub` or a role `sub` has.
    pub fn match_sub(&self, sub: Uuid) -> impl Iterator<Item = &Policy> {
        self.policies.iter().filter(move |p| {
            p.rule.v0 == sub || self.roles.match_role(sub, p.rule.v0, GroupType::Subject)
        })
    }

    /// Whether some policy grants `act` on `obj` to `sub` for this request.
    ///
    /// Only the rules are consulted. Whether `obj` is active is not in the
    /// snapshot, so the caller checks that against the database.
    /// TODO: Check if group is active
    pub fn grants(
        &self,
        sub: Uuid,
        obj: Uuid,
        act: Uuid,
        ext: &ExtendPolicyReq,
    ) -> Result<bool, ServerError> {
        for pol in self.match_sub(sub) {
            let rule = &pol.rule;
            if !(rule.v1 == obj || self.roles.match_role(rule.v1, obj, GroupType::Object)) {
                trace!(
                    "Reject by object, sub: {}, obj: {}, policy: {:?}",
                    sub, obj, rule
                );
                continue;
            }
            if !(rule.v2 == act || self.roles.match_role(rule.v2, act, GroupType::Action)) {
                trace!(
                    "Reject by action, sub: {}, act: {}, policy: {:?}",
                    sub, act, rule
                );
                continue;
            }
            let Some(compiled) = &pol.ext else {
                trace!(
                    "Reject by invalid extend policy, sub: {}, policy: {:?}",
                    sub, rule
                );
                continue;
            };
            if verify_extend_policy(ext, compiled)? {
                trace!("Accept sub: {}, policy: {:?}", sub, rule);
                return Ok(true);
            }
            trace!(
                "Reject by extend policy, sub: {}, ext: {:?}, policy: {:?}",
                sub, ext, rule
            );
        }
        Ok(false)
    }
}

pub struct RoleManage {
    h1: HashMap<Uuid, NodeIndex>,
    h2: HashMap<Uuid, NodeIndex>,
    h3: HashMap<Uuid, NodeIndex>,
    g1: StableDiGraph<RuleNode, ()>,
    g2: StableDiGraph<RuleNode, ()>,
    g3: StableDiGraph<RuleNode, ()>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleNode {
    V0(RuleInfo),
    V1(RuleInfo),
}

impl RuleNode {
    pub fn from(r: CasbinRuleGroup) -> Result<(Self, Self), ServerError> {
        Ok((
            RuleNode::V0(RuleInfo::parse_casbin_rule_group(
                r.id,
                r.v0,
                r.v0_object_label.or(r.v0_command_set),
                r.v0_group_label,
            )?),
            RuleNode::V1(RuleInfo::parse_casbin_rule_group(
                r.id,
                r.v1,
                r.v1_object_label,
                r.v1_group_label,
            )?),
        ))
    }

    pub fn label(&self) -> String {
        match self {
            RuleNode::V0(v) => v.label.to_string(),
            RuleNode::V1(v) => v.label.to_string(),
        }
    }

    pub fn fetch_role(&self) -> Uuid {
        match self {
            RuleNode::V0(v) => v.v_id,
            RuleNode::V1(v) => v.v_id,
        }
    }

    pub fn get_type(&self) -> RuleType {
        match self {
            RuleNode::V0(v) => v.v_type,
            RuleNode::V1(v) => v.v_type,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RuleType {
    Object,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleInfo {
    pub id: Uuid,
    pub v_id: Uuid,
    pub v_type: RuleType,
    pub label: String,
}

impl RuleInfo {
    pub fn parse_casbin_rule_group(
        id: Uuid,
        v_id: Uuid,
        object_label: Option<String>,
        group_label: Option<String>,
    ) -> Result<Self, ServerError> {
        match (object_label, group_label) {
            (Some(label), None) => Ok(RuleInfo {
                id,
                v_id,
                v_type: RuleType::Object,
                label,
            }),
            (None, Some(label)) => Ok(RuleInfo {
                id,
                v_id,
                v_type: RuleType::Group,
                label,
            }),
            _ => Err(ServerError::InvalidRuleGroup),
        }
    }
}

impl RoleManage {
    pub fn new(
        r1: Vec<CasbinRuleGroup>,
        r2: Vec<CasbinRuleGroup>,
        r3: Vec<CasbinRuleGroup>,
    ) -> Result<Self, ServerError> {
        let mut h1 = HashMap::new();
        let g1 = build_graph(r1, &mut h1)?;
        let mut h2 = HashMap::new();
        let g2 = build_graph(r2, &mut h2)?;
        let mut h3 = HashMap::new();
        let g3 = build_graph(r3, &mut h3)?;
        Ok(Self {
            h1,
            h2,
            h3,
            g1,
            g2,
            g3,
        })
    }

    pub fn get_group(&self, rt: GroupType) -> StableDiGraph<RuleNode, ()> {
        match rt {
            GroupType::Subject => self.g1.clone(),
            GroupType::Object => self.g2.clone(),
            GroupType::Action => self.g3.clone(),
        }
    }

    pub fn fetch_role_from_start(&self, start: Uuid, rt: GroupType) -> Vec<Uuid> {
        match rt {
            GroupType::Subject => {
                let start = if let Some(n) = self.h1.get(&start) {
                    n
                } else {
                    return Vec::new();
                };
                Bfs::new(&self.g1, *start)
                    .iter(&self.g1)
                    .map(|n| {
                        self.g1
                            .node_weight(n)
                            .expect("node should not be none")
                            .fetch_role()
                    })
                    .collect::<Vec<_>>()
            }
            GroupType::Object => {
                let start = if let Some(n) = self.h2.get(&start) {
                    n
                } else {
                    return Vec::new();
                };
                Bfs::new(&self.g2, *start)
                    .iter(&self.g2)
                    .map(|n| {
                        self.g2
                            .node_weight(n)
                            .expect("node should not be none")
                            .fetch_role()
                    })
                    .collect::<Vec<_>>()
            }
            GroupType::Action => {
                let start = if let Some(n) = self.h3.get(&start) {
                    n
                } else {
                    return Vec::new();
                };
                Bfs::new(&self.g3, *start)
                    .iter(&self.g3)
                    .map(|n| {
                        self.g3
                            .node_weight(n)
                            .expect("node should not be none")
                            .fetch_role()
                    })
                    .collect::<Vec<_>>()
            }
        }
    }

    pub fn match_role(&self, start: Uuid, req: Uuid, rt: GroupType) -> bool {
        match rt {
            GroupType::Subject => {
                let start = if let Some(n) = self.h1.get(&start) {
                    n
                } else {
                    return false;
                };
                let node = if let Some(n) = self.h1.get(&req) {
                    n
                } else {
                    return false;
                };
                Bfs::new(&self.g1, *start)
                    .iter(&self.g1)
                    .any(|n| &n == node)
            }
            GroupType::Object => {
                let start = if let Some(n) = self.h2.get(&start) {
                    n
                } else {
                    return false;
                };
                let node = if let Some(n) = self.h2.get(&req) {
                    n
                } else {
                    return false;
                };
                Bfs::new(&self.g2, *start)
                    .iter(&self.g2)
                    .any(|n| &n == node)
            }
            GroupType::Action => {
                let start = if let Some(n) = self.h3.get(&start) {
                    n
                } else {
                    return false;
                };
                let node = if let Some(n) = self.h3.get(&req) {
                    n
                } else {
                    return false;
                };
                Bfs::new(&self.g3, *start)
                    .iter(&self.g3)
                    .any(|n| &n == node)
            }
        }
    }
}

fn build_graph(
    rules: Vec<CasbinRuleGroup>,
    hm: &mut HashMap<Uuid, NodeIndex>,
) -> Result<StableDiGraph<RuleNode, ()>, ServerError> {
    let mut g = StableDiGraph::<RuleNode, ()>::new();

    for r in rules.into_iter() {
        // An end with no label names a row that was deleted, from before deletes
        // took their rules with them. It can match nothing, so the rule is
        // dropped rather than keeping the server from starting.
        if (r.v0_object_label.is_none() && r.v0_group_label.is_none() && r.v0_command_set.is_none())
            || (r.v1_object_label.is_none() && r.v1_group_label.is_none())
        {
            warn!(
                "Skipping casbin_rule {}: it names a deleted row (v0={}, v1={})",
                r.id, r.v0, r.v1
            );
            continue;
        }
        let r_v0 = r.v0;
        let r_v1 = r.v1;
        let (v0_rg, v1_rg) = RuleNode::from(r)?;

        let u = *hm.entry(r_v0).or_insert_with(|| g.add_node(v0_rg));
        let v = *hm.entry(r_v1).or_insert_with(|| g.add_node(v1_rg));
        g.add_edge(v, u, ());
    }

    Ok(g)
}
