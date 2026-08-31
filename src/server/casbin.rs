use crate::database::Uuid;
use crate::error::Error;
use crate::server::error::ServerError;
use {
    crate::database::models::{CasbinRule, CasbinRuleGroup, GroupType},
    petgraph::stable_graph::{NodeIndex, StableDiGraph},
    petgraph::visit::{Bfs, Walker},
    std::collections::HashMap,
};

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
                r.v0_object_label,
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
    ) -> Result<Self, Error> {
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

    pub fn match_sub(&self, policies: Vec<CasbinRule>, sub: Uuid) -> Vec<CasbinRule> {
        policies
            .into_iter()
            .filter(|p| p.v0 == sub || self.match_role(sub, p.v0, GroupType::Subject))
            .collect()
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
) -> Result<StableDiGraph<RuleNode, ()>, Error> {
    let mut g = StableDiGraph::<RuleNode, ()>::new();

    for r in rules.into_iter() {
        let r_v0 = r.v0;
        let r_v1 = r.v1;
        let (v0_rg, v1_rg) = RuleNode::from(r)?;

        let u = *hm.entry(r_v0).or_insert_with(|| g.add_node(v0_rg));
        let v = *hm.entry(r_v1).or_insert_with(|| g.add_node(v1_rg));
        g.add_edge(v, u, ());
    }

    Ok(g)
}
