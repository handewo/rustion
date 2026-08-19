use crate::database::Uuid;
use crate::error::Error;
use crate::server::error::ServerError;
use std::fmt;
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
    g1: StableDiGraph<RuleGroup, ()>,
    g2: StableDiGraph<RuleGroup, ()>,
    g3: StableDiGraph<RuleGroup, ()>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleGroup {
    V0(Group),
    V1(Group),
}

impl RuleGroup {
    pub fn from_v0(r: &CasbinRuleGroup) -> Result<Self, Error> {
        Ok(RuleGroup::V0(Group {
            id: r.id,
            v: r.v0,
            label: Label::from_v0(r)?,
        }))
    }
    pub fn from_v1(r: &CasbinRuleGroup) -> Result<Self, Error> {
        Ok(RuleGroup::V1(Group {
            id: r.id,
            v: r.v1,
            label: Label::from_v1(r)?,
        }))
    }

    pub fn label(&self) -> String {
        match self {
            RuleGroup::V0(v) => v.label.to_string(),
            RuleGroup::V1(v) => v.label.to_string(),
        }
    }

    pub fn fetch_role(&self) -> Uuid {
        match self {
            RuleGroup::V0(v) => v.v,
            RuleGroup::V1(v) => v.v,
        }
    }

    pub fn get_type(&self) -> Type {
        match self {
            RuleGroup::V0(v) => v.label.get_type(),
            RuleGroup::V1(v) => v.label.get_type(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    Object,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Group {
    pub id: Uuid,
    pub v: Uuid,
    pub label: Label,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Label {
    Object(String),
    Group(String),
}

impl Label {
    pub fn from_v0(r: &CasbinRuleGroup) -> Result<Self, Error> {
        match (&r.v0_object_label, &r.v0_group_label) {
            (Some(v), None) => Ok(Self::Object(v.clone())),
            (None, Some(v)) => Ok(Self::Group(v.clone())),
            _ => Err(Error::Server(ServerError::InvalidRuleGroup)),
        }
    }

    pub fn from_v1(r: &CasbinRuleGroup) -> Result<Self, Error> {
        match (&r.v1_object_label, &r.v1_group_label) {
            (Some(v), None) => Ok(Self::Object(v.clone())),
            (None, Some(v)) => Ok(Self::Group(v.clone())),
            _ => Err(Error::Server(ServerError::InvalidRuleGroup)),
        }
    }

    pub fn get_type(&self) -> Type {
        match self {
            Label::Object(_) => Type::Object,
            Label::Group(_) => Type::Group,
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Object(s) => write!(f, "{s}"),
            Self::Group(s) => write!(f, "{s}"),
        }
    }
}

impl RoleManage {
    pub fn new(
        r1: &[CasbinRuleGroup],
        r2: &[CasbinRuleGroup],
        r3: &[CasbinRuleGroup],
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

    pub fn get_group(&self, rt: GroupType) -> StableDiGraph<RuleGroup, ()> {
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
    rules: &[CasbinRuleGroup],
    hm: &mut HashMap<Uuid, NodeIndex>,
) -> Result<StableDiGraph<RuleGroup, ()>, Error> {
    let mut g = StableDiGraph::<RuleGroup, ()>::new();

    for r in rules {
        let v0_rg = RuleGroup::from_v0(r)?;
        let v1_rg = RuleGroup::from_v1(r)?;

        let u = *hm.entry(r.v0).or_insert_with(|| g.add_node(v0_rg));
        let v = *hm.entry(r.v1).or_insert_with(|| g.add_node(v1_rg));
        g.add_edge(v, u, ());
    }

    Ok(g)
}
