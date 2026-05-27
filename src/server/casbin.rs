use crate::database::Uuid;
use crate::error::Error;
use crate::server::error::{ExtendPolicyError, ServerError};
use ipnetwork::IpNetwork;
use log::trace;
use std::fmt;
use std::fmt::Display;
use std::net::IpAddr;
use {
    crate::database::models::{CasbinRule, CasbinRuleGroup},
    petgraph::stable_graph::{NodeIndex, StableDiGraph},
    petgraph::visit::{Bfs, Walker},
    std::collections::HashMap,
};

use chrono::{DateTime, FixedOffset, NaiveTime, Utc};
use serde::{Deserialize, Serialize, de};
use std::str::FromStr;

pub struct RoleManage {
    h1: HashMap<Uuid, NodeIndex>,
    h2: HashMap<Uuid, NodeIndex>,
    h3: HashMap<Uuid, NodeIndex>,
    g1: StableDiGraph<RuleGroup, ()>,
    g2: StableDiGraph<RuleGroup, ()>,
    g3: StableDiGraph<RuleGroup, ()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupType {
    Subject,
    Object,
    Action,
}

impl From<GroupType> for &str {
    fn from(value: GroupType) -> Self {
        match value {
            GroupType::Subject => "g1",
            GroupType::Object => "g2",
            GroupType::Action => "g3",
        }
    }
}

impl Display for GroupType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subject => write!(f, "g1"),
            Self::Object => write!(f, "g2"),
            Self::Action => write!(f, "g3"),
        }
    }
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
/// This is used for p.ext
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtendPolicy {
    pub ip_policy: Option<IpPolicy>,
    pub start_time: Option<TimeWithOffset>,
    pub end_time: Option<TimeWithOffset>,
    pub expire_date: Option<DateTime<FixedOffset>>,
}

impl ExtendPolicy {
    pub fn validate(&self) -> Result<(), ExtendPolicyError> {
        // ensure start_time and end_time are consistent
        match (&self.start_time, &self.end_time) {
            (Some(_), None) => Err(ExtendPolicyError::EndTimeAbsent),
            (None, Some(_)) => Err(ExtendPolicyError::StartTimeAbsent),
            (Some(s), Some(e)) if s.offset != e.offset => Err(ExtendPolicyError::DifferentTimezone),

            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TimeWithOffset {
    pub time: NaiveTime,
    pub offset: FixedOffset,
}

impl Serialize for TimeWithOffset {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        // "12:23 +0800"
        serializer.serialize_str(&format!("{} {}", self.time.format("%H:%M"), self.offset,))
    }
}

impl<'de> Deserialize<'de> for TimeWithOffset {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let (time_str, offset_str) = s
            .rsplit_once(' ')
            .ok_or_else(|| serde::de::Error::custom("expected 'HH:MM ±HH:MM'"))?;
        let time =
            NaiveTime::parse_from_str(time_str, "%H:%M").map_err(serde::de::Error::custom)?;
        let offset = FixedOffset::from_str(offset_str).map_err(serde::de::Error::custom)?;
        Ok(TimeWithOffset { time, offset })
    }
}

/// This is used for r.ext
#[derive(Debug)]
pub struct ExtendPolicyReq {
    pub ip: Option<IpAddr>,
    pub now: DateTime<Utc>,
}

impl Default for ExtendPolicyReq {
    fn default() -> Self {
        ExtendPolicyReq {
            ip: None,
            now: Utc::now(),
        }
    }
}

impl ExtendPolicyReq {
    pub fn new(ip: Option<IpAddr>) -> Self {
        ExtendPolicyReq {
            ip,
            now: Utc::now(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum IpPolicy {
    Allow(IpNetwork),
    Deny(IpNetwork),
}

pub fn verify_extend_policy(ext_req: &ExtendPolicyReq, ext_str: &str) -> Result<bool, Error> {
    trace!("ext_req: {:?} ext_str: \"{}\"", ext_req, ext_str);
    let ext: ExtendPolicy = serde_json::from_str(ext_str)?;
    ext.validate().map_err(ServerError::ExtendPolicy)?;
    if !is_ip_in_cidr(ext_req.ip, ext.ip_policy) {
        return Ok(false);
    }
    let now = ext_req.now;
    let start_time = ext
        .start_time
        .map(|t| parse_time(&now, &t))
        .transpose()
        .map_err(ServerError::ExtendPolicy)?;
    let end_time = ext
        .end_time
        .map(|t| parse_time(&now, &t))
        .transpose()
        .map_err(ServerError::ExtendPolicy)?;
    if !is_in_period(now, start_time, end_time) {
        return Ok(false);
    }
    if let Some(ep) = ext.expire_date
        && ext_req.now >= ep
    {
        return Ok(false);
    }
    Ok(true)
}

fn parse_time(
    now: &DateTime<Utc>,
    policy_time: &TimeWithOffset,
) -> Result<DateTime<FixedOffset>, ExtendPolicyError> {
    now.with_timezone(&policy_time.offset)
        .with_time(policy_time.time)
        .single()
        .ok_or(ExtendPolicyError::InvalidSingleTime)
}

/// Returns true if `t` is in the half-open period `[start, end)`.
/// Handles midnight wrap-arounds automatically.
pub fn is_in_period(
    t: DateTime<Utc>,
    start: Option<DateTime<FixedOffset>>,
    end: Option<DateTime<FixedOffset>>,
) -> bool {
    match (start, end) {
        (Some(_), None) | (None, Some(_)) => false,
        (Some(s), Some(e)) => {
            if start <= end {
                t >= s && t < e
            } else {
                t >= s || t < e
            }
        }
        (None, None) => true,
    }
}

/// Check if an IP address is within a CIDR range
///
/// # Arguments
/// * `ip` - The IP address to check (can be IPv4 or IPv6)
/// * `cidr` - The CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/32")
pub fn is_ip_in_cidr(ip: Option<IpAddr>, ip_policy: Option<IpPolicy>) -> bool {
    match (ip, ip_policy) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(ip), Some(policy)) => match policy {
            IpPolicy::Allow(cidr) => cidr.contains(ip),
            IpPolicy::Deny(cidr) => !cidr.contains(ip),
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveTime, TimeZone};

    #[test]
    fn test_parse_extend_policy() {
        let input = r#"{"ip_policy":{"Deny":"192.168.0.0/16"},"start_time":"11:30 +08:00","end_time":"17:30 +0800","expire_date":"2025-09-10 16:30:00 +0800"}"#;
        let policy: ExtendPolicy = serde_json::from_str(input).unwrap();

        let offset = FixedOffset::east_opt(8 * 3600).unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Deny(ref ip)) if ip == &IpNetwork::from_str("192.168.0.0/16").unwrap())
        );
        assert_eq!(
            parse_time(&Utc::now(), &policy.start_time.unwrap()).unwrap(),
            Utc::now()
                .with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(11, 30, 0).unwrap())
                .unwrap()
        );
        assert_eq!(
            parse_time(&Utc::now(), &policy.end_time.unwrap()).unwrap(),
            Utc::now()
                .with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(17, 30, 0).unwrap())
                .unwrap()
        );
        assert_eq!(
            policy.expire_date,
            Some(
                offset
                    .from_local_datetime(
                        &NaiveDate::from_ymd_opt(2025, 9, 10)
                            .unwrap()
                            .and_hms_opt(16, 30, 0)
                            .unwrap()
                    )
                    .unwrap()
            )
        );

        let input = r#"{"ip_policy":{"Allow":"10.0.0.0/8"},"start_time":"08:00 -0330","end_time":"20:00 -0330","expire_date":"2030-01-01 00:00:00 -0330"}"#;
        let policy: ExtendPolicy = serde_json::from_str(input).unwrap();

        let offset = FixedOffset::west_opt(3 * 3600 + 1800).unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Allow(ref ip)) if ip == &IpNetwork::from_str("10.0.0.0/8").unwrap())
        );
        assert_eq!(
            parse_time(&Utc::now(), &policy.start_time.unwrap()).unwrap(),
            Utc::now()
                .with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(8, 0, 0).unwrap())
                .unwrap()
        );
        assert_eq!(
            parse_time(&Utc::now(), &policy.end_time.unwrap()).unwrap(),
            Utc::now()
                .with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(20, 0, 0).unwrap())
                .unwrap()
        );
        assert_eq!(
            policy.expire_date,
            Some(
                offset
                    .from_local_datetime(
                        &NaiveDate::from_ymd_opt(2030, 1, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap()
                    )
                    .unwrap()
            )
        );

        let input = r#"{"ip_policy":{"Allow":"10.0.0.0/8"},"start_time":"08:00 -08:00","end_time":null,"expire_date":"2030-01-01 00:00:00 -0330"}"#;
        let policy: ExtendPolicy = serde_json::from_str(input).unwrap();
        assert_eq!(policy.validate(), Err(ExtendPolicyError::EndTimeAbsent));
        let input = r#"{"ip_policy":{"Allow":"10.0.0.0/8"},"start_time":null,"end_time":"08:00 -0800","expire_date":"2030-01-01 00:00:00 -0330"}"#;
        let policy: ExtendPolicy = serde_json::from_str(input).unwrap();
        assert_eq!(policy.validate(), Err(ExtendPolicyError::StartTimeAbsent));
        let input = r#"{"ip_policy":{"Allow":"10.0.0.0/8"}}"#;
        assert!(serde_json::from_str::<ExtendPolicy>(input).is_ok());
        let input = "{}";
        assert!(serde_json::from_str::<ExtendPolicy>(input).is_ok());
        let input = r#"{"ip_policy":{"Allow":"1000.0.0.0/8"}}"#;
        assert!(serde_json::from_str::<ExtendPolicy>(input).is_err());
        let input = r#"{"ip_policy":{"Allow":"10.0.0.0/80"}}"#;
        assert!(serde_json::from_str::<ExtendPolicy>(input).is_err());

        let input = r#"{"ip_policy":{"Allow":"10.0.0.0/8"},"start_time":null,"end_time":null,"expire_date":"2030-01-01 00:00:00 +0000"}"#;
        let policy: ExtendPolicy = serde_json::from_str(input).unwrap();
        let offset = FixedOffset::east_opt(0).unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Allow(ref ip)) if ip == &IpNetwork::from_str("10.0.0.0/8").unwrap())
        );
        assert!(policy.start_time.is_none());
        assert!(policy.end_time.is_none());
        assert_eq!(
            policy.expire_date,
            Some(
                offset
                    .from_local_datetime(
                        &NaiveDate::from_ymd_opt(2030, 1, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap()
                    )
                    .unwrap()
            )
        );

        let input = r#"{"ip_policy":{"Allow":"10.0.0.0/8"},"start_time":null,"end_time":null}"#;
        let policy: ExtendPolicy = serde_json::from_str(input).unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Allow(ref ip)) if ip == &IpNetwork::from_str("10.0.0.0/8").unwrap())
        );
        assert!(policy.start_time.is_none());
        assert!(policy.end_time.is_none());
        assert!(policy.expire_date.is_none());
    }

    #[test]
    fn test_serde_extend_policy() {
        let offset = FixedOffset::east_opt(3 * 3600).unwrap();
        let ext = ExtendPolicy {
            ip_policy: Some(IpPolicy::Allow(IpNetwork::from_str("10.0.0.0/8").unwrap())),
            start_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
                offset,
            }),
            end_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(20, 0, 0).unwrap(),
                offset,
            }),
            expire_date: Some(
                offset
                    .from_local_datetime(
                        &NaiveDate::from_ymd_opt(2030, 1, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap(),
                    )
                    .unwrap(),
            ),
        };
        let serialized = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            serialized,
            r#"{"ip_policy":{"Allow":"10.0.0.0/8"},"start_time":"08:00 +03:00","end_time":"20:00 +03:00","expire_date":"2030-01-01T00:00:00+03:00"}"#
        );

        let ext = ExtendPolicy {
            ip_policy: Some(IpPolicy::Deny(IpNetwork::from_str("10.0.0.0/8").unwrap())),
            start_time: None,
            end_time: None,
            expire_date: Some(
                offset
                    .from_local_datetime(
                        &NaiveDate::from_ymd_opt(2030, 1, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap(),
                    )
                    .unwrap(),
            ),
        };
        let serialized = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            serialized,
            r#"{"ip_policy":{"Deny":"10.0.0.0/8"},"start_time":null,"end_time":null,"expire_date":"2030-01-01T00:00:00+03:00"}"#
        );

        let ext = ExtendPolicy {
            ip_policy: None,
            start_time: None,
            end_time: None,
            expire_date: Some(
                offset
                    .from_local_datetime(
                        &NaiveDate::from_ymd_opt(2030, 1, 1)
                            .unwrap()
                            .and_hms_opt(0, 0, 0)
                            .unwrap(),
                    )
                    .unwrap(),
            ),
        };
        let serialized = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            serialized,
            r#"{"ip_policy":null,"start_time":null,"end_time":null,"expire_date":"2030-01-01T00:00:00+03:00"}"#
        );

        let ext = ExtendPolicy {
            ip_policy: None,
            start_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
                offset,
            }),
            end_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(8, 35, 0).unwrap(),
                offset,
            }),
            expire_date: None,
        };
        let serialized = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            serialized,
            r#"{"ip_policy":null,"start_time":"08:00 +03:00","end_time":"08:35 +03:00","expire_date":null}"#
        );

        let ext = ExtendPolicy {
            ip_policy: None,
            start_time: None,
            end_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(8, 35, 0).unwrap(),
                offset,
            }),
            expire_date: None,
        };
        let ext_string = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            ext_string,
            r#"{"ip_policy":null,"start_time":null,"end_time":"08:35 +03:00","expire_date":null}"#
        );
        assert!(ext.validate().is_err());
    }

    #[test]
    fn test_is_in_period() {
        let offset = FixedOffset::east_opt(3 * 3600).unwrap();
        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(11, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(10, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(17, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(17, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(10, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(17, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(10, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(10, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(17, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(18, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(10, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(17, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(11, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(10, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(17, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(21, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(20, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(6, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(6, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(20, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(6, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(20, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(20, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(6, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(1, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(20, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(6, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(19, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(9, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(8, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(9, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(19, 59, 1)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(20, 30, 1)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(20, 30, 0)
            .unwrap()
            .and_utc();
        let start = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(20, 30, 0)
            .unwrap()
            .and_utc();
        let start = None;
        let end = None;
        assert!(super::is_in_period(t, start, end));

        let t = NaiveDate::from_ymd_opt(2000, 1, 1)
            .unwrap()
            .and_hms_opt(20, 30, 0)
            .unwrap()
            .and_utc();
        let start = None;
        let end = Some(
            t.with_timezone(&offset)
                .with_time(NaiveTime::from_hms_opt(23, 30, 0).unwrap())
                .unwrap(),
        );
        assert!(!super::is_in_period(t, start, end));
    }

    #[test]
    fn test_is_ip_in_cidr() {
        use super::IpPolicy;
        assert!(super::is_ip_in_cidr(None, None));

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let cidr: IpPolicy = IpPolicy::Allow("192.168.1.0/24".parse().unwrap());
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        assert!(!is_ip_in_cidr(None, Some(cidr)));

        let ip: IpAddr = "192.168.1.0".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "192.168.1.255".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "192.168.2.1".parse().unwrap();
        assert!(!is_ip_in_cidr(Some(ip), Some(cidr)));

        let cidr: IpPolicy = IpPolicy::Allow("192.168.1.100/32".parse().unwrap());
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "192.168.1.101".parse().unwrap();
        assert!(!is_ip_in_cidr(Some(ip), Some(cidr)));

        let cidr: IpPolicy = IpPolicy::Allow("192.168.1.128/25".parse().unwrap());

        let ip: IpAddr = "192.168.1.128".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "192.168.1.129".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "192.168.1.127".parse().unwrap();
        assert!(!is_ip_in_cidr(Some(ip), Some(cidr)));

        let cidr: IpPolicy = IpPolicy::Allow("2001:db8::/64".parse().unwrap());

        let ip: IpAddr = "2001:0db8::1".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "2001:db8::ffff:ffff:ffff:ffff".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(!is_ip_in_cidr(Some(ip), Some(cidr)));

        let cidr: IpPolicy = IpPolicy::Deny("192.168.1.0/24".parse().unwrap());
        let ip: IpAddr = "192.168.1.0".parse().unwrap();
        assert!(!is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "192.168.1.255".parse().unwrap();
        assert!(!is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "192.168.2.1".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));

        let ip: IpAddr = "1.1.2.1".parse().unwrap();
        assert!(is_ip_in_cidr(Some(ip), Some(cidr)));
    }
}
