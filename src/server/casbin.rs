use crate::error::Error;
use ipnetwork::IpNetwork;
use log::trace;
use std::fmt;
use std::net::IpAddr;
#[cfg(feature = "full-role")]
use {
    crate::database::models::CasbinRule,
    petgraph::stable_graph::{NodeIndex, StableDiGraph},
    petgraph::visit::{Bfs, Walker},
    std::collections::HashMap,
};

use chrono::{DateTime, FixedOffset, NaiveTime, Utc};
use serde::{ser, Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

#[cfg(feature = "full-role")]
pub struct RoleManage {
    h1: HashMap<String, NodeIndex>,
    h2: HashMap<String, NodeIndex>,
    h3: HashMap<String, NodeIndex>,
    g1: StableDiGraph<String, ()>,
    g2: StableDiGraph<String, ()>,
    g3: StableDiGraph<String, ()>,
}

#[cfg(feature = "full-role")]
pub enum RoleType {
    Subject,
    Object,
    Action,
}

#[cfg(feature = "full-role")]
impl RoleManage {
    pub fn new(r1: &[CasbinRule], r2: &[CasbinRule], r3: &[CasbinRule]) -> Self {
        let mut h1 = HashMap::new();
        let g1 = build_graph(r1, &mut h1);
        let mut h2 = HashMap::new();
        let g2 = build_graph(r2, &mut h2);
        let mut h3 = HashMap::new();
        let g3 = build_graph(r3, &mut h3);
        Self {
            h1,
            h2,
            h3,
            g1,
            g2,
            g3,
        }
    }

    pub fn get_group(&self, rt: RoleType) -> StableDiGraph<String, ()> {
        match rt {
            RoleType::Subject => self.g1.clone(),
            RoleType::Object => self.g2.clone(),
            RoleType::Action => self.g3.clone(),
        }
    }

    pub fn match_sub(
        &self,
        policies: Vec<CasbinRule>,
        roles: &Vec<CasbinRule>,
        sub: &str,
    ) -> Vec<CasbinRule> {
        policies
            .into_iter()
            .filter(|p| {
                if p.v0 == sub {
                    return true;
                };
                for r in roles {
                    // exclude user_id
                    if uuid::Uuid::from_str(&p.v0).is_err()
                        && self.match_role(&r.v1, &p.v0, RoleType::Subject)
                    {
                        return true;
                    }
                }
                false
            })
            .collect()
    }

    pub fn fetch_role_from_start(&self, start: &str, rt: RoleType) -> Vec<&str> {
        match rt {
            RoleType::Subject => todo!(),
            RoleType::Object => {
                let start = if let Some(n) = self.h2.get(start) {
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
                            .as_str()
                    })
                    .collect::<Vec<_>>()
            }
            RoleType::Action => todo!(),
        }
    }

    pub fn match_role(&self, start: &str, req: &str, rt: RoleType) -> bool {
        match rt {
            RoleType::Subject => {
                let start = if let Some(n) = self.h1.get(start) {
                    n
                } else {
                    return false;
                };
                let node = if let Some(n) = self.h1.get(req) {
                    n
                } else {
                    return false;
                };
                Bfs::new(&self.g1, *start)
                    .iter(&self.g1)
                    .any(|n| &n == node)
            }
            RoleType::Object => {
                let start = if let Some(n) = self.h2.get(start) {
                    n
                } else {
                    return false;
                };
                let node = if let Some(n) = self.h2.get(req) {
                    n
                } else {
                    return false;
                };
                Bfs::new(&self.g2, *start)
                    .iter(&self.g2)
                    .any(|n| &n == node)
            }
            RoleType::Action => {
                let start = if let Some(n) = self.h3.get(start) {
                    n
                } else {
                    return false;
                };
                let node = if let Some(n) = self.h3.get(req) {
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
#[derive(Debug, PartialEq)]
pub struct ExtendPolicy {
    pub ip_policy: Option<IpPolicy>,
    pub start_time: Option<DateTime<FixedOffset>>,
    pub end_time: Option<DateTime<FixedOffset>>,
    pub expire_date: Option<DateTime<FixedOffset>>,
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

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IpPolicy {
    Allow(IpNetwork),
    Deny(IpNetwork),
}

pub fn verify_extend_policy(ext_req: &ExtendPolicyReq, ext_str: &str) -> Result<bool, Error> {
    trace!("ext_req: {:?} ext_str: \"{}\"", ext_req, ext_str);
    let ext: ExtendPolicy = ext_str.parse().map_err(Error::Casbin)?;
    if !is_ip_in_cidr(ext_req.ip, ext.ip_policy) {
        return Ok(false);
    }
    if !is_in_period(ext_req.now, ext.start_time, ext.end_time) {
        return Ok(false);
    }
    if let Some(ep) = ext.expire_date {
        if ext_req.now >= ep {
            return Ok(false);
        }
    }
    Ok(true)
}

impl fmt::Display for ExtendPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if let Some(ip) = &self.ip_policy {
            match ip {
                IpPolicy::Allow(v) => parts.push(v.to_string()),
                IpPolicy::Deny(v) => parts.push(format!("!{}", v)),
            }
        } else {
            parts.push("".to_string());
        }

        if let Some(start) = &self.start_time {
            parts.push(start.format("%H:%M %z").to_string());
        } else {
            parts.push("".to_string());
        }
        if let Some(end) = &self.end_time {
            parts.push(end.format("%H:%M %z").to_string());
        } else {
            parts.push("".to_string());
        }
        if let Some(expire) = &self.expire_date {
            parts.push(expire.format("%Y-%m-%d %H:%M:%S %z").to_string());
        } else {
            parts.push("".to_string());
        }

        write!(f, "{}", parts.join(","))
    }
}

impl FromStr for ExtendPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();

        let ip_policy = if !parts.is_empty() && !parts[0].is_empty() {
            if parts[0].starts_with('!') {
                Some(IpPolicy::Deny(
                    parts[0][1..].parse().map_err(|e| format!("{}", e))?,
                ))
            } else {
                Some(IpPolicy::Allow(
                    parts[0].parse().map_err(|e| format!("{}", e))?,
                ))
            }
        } else {
            None
        };

        let start_time = if parts.len() > 1 && !parts[1].is_empty() {
            Some(parse_time(parts[1]).map_err(|e| format!("invalid start_time: {e}"))?)
        } else {
            None
        };

        let end_time = if parts.len() > 2 && !parts[2].is_empty() {
            Some(parse_time(parts[2]).map_err(|e| format!("invalid end_time: {e}"))?)
        } else {
            None
        };

        // ensure start_time and end_time are consistent
        match (&start_time, &end_time) {
            (Some(_), None) | (None, Some(_)) => {
                return Err("start_time and end_time must both be present or both absent".into())
            }
            (Some(s), Some(e)) => {
                if s.timezone() != e.timezone() {
                    return Err("timezone of start_time and end_time must be equal".into());
                }
            }
            _ => {}
        }

        let expire_date = if parts.len() > 3 && !parts[3].is_empty() {
            Some(
                DateTime::parse_from_str(parts[3], "%Y-%m-%d %H:%M:%S %z")
                    .map_err(|e| format!("invalid expire_date: {e}"))?,
            )
        } else {
            None
        };

        Ok(ExtendPolicy {
            ip_policy,
            start_time,
            end_time,
            expire_date,
        })
    }
}

fn parse_time(time_str: &str) -> Result<DateTime<FixedOffset>, chrono::ParseError> {
    // FIXME: It's better to use the time when request arrive rather than `Utc::now()`.
    let now = Utc::now();
    let s = NaiveTime::parse_from_str(time_str, "%H:%M %z")?;
    let s_tz = FixedOffset::from_str(time_str.split_whitespace().nth(1).unwrap_or("+0000"))?;
    Ok(now.with_timezone(&s_tz).with_time(s).unwrap())
}

impl Serialize for ExtendPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // ensure start_time and end_time are consistent
        match (self.start_time, self.end_time) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ser::Error::custom(
                    "start_time and end_time must both be present or both absent",
                ))
            }
            (Some(s), Some(e)) => {
                if s.timezone() != e.timezone() {
                    return Err(ser::Error::custom(
                        "timezone of start_time and end_time must be equal",
                    ));
                }
            }
            _ => {}
        }

        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ExtendPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ExtendPolicy::from_str(&s).map_err(serde::de::Error::custom)
    }
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

#[cfg(feature = "full-role")]
fn build_graph(
    rules: &[CasbinRule],
    hm: &mut HashMap<String, NodeIndex>,
) -> StableDiGraph<String, ()> {
    let mut g = StableDiGraph::<String, ()>::new();

    for r in rules {
        let u = *hm
            .entry(r.v0.clone())
            .or_insert_with(|| g.add_node(r.v0.clone()));
        let v = *hm
            .entry(r.v1.clone())
            .or_insert_with(|| g.add_node(r.v1.clone()));
        g.add_edge(v, u, ());
    }

    g
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveTime, TimeZone};

    #[test]
    fn test_parse_extend_policy() {
        let input = "!192.168.0.0/16,11:30 +0800,17:30 +0800,2025-09-10 16:30:00 +0800";
        let policy: ExtendPolicy = input.parse().unwrap();

        let offset = FixedOffset::east_opt(8 * 3600).unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Deny(ref ip)) if ip == &IpNetwork::from_str("192.168.0.0/16").unwrap())
        );
        assert_eq!(
            policy.start_time,
            Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(11, 30, 0).unwrap())
                    .unwrap()
            )
        );
        assert_eq!(
            policy.end_time,
            Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(17, 30, 0).unwrap())
                    .unwrap()
            )
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

        assert_eq!(policy.to_string(), input);

        let input = "10.0.0.0/8,08:00 -0330,20:00 -0330,2030-01-01 00:00:00 -0330";
        let policy: ExtendPolicy = input.parse().unwrap();

        let offset = FixedOffset::west_opt(3 * 3600 + 1800).unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Allow(ref ip)) if ip == &IpNetwork::from_str("10.0.0.0/8").unwrap())
        );
        assert_eq!(
            policy.start_time,
            Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(8, 0, 0).unwrap())
                    .unwrap()
            )
        );
        assert_eq!(
            policy.end_time,
            Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(20, 0, 0).unwrap())
                    .unwrap()
            )
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

        assert_eq!(policy.to_string(), input);

        let input = "10.0.0.0/8,,20:00 +0000,2030-01-01 00:00:00 +0000";
        assert!(input.parse::<ExtendPolicy>().is_err());
        let input = "10.0.0.0/8,20:00 +0000,,2030-01-01 00:00:00 +0000";
        assert!(input.parse::<ExtendPolicy>().is_err());
        let input = "10.0.0.0/8,,";
        assert!(input.parse::<ExtendPolicy>().is_ok());
        let input = "";
        assert!(input.parse::<ExtendPolicy>().is_ok());
        let input = ",,";
        assert!(input.parse::<ExtendPolicy>().is_ok());
        let input = "1000.0.0.0/8,,";
        assert!(input.parse::<ExtendPolicy>().is_err());
        let input = "10.0.0.0/80,,";
        assert!(input.parse::<ExtendPolicy>().is_err());

        let input = "10.0.0.0/8,,,2030-01-01 00:00:00 +0000";
        let policy: ExtendPolicy = input.parse().unwrap();
        let offset = FixedOffset::east_opt(0).unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Allow(ref ip)) if ip == &IpNetwork::from_str("10.0.0.0/8").unwrap())
        );
        assert_eq!(policy.start_time, None);
        assert_eq!(policy.end_time, None);
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

        let input = "10.0.0.0/8,,,";
        let policy: ExtendPolicy = input.parse().unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Allow(ref ip)) if ip == &IpNetwork::from_str("10.0.0.0/8").unwrap())
        );
        assert_eq!(policy.start_time, None);
        assert_eq!(policy.end_time, None);
        assert_eq!(policy.expire_date, None);
    }

    #[test]
    fn test_serde_extend_policy() {
        let offset = FixedOffset::east_opt(3 * 3600).unwrap();
        let ext = ExtendPolicy {
            ip_policy: Some(IpPolicy::Allow(IpNetwork::from_str("10.0.0.0/8").unwrap())),
            start_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(8, 0, 0).unwrap())
                    .unwrap(),
            ),
            end_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(20, 0, 0).unwrap())
                    .unwrap(),
            ),
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
            "\"10.0.0.0/8,08:00 +0300,20:00 +0300,2030-01-01 00:00:00 +0300\""
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
        let serialized = ext.to_string();
        assert_eq!(serialized, "!10.0.0.0/8,,,2030-01-01 00:00:00 +0300");

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
        let serialized = ext.to_string();
        assert_eq!(serialized, ",,,2030-01-01 00:00:00 +0300");

        let ext = ExtendPolicy {
            ip_policy: None,
            start_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(8, 0, 0).unwrap())
                    .unwrap(),
            ),
            end_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(8, 35, 0).unwrap())
                    .unwrap(),
            ),
            expire_date: None,
        };
        let serialized = ext.to_string();
        assert_eq!(serialized, ",08:00 +0300,08:35 +0300,");

        let ext = ExtendPolicy {
            ip_policy: None,
            start_time: None,
            end_time: Some(
                Utc::now()
                    .with_timezone(&offset)
                    .with_time(NaiveTime::from_hms_opt(8, 35, 0).unwrap())
                    .unwrap(),
            ),
            expire_date: None,
        };
        let ext_string = ext.to_string();
        assert_eq!(ext_string, ",,08:35 +0300,");
        assert!(serde_json::to_string(&ext).is_err());
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
