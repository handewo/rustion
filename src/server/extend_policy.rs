use crate::error::Error;
use crate::server::error::{ExtendPolicyError, ServerError};
use chrono::{DateTime, FixedOffset, NaiveTime, Utc};
use ipnetwork::IpNetwork;
use log::trace;
use serde::{Deserialize, Serialize, de};
use std::net::IpAddr;
use std::str::FromStr;

/// This is used for p.ext
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtendPolicy {
    pub ip_policy: Option<IpPolicy>,
    pub start_time: Option<TimeWithOffset>,
    pub end_time: Option<TimeWithOffset>,
    pub expire_date: Option<DateTime<FixedOffset>>,
    pub open_direct_tcpip_host: Option<HostPolicy>,
    pub open_direct_tcpip_port: Option<PortPolicy>,
    /// Regexes over the resolved absolute path of an SFTP request. See
    /// [`is_path_match`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sftp_path: Option<PathPolicy>,
}

impl ExtendPolicy {
    pub fn validate(&self) -> Result<(), ExtendPolicyError> {
        // ensure start_time and end_time are consistent
        match (&self.start_time, &self.end_time) {
            (Some(_), None) => return Err(ExtendPolicyError::EndTimeAbsent),
            (None, Some(_)) => return Err(ExtendPolicyError::StartTimeAbsent),
            (Some(s), Some(e)) if s.offset != e.offset => {
                return Err(ExtendPolicyError::DifferentTimezone);
            }
            _ => {}
        }
        if let Some(p) = &self.sftp_path {
            p.compile()?;
        }
        Ok(())
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

/// What kind of request is being authorized, and the values its kind carries.
///
/// The kind is what lets a matcher tell "this request has no such value" from
/// "this constraint does not apply to this request". Holding the values inside
/// the kind rather than beside it means the two cannot disagree: there is no
/// way to build a request that carries a destination host but is not a
/// `direct-tcpip`, or an SFTP path but is not SFTP.
#[derive(Debug, Default, Clone)]
pub enum RequestKind {
    /// Login, shell, pty, exec, admin, player: no per-kind constraint applies.
    #[default]
    Other,
    /// A `direct-tcpip` channel to `(host, port)`, checked against
    /// `open_direct_tcpip_host` and `open_direct_tcpip_port`.
    OpenDirectTcpip(String, u16),
    /// An SFTP request, checked against `sftp_path`.
    ///
    /// `None` is a request that names no path — the subsystem gate and
    /// `realpath`. Those are not exempt by oversight: a path rule has nothing
    /// to match against, and denying them would make a path-restricted policy
    /// refuse the session it is meant to narrow.
    Sftp(Option<String>),
}

/// This is used for r.ext
#[derive(Debug)]
pub struct ExtendPolicyReq {
    pub ip: Option<IpAddr>,
    pub now: DateTime<Utc>,
    pub kind: RequestKind,
}

impl Default for ExtendPolicyReq {
    fn default() -> Self {
        ExtendPolicyReq {
            ip: None,
            kind: RequestKind::Other,
            now: Utc::now(),
        }
    }
}

impl ExtendPolicyReq {
    pub fn new(ip: Option<IpAddr>) -> Self {
        ExtendPolicyReq {
            ip,
            kind: RequestKind::Other,
            now: Utc::now(),
        }
    }

    /// [`new`](Self::new), for a request of one particular kind.
    pub fn of(ip: Option<IpAddr>, kind: RequestKind) -> Self {
        ExtendPolicyReq {
            ip,
            kind,
            now: Utc::now(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum HostPolicy {
    Allow(String),
    Deny(String),
}
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum PortPolicy {
    Allow(Vec<u16>),
    Deny(Vec<u16>),
}

/// Allow or deny SFTP paths by regex. Each pattern must match the *whole*
/// resolved path: it is compiled as `^(?:pattern)$`, so `/srv/upload/.*` does
/// not also match `/tmp/srv/upload/x`. To cover a directory and everything in
/// it, write `/dir(/.*)?`. `.` matches every character, newline included, since
/// a name may contain any byte but NUL.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum PathPolicy {
    Allow(Vec<String>),
    Deny(Vec<String>),
}

impl PathPolicy {
    fn patterns(&self) -> &[String] {
        match self {
            Self::Allow(p) | Self::Deny(p) => p,
        }
    }

    /// Compiled per call: `enforce` already reads every policy from the
    /// database per call, and these sets are a handful of short patterns.
    fn compile(&self) -> Result<regex::RegexSet, ExtendPolicyError> {
        // Each pattern must be valid on its own. Checking only the wrapped form
        // is not enough: `x)|(.*` becomes `^(?:x)|(.*)$`, which compiles but is
        // an unanchored alternation that matches every path.
        for p in self.patterns() {
            regex::RegexBuilder::new(p)
                .dot_matches_new_line(true)
                .build()
                .map_err(|e| ExtendPolicyError::InvalidPathRegex {
                    pattern: p.clone(),
                    reason: e.to_string(),
                })?;
        }
        let anchored = self.patterns().iter().map(|p| format!("^(?:{p})$"));
        // `.` must match `\n`: names may contain any byte but NUL, and with
        // default flags `/etc(/.*)?` would not match `/etc/x\ny`, so a Deny
        // rule would let it through.
        regex::RegexSetBuilder::new(anchored)
            .dot_matches_new_line(true)
            .build()
            .map_err(|e| ExtendPolicyError::InvalidPathRegex {
                pattern: String::new(),
                reason: e.to_string(),
            })
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum IpPolicy {
    Allow(IpNetwork),
    Deny(IpNetwork),
}

pub struct HostPolicyNotIpPolicy;

impl TryFrom<HostPolicy> for IpPolicy {
    type Error = HostPolicyNotIpPolicy;
    fn try_from(value: HostPolicy) -> Result<Self, Self::Error> {
        match value {
            HostPolicy::Allow(p) => {
                let ip = IpNetwork::from_str(&p).map_err(|_| HostPolicyNotIpPolicy)?;
                Ok(IpPolicy::Allow(ip))
            }
            HostPolicy::Deny(p) => {
                let ip = IpNetwork::from_str(&p).map_err(|_| HostPolicyNotIpPolicy)?;
                Ok(IpPolicy::Deny(ip))
            }
        }
    }
}

/// Check one policy's `v3` against a request.
///
/// Two kinds of constraint live in an [`ExtendPolicy`], and they are checked
/// differently:
///
/// * **Universal** — `ip_policy`, `start_time`/`end_time`, `expire_date`. Every
///   request has a client address and a time, so these are checked for every
///   request whatever its kind. A policy that is out of its window or past its
///   expiry grants nothing at all.
/// * **Per-kind** — `open_direct_tcpip_host`/`_port` and `sftp_path`. These
///   describe one kind of request, so they are checked only against
///   [`RequestKind`]s that carry the value they constrain, and a request of
///   another kind passes them.
///
/// The per-kind rule is why the request carries its kind. The fields used to be
/// bare `Option`s on the request, so a shell request — which has no destination
/// host and no SFTP path — was indistinguishable from a `direct-tcpip` to an
/// unknown host, and `is_host_match`/`is_path_match` read that absence as a
/// failure. A policy carrying either field then denied every request of every
/// other kind, including the SFTP subsystem gate, which names no path and so
/// made a path-restricted policy refuse the session it was meant to narrow.
///
/// What a policy grants is its action list; an extended policy only narrows the
/// kind it names. So an action group holding both `shell` and the SFTP actions,
/// on a policy carrying `sftp_path`, grants shell unconstrained and narrows
/// only SFTP. Split the group if that is not what you want.
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

    // Per-kind constraints. Each arm checks only the constraints its own kind
    // carries a value for; the rest do not apply to this request.
    match &ext_req.kind {
        RequestKind::Other => {}
        RequestKind::OpenDirectTcpip(host, port) => {
            if !is_host_match(Some(host.clone()), ext.open_direct_tcpip_host) {
                return Ok(false);
            }
            if !is_port_in_range(Some(*port), ext.open_direct_tcpip_port) {
                return Ok(false);
            }
        }
        // `None` names no path, so a path rule has nothing to match: the
        // subsystem gate and `realpath` pass it. Every SFTP request that does
        // name a path is checked.
        RequestKind::Sftp(Some(path)) => {
            if !is_path_match(Some(path.as_str()), ext.sftp_path.as_ref())
                .map_err(ServerError::ExtendPolicy)?
            {
                return Ok(false);
            }
        }
        RequestKind::Sftp(None) => {}
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

pub fn is_host_match(dest: Option<String>, host_policy: Option<HostPolicy>) -> bool {
    match (dest, host_policy) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(host_dest), Some(policy)) => {
            match (
                IpAddr::from_str(&host_dest),
                IpPolicy::try_from(policy.clone()),
            ) {
                (Ok(ip_dest), Ok(ip_policy)) => {
                    return is_ip_in_cidr(Some(ip_dest), Some(ip_policy));
                }
                // NOTE: Since rustion cannot resolve the Domain name which resolved by target,
                // It cannot resolve to IP to match.
                (Err(_), Ok(IpPolicy::Allow(_))) => return false,
                (Err(_), Ok(IpPolicy::Deny(_))) => return true,

                (Ok(_), Err(_)) => return false,
                (Err(_), Err(_)) => (),
            };
            match policy {
                HostPolicy::Allow(h) => host_dest == h,
                HostPolicy::Deny(h) => host_dest != h,
            }
        }
    }
}
pub fn is_port_in_range(port: Option<u16>, port_policy: Option<PortPolicy>) -> bool {
    match (port, port_policy) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(port), Some(policy)) => match policy {
            PortPolicy::Allow(ports) => ports.iter().any(|p| p == &port),
            PortPolicy::Deny(ports) => !ports.iter().any(|p| p == &port),
        },
    }
}

/// `Allow` passes if any pattern matches, `Deny` if none does. Like
/// [`is_host_match`], a request with no path never satisfies a path rule, so a
/// path-restricted policy grants only path-bearing SFTP operations.
pub fn is_path_match(
    path: Option<&str>,
    policy: Option<&PathPolicy>,
) -> Result<bool, ExtendPolicyError> {
    let (path, policy) = match (path, policy) {
        (_, None) => return Ok(true),
        (None, Some(_)) => return Ok(false),
        (Some(path), Some(policy)) => (path, policy),
    };
    let hit = policy.compile()?.is_match(path);
    Ok(match policy {
        PathPolicy::Allow(_) => hit,
        PathPolicy::Deny(_) => !hit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveTime, TimeZone};

    /// The test fixture embeds a serialized [`ExtendPolicy`] as a string literal,
    /// because `crate::database` cannot depend on this module. Nothing else
    /// connects the two, so this is what catches the literal going stale if a
    /// field here is renamed or its format changes.
    #[test]
    fn fixture_extend_policy_still_parses() {
        let raw = crate::database::fixture::VENDOR_EXTEND_POLICY;
        // `casbin_rule.v3` is a `varchar(256)`, which MySQL enforces.
        assert!(raw.len() <= 256, "too long for v3: {}", raw.len());

        let policy: ExtendPolicy =
            serde_json::from_str(raw).expect("fixture extended policy no longer parses");
        policy.validate().expect("fixture extended policy invalid");

        let offset = FixedOffset::east_opt(8 * 3600).unwrap();
        assert!(
            matches!(policy.ip_policy, Some(IpPolicy::Allow(ref ip)) if ip == &IpNetwork::from_str("10.20.0.0/16").unwrap())
        );
        let start = policy.start_time.expect("start_time");
        let end = policy.end_time.expect("end_time");
        assert_eq!(start.time, NaiveTime::from_hms_opt(8, 0, 0).unwrap());
        assert_eq!(end.time, NaiveTime::from_hms_opt(20, 0, 0).unwrap());
        assert_eq!(start.offset, offset);
        assert_eq!(end.offset, offset);
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
        assert!(policy.open_direct_tcpip_host.is_none());
        assert!(policy.open_direct_tcpip_port.is_none());
    }

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
            open_direct_tcpip_host: None,
            open_direct_tcpip_port: None,
            sftp_path: None,
        };
        let serialized = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            serialized,
            r#"{"ip_policy":{"Allow":"10.0.0.0/8"},"start_time":"08:00 +03:00","end_time":"20:00 +03:00","expire_date":"2030-01-01T00:00:00+03:00","open_direct_tcpip_host":null,"open_direct_tcpip_port":null}"#
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
            open_direct_tcpip_host: None,
            open_direct_tcpip_port: None,
            sftp_path: None,
        };
        let serialized = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            serialized,
            r#"{"ip_policy":{"Deny":"10.0.0.0/8"},"start_time":null,"end_time":null,"expire_date":"2030-01-01T00:00:00+03:00","open_direct_tcpip_host":null,"open_direct_tcpip_port":null}"#
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
            open_direct_tcpip_host: None,
            open_direct_tcpip_port: None,
            sftp_path: None,
        };
        let serialized = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            serialized,
            r#"{"ip_policy":null,"start_time":null,"end_time":null,"expire_date":"2030-01-01T00:00:00+03:00","open_direct_tcpip_host":null,"open_direct_tcpip_port":null}"#
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
            open_direct_tcpip_host: Some(HostPolicy::Allow("10.10.10.0/24".to_string())),
            open_direct_tcpip_port: None,
            sftp_path: None,
        };
        let serialized = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            serialized,
            r#"{"ip_policy":null,"start_time":"08:00 +03:00","end_time":"08:35 +03:00","expire_date":null,"open_direct_tcpip_host":{"Allow":"10.10.10.0/24"},"open_direct_tcpip_port":null}"#
        );

        let ext = ExtendPolicy {
            ip_policy: None,
            start_time: None,
            end_time: Some(TimeWithOffset {
                time: NaiveTime::from_hms_opt(8, 35, 0).unwrap(),
                offset,
            }),
            expire_date: None,
            open_direct_tcpip_host: Some(HostPolicy::Allow("example.com".into())),
            open_direct_tcpip_port: None,
            sftp_path: None,
        };
        let ext_string = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            ext_string,
            r#"{"ip_policy":null,"start_time":null,"end_time":"08:35 +03:00","expire_date":null,"open_direct_tcpip_host":{"Allow":"example.com"},"open_direct_tcpip_port":null}"#
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

    fn allow(p: &[&str]) -> Option<PathPolicy> {
        Some(PathPolicy::Allow(p.iter().map(|s| s.to_string()).collect()))
    }
    fn deny(p: &[&str]) -> Option<PathPolicy> {
        Some(PathPolicy::Deny(p.iter().map(|s| s.to_string()).collect()))
    }

    #[test]
    fn path_patterns_are_full_match() {
        let p = allow(&["/srv/upload/.*"]);
        assert!(is_path_match(Some("/srv/upload/a"), p.as_ref()).unwrap());
        // Unanchored, this would match: the pattern occurs inside the path.
        assert!(!is_path_match(Some("/tmp/x/srv/upload/y"), p.as_ref()).unwrap());
        // `/dir/.*` does not cover `/dir` itself; `/dir(/.*)?` does.
        assert!(!is_path_match(Some("/srv/upload"), p.as_ref()).unwrap());
        let p = allow(&["/srv/upload(/.*)?"]);
        assert!(is_path_match(Some("/srv/upload"), p.as_ref()).unwrap());
        assert!(!is_path_match(Some("/srv/uploads"), p.as_ref()).unwrap());
        // An alternation is anchored as a whole, not just its first branch.
        let p = allow(&["/a|/b"]);
        assert!(!is_path_match(Some("/b/c"), p.as_ref()).unwrap());
    }

    /// OpenSSH accepts any non-NUL byte in a name, newline included. With
    /// default flags `.` stops at `\n`, so a Deny rule would fail open.
    #[test]
    fn path_patterns_match_across_newlines() {
        let d = deny(&["/etc(/.*)?"]);
        assert_eq!(is_path_match(Some("/etc/x\ny"), d.as_ref()), Ok(false));
        let a = allow(&["/srv(/.*)?"]);
        assert_eq!(is_path_match(Some("/srv/a\nb"), a.as_ref()), Ok(true));
    }

    #[test]
    fn path_allow_is_any_deny_is_none() {
        let a = allow(&["/a(/.*)?", "/b(/.*)?"]);
        assert!(is_path_match(Some("/b/x"), a.as_ref()).unwrap());
        assert!(!is_path_match(Some("/c"), a.as_ref()).unwrap());
        let d = deny(&["/etc(/.*)?", ".*\\.key"]);
        assert!(is_path_match(Some("/srv/x"), d.as_ref()).unwrap());
        assert!(!is_path_match(Some("/etc/passwd"), d.as_ref()).unwrap());
        assert!(!is_path_match(Some("/home/u/id.key"), d.as_ref()).unwrap());
    }

    #[test]
    fn path_rule_needs_a_path_and_no_rule_needs_nothing() {
        assert!(is_path_match(None, None).unwrap());
        assert!(is_path_match(Some("/x"), None).unwrap());
        // Mirrors `is_host_match`: a request without a path never satisfies a
        // policy that restricts paths — either kind.
        assert!(!is_path_match(None, allow(&[".*"]).as_ref()).unwrap());
        assert!(!is_path_match(None, deny(&["/etc"]).as_ref()).unwrap());
    }

    #[test]
    fn invalid_path_regex_is_rejected() {
        let ext: ExtendPolicy =
            serde_json::from_str(r#"{"sftp_path":{"Allow":["/srv/("]}}"#).unwrap();
        assert!(matches!(
            ext.validate(),
            Err(ExtendPolicyError::InvalidPathRegex { ref pattern, .. }) if pattern == "/srv/("
        ));
        let req = ExtendPolicyReq {
            kind: RequestKind::Sftp(Some("/srv/x".into())),
            ..ExtendPolicyReq::default()
        };
        assert!(verify_extend_policy(&req, r#"{"sftp_path":{"Deny":["("]}}"#).is_err());
    }

    /// `x)|(.*` compiles once wrapped as `^(?:x)|(.*)$`, but as an unanchored
    /// alternation that matches every path. A pattern must be valid on its own.
    #[test]
    fn path_regex_that_only_compiles_wrapped_is_rejected() {
        let ext: ExtendPolicy =
            serde_json::from_str(r#"{"sftp_path":{"Deny":["x)|(.*"]}}"#).unwrap();
        assert!(matches!(
            ext.validate(),
            Err(ExtendPolicyError::InvalidPathRegex { ref pattern, .. }) if pattern == "x)|(.*"
        ));
        let policy = PathPolicy::Allow(vec!["x)|(.*".into()]);
        assert!(is_path_match(Some("/anything"), Some(&policy)).is_err());
    }

    #[test]
    fn sftp_path_is_optional_on_disk() {
        // Every `v3` written before this field existed still parses...
        let ext: ExtendPolicy = serde_json::from_str("{}").unwrap();
        assert!(ext.sftp_path.is_none());
        // ...and a policy without a path rule serializes exactly as before.
        assert!(!serde_json::to_string(&ext).unwrap().contains("sftp_path"));
        let ext: ExtendPolicy =
            serde_json::from_str(r#"{"sftp_path":{"Allow":["/srv(/.*)?"]}}"#).unwrap();
        assert_eq!(ext.sftp_path, allow(&["/srv(/.*)?"]));
    }
}
