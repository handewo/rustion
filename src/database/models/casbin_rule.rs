use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) use crate::database::entity::casbin_names::NamePtype;
pub(crate) use crate::database::entity::casbin_rule::Ptype;

/// Which of the three role hierarchies a group membership belongs to.
///
/// A strict subset of [`Ptype`]: the `g*` variants, without `p`. That is the
/// whole point of it existing separately — a caller holding a `GroupType`
/// cannot be holding [`Ptype::Policy`], so the operations that are only
/// meaningful for group rows (walking a hierarchy, deleting by `v0`/`v1`) can
/// say so in their signature instead of documenting a caveat.
///
/// Lives here rather than in `server::casbin` because both the RBAC engine and
/// the [`DatabaseRepository`](crate::database::DatabaseRepository) trait speak
/// in it, and the database layer cannot depend on the server layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupType {
    /// user → role, `g1`
    Subject,
    /// object → group, `g2`
    Object,
    /// action → group, `g3`
    Action,
}

impl From<GroupType> for Ptype {
    fn from(value: GroupType) -> Self {
        match value {
            GroupType::Subject => Ptype::G1,
            GroupType::Object => Ptype::G2,
            GroupType::Action => Ptype::G3,
        }
    }
}

impl GroupType {
    /// The `ptype` name, for logs. Borrowed from [`Ptype`] rather than spelled
    /// again here, so the two cannot drift.
    pub fn as_str(&self) -> &'static str {
        Ptype::from(*self).as_str()
    }
}

impl std::fmt::Display for GroupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CasbinRule stores RBAC policies with all UUID references stored as BLOB
/// - ptype: rule kind, see [`Ptype`]
/// - v0: subject UUID (user or group)
/// - v1: object UUID (target_secret, internal_object, or group)
/// - v2: action UUID (action or action group)
/// - v3-v5: extended policy data (IP ranges, time constraints, etc.) - stored as TEXT
#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct CasbinRule {
    pub id: Uuid,
    pub ptype: Ptype,
    pub v0: Uuid,   // Subject UUID
    pub v1: Uuid,   // Object UUID
    pub v2: Uuid,   // Action UUID
    pub v3: String, // Extended policy data
    pub v4: String, // Extended policy data
    pub v5: String, // Extended policy data
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl CasbinRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ptype: Ptype,
        v0: Uuid,
        v1: Uuid,
        v2: Uuid,
        v3: String,
        v4: String,
        v5: String,
        updated_by: Uuid,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ptype,
            v0,
            v1,
            v2,
            v3,
            v4,
            v5,
            updated_by,
            updated_at: now.timestamp_millis(),
        }
    }
}

/// CasbinName maps UUIDs to human-readable names for casbin entities
/// - ptype: see [`NamePtype`], a wider set than a `casbin_rule` row can hold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasbinName {
    pub id: Uuid,
    pub ptype: NamePtype,
    pub name: String,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl CasbinName {
    pub fn new(ptype: NamePtype, name: String, is_active: bool, updated_by: Uuid) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4(),
            ptype,
            name,
            is_active,
            updated_by,
            updated_at: now,
        }
    }

    pub fn is_internal(&self) -> bool {
        self.ptype.is_internal()
    }

    pub fn validate(&self) -> Result<(), ValidateError> {
        // `NamePtype` makes the empty case unrepresentable, but `act` and the two
        // internal markers are still values a user must not pick.
        if !matches!(self.ptype, NamePtype::G1 | NamePtype::G2 | NamePtype::G3) {
            return Err(ValidateError::PtypeInvalid);
        }
        if self.name.trim().is_empty() {
            return Err(ValidateError::NameEmpty);
        }
        if self.name.starts_with('_') {
            return Err(ValidateError::NameStartsWithUnderscore);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    // `PtypeEmpty` used to live here. `NamePtype` has no empty state, so it
    // became unconstructible.
    #[error("Ptype must be one of g1, g2, g3")]
    PtypeInvalid,
    #[error("Name cannot be empty")]
    NameEmpty,
    #[error("Name cannot start with underscore")]
    NameStartsWithUnderscore,
    #[error("Cannot modify internal types")]
    InternalTypeModification,
}

#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct CasbinRuleGroup {
    pub id: Uuid,
    pub v0: Uuid,
    pub v0_object_label: Option<String>,
    pub v0_group_label: Option<String>,
    pub v1: Uuid,
    pub v1_object_label: Option<String>,
    pub v1_group_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct Role {
    pub rid: Uuid,
    pub rule_id: Option<Uuid>,
    pub role: String,
    pub is_bound: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionPolicy {
    pub rule: CasbinRule,
    pub user_role: String,
    pub target_group: String,
    pub action_group: String,
}

impl PermissionPolicy {
    pub fn new(updated_by: Uuid) -> Self {
        Self {
            rule: CasbinRule::new(
                // A permission policy is a `p` rule by definition; there is no
                // longer an empty state for the caller to fill in.
                Ptype::Policy,
                Uuid::default(),
                Uuid::default(),
                Uuid::default(),
                String::new(),
                String::new(),
                String::new(),
                updated_by,
            ),
            user_role: String::new(),
            target_group: String::new(),
            action_group: String::new(),
        }
    }

    pub fn verify(&self) -> Result<(), PermissionPolicyEmptyError> {
        if self.user_role == String::new() {
            return Err(PermissionPolicyEmptyError::UserRole);
        }

        if self.target_group == String::new() {
            return Err(PermissionPolicyEmptyError::TargetGroup);
        }

        if self.action_group == String::new() {
            return Err(PermissionPolicyEmptyError::ActionGroup);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PermissionPolicyEmptyError {
    UserRole,
    TargetGroup,
    ActionGroup,
}

impl std::fmt::Display for PermissionPolicyEmptyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use PermissionPolicyEmptyError::*;
        match self {
            UserRole => {
                write!(f, "User/Role cannot be empty")
            }
            TargetGroup => {
                write!(f, "Target/Group cannot be empty")
            }
            ActionGroup => {
                write!(f, "Action/Group cannot be empty")
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct ObjectGroup {
    pub id: Uuid,
    pub name: String,
    pub is_group: bool,
}

impl From<crate::database::entity::casbin_rule::Model> for CasbinRule {
    fn from(m: crate::database::entity::casbin_rule::Model) -> Self {
        Self {
            id: m.id,
            ptype: m.ptype,
            v0: m.v0,
            v1: m.v1,
            v2: m.v2,
            v3: m.v3,
            v4: m.v4,
            v5: m.v5,
            updated_by: m.updated_by,
            updated_at: m.updated_at,
        }
    }
}

impl CasbinRule {
    pub(in crate::database) fn into_active_model(
        self,
    ) -> crate::database::entity::casbin_rule::ActiveModel {
        use sea_orm::ActiveValue::Set;
        crate::database::entity::casbin_rule::ActiveModel {
            id: Set(self.id),
            ptype: Set(self.ptype),
            v0: Set(self.v0),
            v1: Set(self.v1),
            v2: Set(self.v2),
            v3: Set(self.v3),
            v4: Set(self.v4),
            v5: Set(self.v5),
            updated_by: Set(self.updated_by),
            updated_at: Set(self.updated_at),
        }
    }
}

impl From<crate::database::entity::casbin_names::Model> for CasbinName {
    fn from(m: crate::database::entity::casbin_names::Model) -> Self {
        Self {
            id: m.id,
            ptype: m.ptype,
            name: m.name,
            is_active: m.is_active,
            updated_by: m.updated_by,
            updated_at: m.updated_at,
        }
    }
}

impl CasbinName {
    pub(in crate::database) fn into_active_model(
        self,
    ) -> crate::database::entity::casbin_names::ActiveModel {
        use sea_orm::ActiveValue::Set;
        crate::database::entity::casbin_names::ActiveModel {
            id: Set(self.id),
            ptype: Set(self.ptype),
            name: Set(self.name),
            is_active: Set(self.is_active),
            updated_by: Set(self.updated_by),
            updated_at: Set(self.updated_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GroupType` is meant to be `Ptype` minus `p`. Nothing in the type system
    /// says so, so say it here: every variant must map to a `g*`, and the three
    /// mappings must be distinct.
    #[test]
    fn group_type_maps_onto_the_g_ptypes() {
        let mapped: Vec<Ptype> = [GroupType::Subject, GroupType::Object, GroupType::Action]
            .into_iter()
            .map(Ptype::from)
            .collect();

        assert_eq!(mapped, vec![Ptype::G1, Ptype::G2, Ptype::G3]);
        assert!(!mapped.contains(&Ptype::Policy), "`p` is not a group type");
    }

    /// The name is borrowed from `Ptype`, so this is really a check that the
    /// delegation is wired to the matching variant.
    #[test]
    fn group_type_names_match_their_ptype() {
        for gt in [GroupType::Subject, GroupType::Object, GroupType::Action] {
            assert_eq!(gt.as_str(), Ptype::from(gt).as_str());
            assert_eq!(gt.to_string(), gt.as_str());
        }
    }
}
