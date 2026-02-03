use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// CasbinRule stores RBAC policies with all UUID references stored as BLOB
/// - ptype: policy type ('p' for policy, 'g1' for user groups, 'g2' for object groups, 'g3' for action groups)
/// - v0: subject UUID (user or group)
/// - v1: object UUID (target_secret, internal_object, or group)
/// - v2: action UUID (action or action group)
/// - v3-v5: extended policy data (IP ranges, time constraints, etc.) - stored as TEXT
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CasbinRule {
    pub id: Uuid,
    pub ptype: String,
    pub v0: Uuid,         // Subject UUID
    pub v1: Uuid,         // Object UUID
    pub v2: Option<Uuid>, // Action UUID (optional for group rules)
    pub v3: String,       // Extended policy data
    pub v4: String,       // Extended policy data
    pub v5: String,       // Extended policy data
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl CasbinRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ptype: String,
        v0: Uuid,
        v1: Uuid,
        v2: Option<Uuid>,
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
/// - ptype: 'g1' (user groups), 'g2' (object groups), 'g3' (action groups), 'act' (actions)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CasbinName {
    pub id: Uuid,
    pub ptype: String,
    pub name: String,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl CasbinName {
    pub fn new(ptype: String, name: String, is_active: bool, updated_by: Uuid) -> Self {
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
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CasbinRuleGroup {
    pub id: Uuid,
    pub v0: Uuid,
    pub v0_label: Option<String>,
    pub v1: Uuid,
    pub v1_label: Option<String>,
}
