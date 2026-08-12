use sea_orm::entity::prelude::*;

/// RBAC policies. All UUID references are stored as native UUID columns
/// (BLOB on SQLite, `uuid` on PostgreSQL, `binary(16)` on MySQL).
///
/// - `ptype`: `p` (policy), `g1` (user→role), `g2` (secret→group), `g3` (action→group)
/// - `v0`: subject, `v1`: object, `v2`: action
/// - `v3`–`v5`: extended policy data (IP ranges, time constraints)
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "casbin_rule")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The 7-column unique constraint (was `unique_key_sqlx_adapter`) that keeps
    /// duplicate policies out. The admin UI surfaces violations of it as
    /// "already exists" rather than "internal error".
    #[sea_orm(column_type = "String(StringLen::N(12))", unique_key = "rule")]
    pub ptype: String,
    #[sea_orm(unique_key = "rule")]
    pub v0: Uuid,
    #[sea_orm(unique_key = "rule")]
    pub v1: Uuid,
    #[sea_orm(unique_key = "rule")]
    pub v2: Uuid,
    #[sea_orm(column_type = "String(StringLen::N(256))", unique_key = "rule")]
    pub v3: String,
    #[sea_orm(column_type = "String(StringLen::N(256))", unique_key = "rule")]
    pub v4: String,
    #[sea_orm(column_type = "String(StringLen::N(256))", unique_key = "rule")]
    pub v5: String,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
