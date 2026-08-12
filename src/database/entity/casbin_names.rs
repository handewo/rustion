use sea_orm::entity::prelude::*;

/// Maps UUIDs to human-readable names for casbin entities.
///
/// `ptype`: `g1` (user groups), `g2` (object groups), `g3` (action groups),
/// or the internal `__internal_action_type` / `__internal_object_type`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "casbin_names")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(column_type = "String(StringLen::N(12))")]
    pub ptype: String,
    /// Bounded `varchar`: unique-indexed, and MySQL cannot index `TEXT` without a
    /// prefix length.
    #[sea_orm(column_type = "String(StringLen::N(255))", unique)]
    pub name: String,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
