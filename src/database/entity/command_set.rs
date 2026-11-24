use sea_orm::entity::prelude::*;

/// A named set of commands the limited shell may run, granted like an action:
/// its `id` is the action (`v2`) of a `p` rule, or a member of a `g3` group.
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "command_set")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Bounded `varchar`: unique-indexed, and MySQL cannot index `TEXT` without a
    /// prefix length.
    #[sea_orm(column_type = "String(StringLen::N(255))", unique)]
    pub name: String,
    /// The commands, as JSON. See `crate::command::Policy::from_json`.
    #[sea_orm(column_type = "Text")]
    pub config: String,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
    #[sea_orm(has_many, relation_enum = "CommandSetV0", via_rel = "CommandSetV0")]
    pub command_set_v0: HasMany<super::casbin_rule::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
