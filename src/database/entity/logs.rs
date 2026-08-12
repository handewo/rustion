use sea_orm::entity::prelude::*;

/// Records a user's successful operations.
///
/// Keeps the original composite primary key
/// `(created_at, connection_id, detail)`, which preserves its incidental
/// dedup and — importantly — means existing databases need no `ALTER`.
/// (An earlier attempt at a surrogate `id` failed outright: SQLite cannot add a
/// PRIMARY KEY column to a populated table.)
///
/// `detail` is a bounded `varchar` rather than `text` because MySQL cannot index
/// a `TEXT` column in a key without a prefix length. The bound is generous:
/// details are structurally bounded format strings — UUIDs (36) plus names that
/// `validate()` caps at 40–50 chars — and the longest row in the production
/// database is 192 characters. SQLite ignores `varchar` lengths entirely, so
/// existing rows are unaffected either way.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "logs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, indexed)]
    pub created_at: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub connection_id: Uuid,
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "String(StringLen::N(512))"
    )]
    pub detail: String,
    pub log_type: String,
    pub user_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
