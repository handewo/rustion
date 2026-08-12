use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "target")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Bounded `varchar`: unique-indexed, and MySQL cannot index `TEXT` without a
    /// prefix length. `validate()` caps names at 50 characters.
    #[sea_orm(column_type = "String(StringLen::N(255))", unique)]
    pub name: String,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub hostname: String,
    /// Stored as `i32`, not `u16`: sea-orm's `TryGetable for u16` errors on
    /// PostgreSQL. Narrowed to `u16` when converting to
    /// [`crate::database::models::Target`], which validates the 1..=65535 range.
    pub port: i32,
    pub server_public_key: String,
    pub description: Option<String>,
    pub proxy: Option<String>,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
    /// Reverse of [`super::target_secret::Model::target`]. A compound field, so
    /// it declares the relation and the `Related` impl without adding a column —
    /// the junction table owns the foreign key.
    #[sea_orm(has_many)]
    pub target_secrets: HasMany<super::target_secret::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
