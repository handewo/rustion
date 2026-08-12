use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "secret")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Bounded `varchar`: unique-indexed, and MySQL cannot index `TEXT` without a
    /// prefix length.
    #[sea_orm(column_type = "String(StringLen::N(255))", unique)]
    pub name: String,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub user: String,
    #[sea_orm(nullable)]
    pub password: Option<String>,
    #[sea_orm(nullable)]
    pub private_key: Option<String>,
    #[sea_orm(nullable)]
    pub public_key: Option<String>,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
    /// Many-to-many to targets through the junction table.
    #[sea_orm(has_many, via = "target_secret")]
    pub targets: HasMany<super::target::Entity>,
    /// The junction leg on its own, for queries that filter on the binding
    /// itself rather than on the target. Reverse of
    /// [`super::target_secret::Model::secret`]; adds no column.
    #[sea_orm(has_many)]
    pub target_secrets: HasMany<super::target_secret::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
