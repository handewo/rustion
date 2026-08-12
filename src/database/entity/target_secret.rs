use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "target_secret")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `UNIQUE(target_id, secret_id)` — columns sharing a `unique_key` name are
    /// grouped into one unique index. `upsert_target_secret` relies on this.
    #[sea_orm(unique_key = "target_secret")]
    pub target_id: Uuid,
    #[sea_orm(unique_key = "target_secret")]
    pub secret_id: Uuid,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
    #[sea_orm(
        belongs_to,
        from = "target_id",
        to = "id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    pub target: BelongsTo<super::target::Entity>,
    #[sea_orm(
        belongs_to,
        from = "secret_id",
        to = "id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    pub secret: BelongsTo<super::secret::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
