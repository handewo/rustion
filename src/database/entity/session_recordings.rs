use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_recordings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(indexed)]
    pub user_id: Uuid,
    #[sea_orm(indexed)]
    pub target_id: Uuid,
    pub secret_id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub file_path: String,
    #[sea_orm(indexed)]
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub connection_id: Uuid,
    pub status: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// `skip_fk` is essential, not incidental: recordings outlive the targets and
    /// secrets they reference, and the original table carried no foreign keys for
    /// exactly that reason. Emitting one here would make deleting a target that
    /// has recordings fail on PostgreSQL and MySQL. The relation exists only so
    /// the label query can `LeftJoin` — which is also why
    /// `list_recording_view_for_user` tolerates a missing target or secret.
    #[sea_orm(
        belongs_to = "super::target::Entity",
        from = "Column::TargetId",
        to = "super::target::Column::Id",
        skip_fk
    )]
    Target,
    #[sea_orm(
        belongs_to = "super::secret::Entity",
        from = "Column::SecretId",
        to = "super::secret::Column::Id",
        skip_fk
    )]
    Secret,
}

impl ActiveModelBehavior for ActiveModel {}
