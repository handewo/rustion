use sea_orm::FromQueryResult;
use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Bounded `varchar` rather than `text` because it carries a unique index and
    /// MySQL cannot index `TEXT` without a prefix length. The admin form caps
    /// usernames at `MAX_USERNAME_LEN` (40).
    #[sea_orm(column_type = "String(StringLen::N(255))", unique, indexed)]
    pub username: String,
    #[sea_orm(column_type = "String(StringLen::N(255))", nullable)]
    pub email: Option<String>,
    #[sea_orm(nullable)]
    pub password_hash: Option<String>,
    /// JSON array of authorized keys, stored as TEXT.
    #[sea_orm(column_type = "Text", nullable)]
    pub authorized_keys: Option<StringVec>,
    pub force_init_pass: bool,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
    #[sea_orm(has_many)]
    pub role: HasMany<super::casbin_rule::Entity>,
}

#[derive(FromQueryResult)]
pub struct UserWithRole {
    #[sea_orm(nested)]
    pub user: Model,
    pub role: Option<String>,
}

impl ActiveModelBehavior for ActiveModel {}

use sea_orm::entity::prelude::FromJsonQueryResult;
use serde::{Deserialize, Serialize};

/// Wrapper around `Vec<String>` stored as JSON in a TEXT column.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromJsonQueryResult)]
pub struct StringVec(pub Vec<String>);

impl From<Vec<String>> for StringVec {
    fn from(value: Vec<String>) -> Self {
        StringVec(value)
    }
}

impl From<StringVec> for Vec<String> {
    fn from(value: StringVec) -> Self {
        value.0
    }
}
