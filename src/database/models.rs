pub(crate) mod casbin_rule;
pub mod log;
pub(crate) mod target;
pub(crate) mod target_secret;
pub(crate) mod user;

pub(crate) use casbin_rule::{CasbinName, CasbinRule, CasbinRuleGroup, PermissionPolicy, Role};
pub use log::Log;
pub(crate) use target::{Target, TargetInfo};
pub(crate) use target_secret::{Secret, SecretInfo, TargetSecret, TargetSecretName};
pub(crate) use user::{User, UserWithRole};

use serde::{Deserialize, Serialize};

use sqlx::{
    decode::Decode,
    encode::{Encode, IsNull},
    sqlite::{Sqlite, SqliteArgumentValue, SqliteTypeInfo, SqliteValueRef},
    Type,
};

/// Wrapper around Vec<String> that is stored as JSON TEXT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringArray(pub Vec<String>);

impl Type<Sqlite> for StringArray {
    fn type_info() -> SqliteTypeInfo {
        <String as Type<Sqlite>>::type_info()
    }
    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <String as Type<Sqlite>>::compatible(ty)
    }
}

impl<'q> Encode<'q, Sqlite> for StringArray {
    fn encode_by_ref(
        &self,
        buf: &mut Vec<SqliteArgumentValue<'q>>,
    ) -> Result<IsNull, sqlx::error::BoxDynError> {
        let json = serde_json::to_string(&self.0)?;
        buf.push(SqliteArgumentValue::Text(json.into()));
        Ok(IsNull::No)
    }
}

impl<'r> Decode<'r, Sqlite> for StringArray {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let value = <&str as Decode<Sqlite>>::decode(value)?;
        Ok(StringArray(serde_json::from_str(value)?))
    }
}
