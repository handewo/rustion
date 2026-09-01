use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// RBAC policies. All UUID references are stored as native UUID columns
/// (BLOB on SQLite, `uuid` on PostgreSQL, `binary(16)` on MySQL).
///
/// - `ptype`: see [`Ptype`]
/// - `v0`: subject, `v1`: object, `v2`: action
/// - `v3`–`v5`: extended policy data (IP ranges, time constraints)
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "casbin_rule")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Part of the 7-column unique constraint (was `unique_key_sqlx_adapter`)
    /// that keeps duplicate policies out. The admin UI surfaces violations of it
    /// as "already exists" rather than "internal error".
    ///
    /// No `column_type` here: `ValueType::column_type()` delegates to
    /// [`Ptype`]'s `db_type`, so the enum is the only place the column shape is
    /// declared.
    #[sea_orm(unique_key = "rule")]
    pub ptype: Ptype,
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
    #[sea_orm(
        belongs_to,
        relation_enum = "RoleGroupV0",
        from = "v0",
        to = "id",
        skip_fk
    )]
    pub role_group_v0: BelongsTo<super::casbin_name::Entity>,
    #[sea_orm(
        belongs_to,
        relation_enum = "RoleGroupV1",
        from = "v1",
        to = "id",
        skip_fk
    )]
    pub role_group_v1: BelongsTo<super::casbin_name::Entity>,
    #[sea_orm(belongs_to, from = "v1", to = "id", skip_fk)]
    pub role_user: BelongsTo<super::user::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}

/// The kind of rule a `casbin_rule` row holds.
///
/// Stored as a small integer. The `num_value`s are the on-disk format and must
/// never be renumbered — a database written by this version reads its `ptype`
/// column back through these exact discriminants.
///
/// Serde deliberately stays on the wire names (`"p"`, `"g1"`, …): an exported or
/// imported ruleset spells `ptype` as a string, and that is a separate concern
/// from how the column is stored.
///
/// `casbin_names.ptype` is deliberately *not* this type: it carries a wider set
/// (`act` and the two `__internal_*` types) that has no meaning here.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum Ptype {
    /// A permission policy: subject `v0` may perform action `v2` on object `v1`.
    #[sea_orm(num_value = 0)]
    #[serde(rename = "p")]
    Policy,
    /// user → role
    #[sea_orm(num_value = 1)]
    #[serde(rename = "g1")]
    G1,
    /// object → group
    #[sea_orm(num_value = 2)]
    #[serde(rename = "g2")]
    G2,
    /// action → group
    #[sea_orm(num_value = 3)]
    #[serde(rename = "g3")]
    G3,
}

impl Ptype {
    /// The human-facing name, as used in the admin UI, logs and JSON fixtures.
    /// This is *not* the stored representation — see `num_value` above.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Policy => "p",
            Self::G1 => "g1",
            Self::G2 => "g2",
            Self::G3 => "g3",
        }
    }
}

impl std::fmt::Display for Ptype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveEnum, Iterable};

    /// `as_str`, `Display` and the serde rename are three hand-written spellings
    /// of one name. Pin them together so the UI, logs and fixtures agree.
    #[test]
    fn ptype_name_spellings_agree() {
        for p in Ptype::iter() {
            assert_eq!(p.to_string(), p.as_str(), "Display disagrees with as_str");
            assert_eq!(
                serde_json::to_string(&p).unwrap(),
                format!("\"{}\"", p.as_str()),
                "serde disagrees with as_str"
            );
            assert_eq!(
                serde_json::from_str::<Ptype>(&format!("\"{}\"", p.as_str())).unwrap(),
                p,
                "serde does not round-trip"
            );
        }
    }

    /// The `num_value`s are the on-disk format. Renumbering them silently
    /// reinterprets every existing row, so assert them literally — this test is
    /// meant to fail loudly if anyone reorders the variants.
    #[test]
    fn ptype_stored_discriminants_are_stable() {
        for (want, p) in [
            (0, Ptype::Policy),
            (1, Ptype::G1),
            (2, Ptype::G2),
            (3, Ptype::G3),
        ] {
            assert_eq!(p.to_value(), want, "{p} changed its stored value");
            assert_eq!(Ptype::try_from_value(&want).unwrap(), p);
        }
    }

    /// A `ptype` outside the four known values is a corrupt row, not a default.
    #[test]
    fn ptype_rejects_unknown_discriminant() {
        assert!(Ptype::try_from_value(&4).is_err());
        assert!(Ptype::try_from_value(&-1).is_err());
    }

    #[test]
    fn ptype_column_is_an_integer() {
        assert_eq!(
            Ptype::db_type().get_column_type(),
            &sea_orm::ColumnType::Integer
        );
    }
}
