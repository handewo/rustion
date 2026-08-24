use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Maps UUIDs to human-readable names for casbin entities.
///
/// `ptype`: see [`NamePtype`].
#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "casbin_name")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// No `column_type` here: `ValueType::column_type()` delegates to
    /// [`NamePtype`]'s `db_type`, so the enum is the only place the column shape
    /// is declared.
    pub ptype: NamePtype,
    /// Bounded `varchar`: unique-indexed, and MySQL cannot index `TEXT` without a
    /// prefix length.
    #[sea_orm(unique, column_type = "String(StringLen::N(255))")]
    pub name: String,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl ActiveModelBehavior for ActiveModel {}

/// What kind of casbin entity a `casbin_names` row names.
///
/// Wider than [`super::casbin_rule::Ptype`]: a name can carry one of the two
/// internal type markers, which are not valid in a `casbin_rule` row. The two
/// are deliberately separate types so a rule's `ptype` cannot be assigned a
/// value only a name can hold.
///
/// Stored as a small integer, like `Ptype`. The `num_value`s are the on-disk
/// format and must never be renumbered. They line up with `Ptype`'s where the
/// two enums overlap (`g1`/`g2`/`g3`), and `0` is left unused because it means
/// `p` there — a value a name cannot hold.
///
/// Serde stays on the wire names, matching `Ptype`; `mock_data.json` spells
/// `ptype` as a string.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum NamePtype {
    /// user → role
    #[sea_orm(num_value = 1)]
    #[serde(rename = "g1")]
    G1,
    /// object group
    #[sea_orm(num_value = 2)]
    #[serde(rename = "g2")]
    G2,
    /// action group
    #[sea_orm(num_value = 3)]
    #[serde(rename = "g3")]
    G3,
    /// Marks the built-in action names (`__internal_action_*`).
    #[sea_orm(num_value = 4)]
    #[serde(rename = "__internal_action_type")]
    InternalActionType,
    /// Marks the built-in object names (`__internal_object_*`).
    #[sea_orm(num_value = 5)]
    #[serde(rename = "__internal_object_type")]
    InternalObjectType,
}

impl NamePtype {
    /// The human-facing name, as used in the admin UI, logs and JSON fixtures.
    /// This is *not* the stored representation — see `num_value` above.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::G1 => "g1",
            Self::G2 => "g2",
            Self::G3 => "g3",
            Self::InternalActionType => "__internal_action_type",
            Self::InternalObjectType => "__internal_object_type",
        }
    }

    /// Reserved for the server's own names; not user-creatable.
    pub const fn is_internal(&self) -> bool {
        matches!(self, Self::InternalActionType | Self::InternalObjectType)
    }

    /// Inverse of [`Self::as_str`], for the few places that carry the name rather
    /// than the value — the admin UI's radio widget, and any text input.
    ///
    /// Not `try_from_value`: that one takes the stored `i32` now.
    pub fn from_name(name: &str) -> Option<Self> {
        <Self as sea_orm::Iterable>::iter().find(|p| p.as_str() == name)
    }
}

impl std::fmt::Display for NamePtype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveEnum, Iterable};

    /// `as_str`, `Display` and the serde rename are three hand-written spellings
    /// of one name; pin them together.
    #[test]
    fn name_ptype_name_spellings_agree() {
        for p in NamePtype::iter() {
            assert_eq!(p.to_string(), p.as_str(), "Display disagrees with as_str");
            assert_eq!(
                serde_json::to_string(&p).unwrap(),
                format!("\"{}\"", p.as_str()),
                "serde disagrees with as_str"
            );
            assert_eq!(
                serde_json::from_str::<NamePtype>(&format!("\"{}\"", p.as_str())).unwrap(),
                p,
                "serde does not round-trip"
            );
        }
    }

    /// The `num_value`s are the on-disk format; renumbering them reinterprets
    /// every existing row. `0` stays unused: it is `p` in
    /// [`super::casbin_rule::Ptype`], which no name can be.
    #[test]
    fn name_ptype_stored_discriminants_are_stable() {
        for (want, p) in [
            (1, NamePtype::G1),
            (2, NamePtype::G2),
            (3, NamePtype::G3),
            (4, NamePtype::InternalActionType),
            (5, NamePtype::InternalObjectType),
        ] {
            assert_eq!(p.to_value(), want, "{p} changed its stored value");
            assert_eq!(NamePtype::try_from_value(&want).unwrap(), p);
        }
        assert!(
            NamePtype::try_from_value(&0).is_err(),
            "0 is reserved for `p`"
        );
        assert!(NamePtype::try_from_value(&6).is_err());
    }

    /// `g1`/`g2`/`g3` mean the same thing in both enums, so they must store the
    /// same number. Nothing depends on it today, but a mismatch would make the
    /// two tables disagree about the same concept.
    #[test]
    fn shared_variants_match_casbin_rule_ptype() {
        use super::super::casbin_rule::Ptype;

        for (name, rule) in [
            (NamePtype::G1, Ptype::G1),
            (NamePtype::G2, Ptype::G2),
            (NamePtype::G3, Ptype::G3),
        ] {
            assert_eq!(name.to_value(), rule.to_value(), "{name} disagrees");
            assert_eq!(name.as_str(), rule.as_str());
        }
    }

    /// An integer column also fixes a latent bug: `ptype` used to be declared
    /// `varchar(12)` while the internal markers are 22 characters. SQLite ignores
    /// declared lengths, but PostgreSQL and MySQL enforce them, so `--init` could
    /// not write those two rows there.
    #[test]
    fn name_ptype_column_is_an_integer_on_every_backend() {
        use sea_orm::{DatabaseBackend, Schema};

        assert_eq!(
            NamePtype::db_type().get_column_type(),
            &sea_orm::ColumnType::Integer
        );

        for backend in [
            DatabaseBackend::Sqlite,
            DatabaseBackend::Postgres,
            DatabaseBackend::MySql,
        ] {
            let ddl = backend
                .build(&Schema::new(backend).create_table_from_entity(Entity))
                .to_string();
            let col = ddl
                .split(',')
                .find(|frag| frag.contains("ptype"))
                .unwrap_or_else(|| panic!("no ptype column in {backend:?} DDL: {ddl}"))
                .to_lowercase();

            assert!(
                col.contains("int"),
                "{backend:?} did not emit an integer ptype: {col}"
            );
            assert!(
                !col.contains("char"),
                "{backend:?} still emits a string ptype: {col}"
            );
        }
    }
}
