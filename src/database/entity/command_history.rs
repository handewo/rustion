use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// One line accepted at one of the bastion's own prompts, kept so the next
/// session of the same user recalls it with the up arrow.
///
/// This is the *convenience* history behind reedline's `History` trait, not the
/// audit trail: `event_log` records every limited-shell command for
/// accountability and is never pruned by hand, while this table is capped per
/// user and scope (`history_size`) and can be cleared without touching the
/// audit. Separating them also keeps the shapes honest — a history row is just
/// a line and a time, because that is all the line editor needs to recall it.
///
/// Rows are keyed by `(user_id, scope)`: the admin shell, the target selector
/// and the limited shell each keep their own list, because a line that means
/// something at one prompt is noise at another.
///
/// Created by `initialize()`'s additive sync like every other table — no
/// migration is needed, and existing databases get it on the next start.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "command_history")]
pub struct Model {
    /// Surrogate key, assigned by the database, ascending with time. reedline's
    /// navigation steps through history by id, so "newer than" must be "greater
    /// id" — the append-only autoincrement guarantees that within one user and
    /// scope. `i64`, not `i32`, for the same reason as `event_log`'s key.
    #[sea_orm(primary_key)]
    pub id: i64,
    /// Whose line this is. The row outlives the session that wrote it, so it
    /// names the user rather than the connection.
    pub user_id: Uuid,
    /// Which prompt the line was accepted at — see [`HistoryScope`].
    pub scope: HistoryScope,
    /// The line as typed, stored whole: a truncated command recalled by the up
    /// arrow is worse than a long row, so unlike `event_log`'s bounded detail
    /// there is no length cut.
    #[sea_orm(column_type = "Text")]
    pub command_line: String,
    /// Unix milliseconds. Stamped when the line was *accepted at the prompt*,
    /// not when the row was written — the write-behind task may lag behind the
    /// session, and the time a command ran is the time it was entered.
    #[sea_orm(indexed)]
    pub created_at: i64,
}

/// Which of the bastion's prompts a history line belongs to — the `scope`
/// column.
///
/// One variant per prompt that keeps a history. Stored as a small integer,
/// matching `event_log`'s `EventKind` and `session_recording`'s
/// `RecordingStatus`. The `num_value`s are the on-disk format and must never be
/// renumbered — a database written by this version reads its `scope` column
/// back through these exact discriminants.
///
/// The limited shell deliberately has a single variant for both of its prompt
/// levels (`>` to pick a binding, `user@target>` to run a command): one
/// reedline editor serves both, and one list recalls lines from either, the way
/// bash mixes everything it ran.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum HistoryScope {
    /// The admin shell's `admin>` prompt.
    #[sea_orm(num_value = 0)]
    #[serde(rename = "admin")]
    Admin,
    /// The interactive target selector, before a connection is opened.
    #[sea_orm(num_value = 1)]
    #[serde(rename = "selector")]
    Selector,
    /// The limited shell, both prompt levels.
    #[sea_orm(num_value = 2)]
    #[serde(rename = "limited")]
    Limited,
}

impl HistoryScope {
    /// The human-facing name, matching the serde rename. Kept as a word for
    /// greppability; the column itself stores the integer.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Selector => "selector",
            Self::Limited => "limited",
        }
    }
}

impl std::fmt::Display for HistoryScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveEnum, Iterable};

    /// The `num_value`s are the on-disk format. Renumbering them silently
    /// reinterprets every existing row, so assert them literally — this test is
    /// meant to fail loudly if anyone reorders the variants.
    #[test]
    fn history_scope_stored_discriminants_are_stable() {
        for (want, s) in [
            (0, HistoryScope::Admin),
            (1, HistoryScope::Selector),
            (2, HistoryScope::Limited),
        ] {
            assert_eq!(s.to_value(), want, "{s} changed its stored value");
            assert_eq!(HistoryScope::try_from_value(&want).unwrap(), s);
        }
        assert_eq!(HistoryScope::iter().count(), 3, "a variant was added");
    }

    /// `as_str`, `Display` and the serde rename are three hand-written spellings
    /// of one name — pin them.
    #[test]
    fn history_scope_name_spellings_agree() {
        for s in HistoryScope::iter() {
            assert_eq!(s.to_string(), s.as_str(), "Display disagrees with as_str");
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.as_str()),
                "serde disagrees with as_str"
            );
            assert_eq!(
                serde_json::from_str::<HistoryScope>(&format!("\"{}\"", s.as_str())).unwrap(),
                s,
                "serde does not round-trip"
            );
        }
    }

    /// A `scope` outside the three known values is a corrupt row, not a default.
    #[test]
    fn history_scope_rejects_unknown_discriminant() {
        assert!(HistoryScope::try_from_value(&3).is_err());
        assert!(HistoryScope::try_from_value(&-1).is_err());
    }

    #[test]
    fn history_scope_column_is_an_integer() {
        assert_eq!(
            HistoryScope::db_type().get_column_type(),
            &sea_orm::ColumnType::Integer
        );
    }
}
