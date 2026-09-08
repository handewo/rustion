use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_recording")]
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
    /// No `column_type` here: `ValueType::column_type()` delegates to
    /// [`RecordingStatus`]'s `db_type`, so the enum is the only place the column
    /// shape is declared. Note this is now an integer column — see the enum.
    pub status: RecordingStatus,
}

/// Whether a recording's channel is still open.
///
/// Stored as a small integer, matching [`super::casbin_rule::Ptype`]. The
/// `num_value`s are the on-disk format and must never be renumbered — a database
/// written by this version reads its `status` column back through these exact
/// discriminants.
///
/// This is a change of storage: the column previously held `"active"` and
/// `"completed"` as text, so an existing database needs its values rewritten and
/// the column retyped. There is no migration runner in this tree and
/// [`crate::database::DatabaseRepository::initialize`] only creates missing
/// tables, so that is a manual step —
/// `migrations/001-recording-status-integer.sql`. Until it is applied `status`
/// fails to decode, and because the failure is per-query rather than per-row, one
/// stale row empties every recording list.
///
/// Serde deliberately stays on the names: a status is spelled as a word
/// everywhere outside the column, and that is a separate concern from how it is
/// stored.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter, DeriveActiveEnum, Serialize, Deserialize,
)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum RecordingStatus {
    /// Set when the recording is opened.
    #[sea_orm(num_value = 0)]
    #[serde(rename = "active")]
    Active,
    /// Set when the channel closes.
    #[sea_orm(num_value = 1)]
    #[serde(rename = "completed")]
    Completed,
}

impl RecordingStatus {
    /// The human-facing name, as used in the admin UI and the player's table.
    /// This is *not* the stored representation — see `num_value` above.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Completed => "completed",
        }
    }
}

impl std::fmt::Display for RecordingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveEnum, Iterable};

    /// The `num_value`s are the on-disk format; renumbering them reinterprets
    /// every existing row.
    #[test]
    fn recording_status_stored_discriminants_are_stable() {
        for (want, s) in [
            (0, RecordingStatus::Active),
            (1, RecordingStatus::Completed),
        ] {
            assert_eq!(s.into_value(), want, "{s:?} changed its stored value");
            assert_eq!(RecordingStatus::try_from_value(&want).unwrap(), s);
        }
        assert_eq!(RecordingStatus::iter().count(), 2, "a variant was added");
    }

    /// `as_str`, `Display` and the serde rename are three hand-written spellings
    /// of one name; pin them together.
    #[test]
    fn recording_status_name_spellings_agree() {
        for s in RecordingStatus::iter() {
            assert_eq!(s.to_string(), s.as_str(), "Display disagrees with as_str");
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.as_str()),
                "serde disagrees with as_str"
            );
            assert_eq!(
                serde_json::from_str::<RecordingStatus>(&format!("\"{}\"", s.as_str())).unwrap(),
                s,
                "serde does not round-trip"
            );
        }
    }
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
