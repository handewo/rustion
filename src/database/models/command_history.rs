use serde::{Deserialize, Serialize};

pub(crate) use crate::database::entity::command_history::HistoryScope;

/// One recalled line, as read back for a session's preload.
///
/// Read-only: writes go through `insert_history` as a
/// `entity::command_history::ActiveModel`, so there is no conversion in that
/// direction. `user_id` and `scope` are omitted — the query that produced the
/// row already named them, and the reader knows what it asked for.
#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct CommandHistory {
    /// The row's key. reedline navigates by id, and the preload order
    /// (ascending) makes "greater id" mean "more recent", which is what the
    /// up arrow walks against.
    pub id: i64,
    pub command_line: String,
    /// Unix milliseconds, when the line was accepted at the prompt.
    pub created_at: i64,
}

impl From<crate::database::entity::command_history::Model> for CommandHistory {
    fn from(m: crate::database::entity::command_history::Model) -> Self {
        Self {
            id: m.id,
            command_line: m.command_line,
            created_at: m.created_at,
        }
    }
}
