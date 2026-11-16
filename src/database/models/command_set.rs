use crate::database::Uuid;
use crate::database::entity::command_set;
use serde::{Deserialize, Serialize};

/// A named set of commands for the limited shell. `config` is checked with
/// `crate::command::Policy::from_json` before it is saved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSet {
    pub id: Uuid,
    pub name: String,
    pub config: String,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl CommandSet {
    pub fn new(updated_by: Uuid) -> Self {
        Self {
            id: Uuid::now_v7(),
            name: String::new(),
            config: String::new(),
            is_active: true,
            updated_by,
            // Stamped by the repository on write.
            updated_at: 0,
        }
    }
}

impl From<command_set::Model> for CommandSet {
    fn from(m: command_set::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            config: m.config,
            is_active: m.is_active,
            updated_by: m.updated_by,
            updated_at: m.updated_at,
        }
    }
}

impl CommandSet {
    pub(in crate::database) fn into_active_model(self) -> command_set::ActiveModel {
        use sea_orm::ActiveValue::Set;
        command_set::ActiveModel {
            id: Set(self.id),
            name: Set(self.name),
            config: Set(self.config),
            is_active: Set(self.is_active),
            updated_by: Set(self.updated_by),
            updated_at: Set(self.updated_at),
        }
    }
}
