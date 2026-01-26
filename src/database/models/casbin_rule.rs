use crate::database::common::*;
use crate::error;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CasbinRule {
    pub id: String,
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
    pub updated_by: String, // User ID who last updated this rule
    pub updated_at: i64,
}

impl CasbinRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ptype: String,
        v0: String,
        v1: String,
        v2: String,
        v3: String,
        v4: String,
        v5: String,
        updated_by: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            ptype,
            v0,
            v1,
            v2,
            v3,
            v4,
            v5,
            updated_by,
            updated_at: now.timestamp_millis(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CasbinRuleGroup {
    pub id: String,
    pub v0: String,
    pub v0_label: Option<String>,
    pub v1: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum Action {
    Shell,
    Exec,
    Login,
    OpenDirectTcpip,
    Pty,
}

impl Action {
    pub fn to_sql_store(self) -> String {
        match self {
            Action::Shell => ACT_SHELL,
            Action::Exec => ACT_EXEC,
            Action::Login => ACT_LOGIN,
            Action::Pty => ACT_PTY,
            Action::OpenDirectTcpip => ACT_DIRECT_TCPIP,
        }
        .to_string()
    }
}

impl FromStr for Action {
    type Err = error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            ACT_SHELL => Ok(Action::Shell),
            ACT_EXEC => Ok(Action::Exec),
            ACT_LOGIN => Ok(Action::Login),
            ACT_DIRECT_TCPIP => Ok(Action::OpenDirectTcpip),
            ACT_PTY => Ok(Action::Pty),
            _ => Err(error::Error::Casbin(format!("Unknown action: {}", s))),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Shell => write!(f, "shell"),
            Action::Exec => write!(f, "exec"),
            Action::Login => write!(f, "login"),
            Action::Pty => write!(f, "pty"),
            Action::OpenDirectTcpip => write!(f, "open_direct_tcpip"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct InternalObject {
    pub name: String,
    pub is_active: bool,
    pub updated_by: String,
    pub updated_at: i64,
}

impl InternalObject {
    pub fn new(name: String, updated_by: String) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            name,
            is_active: true,
            updated_by,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AllowedObjects {
    pub pid: String,
    pub id: String,
}
