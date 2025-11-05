use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TargetSecret {
    pub id: String,
    pub target_id: String,
    pub secret_id: String,
    pub is_active: bool,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// For login to remote target
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Secret {
    pub id: String,
    pub name: String, //for display only
    pub user: String, //login user of target
    pub(in crate::database) password: Option<String>,
    pub(in crate::database) private_key: Option<String>,
    pub(in crate::database) public_key: Option<String>,
    pub is_active: bool,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl TargetSecret {
    pub fn new(target_id: String, secret_id: String, created_by: String) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4().to_string(),
            target_id,
            secret_id,
            is_active: true,
            created_by,
            created_at: now,
            updated_at: now,
        }
    }
}

impl Secret {
    pub fn new(name: String, user: String, created_by: String) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            user,
            password: None,
            private_key: None,
            public_key: None,
            is_active: true,
            created_by,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_password(mut self, password: Option<String>) -> Self {
        self.password = password;
        self
    }

    pub fn print_password(&self) -> String {
        if self.password.is_some() {
            "********".to_string()
        } else {
            String::new()
        }
    }

    pub fn with_private_key(mut self, private_key: Option<String>) -> Self {
        self.private_key = private_key;
        self
    }

    pub fn print_private_key(&self) -> String {
        if self.private_key.is_some() {
            "********".to_string()
        } else {
            String::new()
        }
    }

    pub fn with_public_key(mut self, public_key: Option<String>) -> Self {
        self.public_key = public_key;
        self
    }

    pub fn print_public_key(&self) -> String {
        if self.public_key.is_some() {
            "********".to_string()
        } else {
            String::new()
        }
    }

    pub fn take_password(&mut self) -> Option<String> {
        self.password.take()
    }

    pub fn take_private_key(&mut self) -> Option<String> {
        self.private_key.take()
    }

    pub fn take_public_key(&mut self) -> Option<String> {
        self.public_key.take()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TargetSecretName {
    // policy id in casbin_rule
    pub pid: String,
    // target_secret id
    pub id: String,
    pub target_id: String,
    pub target_name: String,
    pub secret_id: String,
    pub secret_user: String,
}
