use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSecret {
    pub id: Uuid,
    pub target_id: Uuid,
    pub secret_id: Uuid,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

/// For login to remote target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub name: String, //for display only
    pub user: String, //login user of target
    pub(in crate::database) password: Option<String>,
    pub(in crate::database) private_key: Option<String>,
    pub(in crate::database) public_key: Option<String>,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl Secret {
    /// A blank secret for the editor to fill in. `updated_at` is left at 0
    /// because the repository stamps it on write.
    pub fn new(updated_by: Uuid) -> Self {
        Self {
            id: Uuid::now_v7(),
            name: String::default(),
            user: String::default(),
            password: None,
            private_key: None,
            public_key: None,
            is_active: true,
            updated_by,
            updated_at: 0,
        }
    }

    pub fn print_password(&self) -> String {
        if self.password.is_some() {
            "********".to_string()
        } else {
            String::new()
        }
    }

    pub fn print_private_key(&self) -> String {
        if self.private_key.is_some() {
            "********".to_string()
        } else {
            String::new()
        }
    }

    pub fn print_public_key(&self) -> String {
        if let Some(p) = self.public_key.as_ref() {
            crate::common::shorten_ssh_pubkey(p)
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

#[derive(Default, Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct TargetSecretName {
    // policy id in casbin_rule
    pub pid: Uuid,
    // target_secret id
    pub id: Uuid,
    pub target_id: Uuid,
    pub target_name: String,
    pub secret_id: Uuid,
    pub secret_user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct SecretInfo {
    pub id: Uuid,
    pub name: String,
    pub user: String,
    pub is_bound: bool,
}

impl From<crate::database::entity::secret::Model> for Secret {
    fn from(m: crate::database::entity::secret::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            user: m.user,
            password: m.password,
            private_key: m.private_key,
            public_key: m.public_key,
            is_active: m.is_active,
            updated_by: m.updated_by,
            updated_at: m.updated_at,
        }
    }
}

impl Secret {
    pub(in crate::database) fn into_active_model(
        self,
    ) -> crate::database::entity::secret::ActiveModel {
        use sea_orm::ActiveValue::Set;
        crate::database::entity::secret::ActiveModel {
            id: Set(self.id),
            name: Set(self.name),
            user: Set(self.user),
            password: Set(self.password),
            private_key: Set(self.private_key),
            public_key: Set(self.public_key),
            is_active: Set(self.is_active),
            updated_by: Set(self.updated_by),
            updated_at: Set(self.updated_at),
        }
    }
}

impl From<crate::database::entity::target_secret::Model> for TargetSecret {
    fn from(m: crate::database::entity::target_secret::Model) -> Self {
        Self {
            id: m.id,
            target_id: m.target_id,
            secret_id: m.secret_id,
            is_active: m.is_active,
            updated_by: m.updated_by,
            updated_at: m.updated_at,
        }
    }
}

impl TargetSecret {
    pub(in crate::database) fn into_active_model(
        self,
    ) -> crate::database::entity::target_secret::ActiveModel {
        use sea_orm::ActiveValue::Set;
        crate::database::entity::target_secret::ActiveModel {
            id: Set(self.id),
            target_id: Set(self.target_id),
            secret_id: Set(self.secret_id),
            is_active: Set(self.is_active),
            updated_by: Set(self.updated_by),
            updated_at: Set(self.updated_at),
        }
    }
}
