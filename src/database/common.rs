use std::sync::OnceLock;
use uuid::Uuid;

/// Any subject, object, or role-group whose name begins with "__" is
/// reserved for internal use. Do not create policies that use such names.
pub const OBJ_LOGIN: &str = "__internal_object_login";
pub const OBJ_ADMIN: &str = "__internal_object_admin";

pub const ACT_SHELL: &str = "__internal_action_shell";
pub const ACT_PTY: &str = "__internal_action_pty";
pub const ACT_EXEC: &str = "__internal_action_exec";
pub const ACT_LOGIN: &str = "__internal_action_login";
pub const ACT_DIRECT_TCPIP: &str = "__internal_action_open_direct_tcpip";

pub const INTERNAL_OBJECT_TYPE: &str = "__internal_object_type";
pub const INTERNAL_ACTION_TYPE: &str = "__internal_action_type";

pub const INTERNAL_OBJECTS: [&str; 2] = [OBJ_LOGIN, OBJ_ADMIN];

pub const INTERNAL_ACTIONS: [&str; 5] = [ACT_SHELL, ACT_DIRECT_TCPIP, ACT_EXEC, ACT_LOGIN, ACT_PTY];

/// Global UUIDs for internal objects and actions, loaded once at service startup
#[derive(Debug, Clone)]
pub struct InternalUuids {
    pub obj_login: Uuid,
    pub obj_admin: Uuid,
    pub act_shell: Uuid,
    pub act_pty: Uuid,
    pub act_exec: Uuid,
    pub act_login: Uuid,
    pub act_direct_tcpip: Uuid,
}

static INTERNAL_UUIDS: OnceLock<InternalUuids> = OnceLock::new();

impl InternalUuids {
    /// Initialize the global UUIDs. Should be called once at service startup.
    pub fn init(uuids: InternalUuids) {
        INTERNAL_UUIDS
            .set(uuids)
            .expect("InternalUuids already initialized");
    }

    /// Get the global UUIDs. Panics if not initialized.
    pub fn get() -> &'static InternalUuids {
        INTERNAL_UUIDS
            .get()
            .expect("InternalUuids not initialized. Call InternalUuids::init() first.")
    }

    /// Check if initialized (for testing)
    pub fn is_initialized() -> bool {
        INTERNAL_UUIDS.get().is_some()
    }

    /// Get action UUID by action name
    pub fn action_uuid(&self, action_name: &str) -> Option<Uuid> {
        match action_name {
            ACT_SHELL => Some(self.act_shell),
            ACT_PTY => Some(self.act_pty),
            ACT_EXEC => Some(self.act_exec),
            ACT_LOGIN => Some(self.act_login),
            ACT_DIRECT_TCPIP => Some(self.act_direct_tcpip),
            _ => None,
        }
    }
}

pub const TABLE_CASBIN_RULE: &str = "CASBIN_RULE";
pub const TABLE_USERS: &str = "USERS";
pub const TABLE_TARGETS: &str = "TARGETS";
pub const TABLE_SECRETS: &str = "SECRETS";
pub const TABLE_TARGET_SECRETS: &str = "TARGET_SECRETS";
pub const TABLE_CASBIN_NAMES: &str = "CASBIN_NAMES";
pub const TABLE_LOGS: &str = "LOGS";
pub const TABLE_LIST: [&str; 7] = [
    TABLE_USERS,
    TABLE_TARGETS,
    TABLE_SECRETS,
    TABLE_TARGET_SECRETS,
    TABLE_CASBIN_NAMES,
    TABLE_CASBIN_RULE,
    TABLE_LOGS,
];
