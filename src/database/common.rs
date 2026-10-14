use std::collections::HashMap;
use std::sync::OnceLock;
use uuid::Uuid;

/// Any subject, object, or role-group whose name begins with "__" is
/// reserved for internal use. Do not create policies that use such names.
pub const OBJ_LOGIN: &str = "__internal_object_login";
pub const OBJ_ADMIN: &str = "__internal_object_admin";
pub const OBJ_PLAYER: &str = "__internal_object_player";

pub const ACT_SHELL: &str = "__internal_action_shell";
pub const ACT_PTY: &str = "__internal_action_pty";
pub const ACT_EXEC: &str = "__internal_action_exec";
pub const ACT_LOGIN: &str = "__internal_action_login";
pub const ACT_SFTP: &str = "__internal_action_sftp";
pub const ACT_SFTP_LIST: &str = "__internal_action_sftp_list";
pub const ACT_SFTP_READ: &str = "__internal_action_sftp_read";
pub const ACT_SFTP_WRITE: &str = "__internal_action_sftp_write";
pub const ACT_SFTP_MKDIR: &str = "__internal_action_sftp_mkdir";
pub const ACT_SFTP_SETSTAT: &str = "__internal_action_sftp_setstat";
pub const ACT_SFTP_FSETSTAT: &str = "__internal_action_sftp_fsetstat";
pub const ACT_SFTP_SYMLINK: &str = "__internal_action_sftp_symlink";
pub const ACT_SFTP_RENAME: &str = "__internal_action_sftp_rename";
pub const ACT_SFTP_DELETE: &str = "__internal_action_sftp_delete";
pub const ACT_DIRECT_TCPIP: &str = "__internal_action_open_direct_tcpip";

pub const INTERNAL_OBJECTS: [&str; 3] = [OBJ_LOGIN, OBJ_ADMIN, OBJ_PLAYER];

/// The SFTP session gate, then one action per kind of operation.
pub const SFTP_ACTIONS: [&str; 10] = [
    ACT_SFTP,
    ACT_SFTP_LIST,
    ACT_SFTP_READ,
    ACT_SFTP_WRITE,
    ACT_SFTP_MKDIR,
    ACT_SFTP_SETSTAT,
    ACT_SFTP_FSETSTAT,
    ACT_SFTP_SYMLINK,
    ACT_SFTP_RENAME,
    ACT_SFTP_DELETE,
];

pub const INTERNAL_ACTIONS: [&str; 15] = [
    ACT_SHELL,
    ACT_DIRECT_TCPIP,
    ACT_EXEC,
    ACT_LOGIN,
    ACT_PTY,
    ACT_SFTP,
    ACT_SFTP_LIST,
    ACT_SFTP_READ,
    ACT_SFTP_WRITE,
    ACT_SFTP_MKDIR,
    ACT_SFTP_SETSTAT,
    ACT_SFTP_FSETSTAT,
    ACT_SFTP_SYMLINK,
    ACT_SFTP_RENAME,
    ACT_SFTP_DELETE,
];

/// The ids of [`SFTP_ACTIONS`]. `session` gates the subsystem; the rest are
/// checked per request (see `server::app::sftp`).
#[derive(Debug, Clone, Copy)]
pub struct SftpActions {
    pub session: Uuid,
    pub list: Uuid,
    pub read: Uuid,
    pub write: Uuid,
    pub mkdir: Uuid,
    pub setstat: Uuid,
    pub fsetstat: Uuid,
    pub symlink: Uuid,
    pub rename: Uuid,
    pub delete: Uuid,
}

impl SftpActions {
    /// Build from a name → id lookup: the startup map, or a test fixture's.
    pub fn from_lookup(id: impl Fn(&str) -> Uuid) -> Self {
        Self {
            session: id(ACT_SFTP),
            list: id(ACT_SFTP_LIST),
            read: id(ACT_SFTP_READ),
            write: id(ACT_SFTP_WRITE),
            mkdir: id(ACT_SFTP_MKDIR),
            setstat: id(ACT_SFTP_SETSTAT),
            fsetstat: id(ACT_SFTP_FSETSTAT),
            symlink: id(ACT_SFTP_SYMLINK),
            rename: id(ACT_SFTP_RENAME),
            delete: id(ACT_SFTP_DELETE),
        }
    }
}

/// Global UUIDs for internal objects and actions, loaded once at service startup
/// TODO: use hash map instead of struct
#[derive(Debug, Clone)]
pub struct InternalUuids {
    pub obj_login: Uuid,
    pub obj_admin: Uuid,
    pub obj_player: Uuid,
    pub act_shell: Uuid,
    pub act_pty: Uuid,
    pub act_exec: Uuid,
    pub act_login: Uuid,
    pub act_direct_tcpip: Uuid,
    pub sftp: SftpActions,
}

static INTERNAL_UUIDS: OnceLock<InternalUuids> = OnceLock::new();

impl InternalUuids {
    /// Install the global ids. The first call wins and later ones are ignored:
    /// outside tests every server in a process opens the same database, and
    /// tests never read the global (see `server::test`).
    pub fn init(uuids: InternalUuids) {
        let _ = INTERNAL_UUIDS.set(uuids);
    }

    /// Get the global UUIDs. Panics if not initialized.
    pub fn get() -> &'static InternalUuids {
        INTERNAL_UUIDS
            .get()
            .expect("InternalUuids not initialized. Call InternalUuids::init() first.")
    }

    /// Build from a map holding every name in [`INTERNAL_OBJECTS`] and
    /// [`INTERNAL_ACTIONS`]. Panics on a missing name.
    pub fn from_ids(ids: &HashMap<&str, Uuid>) -> Self {
        let id = |name: &str| ids[name];
        Self {
            obj_login: id(OBJ_LOGIN),
            obj_admin: id(OBJ_ADMIN),
            obj_player: id(OBJ_PLAYER),
            act_shell: id(ACT_SHELL),
            act_pty: id(ACT_PTY),
            act_exec: id(ACT_EXEC),
            act_login: id(ACT_LOGIN),
            act_direct_tcpip: id(ACT_DIRECT_TCPIP),
            sftp: SftpActions::from_lookup(id),
        }
    }

    /// Get action UUID by action name
    pub fn action_uuid(&self, action_name: &str) -> Option<Uuid> {
        match action_name {
            ACT_SHELL => Some(self.act_shell),
            ACT_PTY => Some(self.act_pty),
            ACT_EXEC => Some(self.act_exec),
            ACT_LOGIN => Some(self.act_login),
            ACT_DIRECT_TCPIP => Some(self.act_direct_tcpip),
            ACT_SFTP => Some(self.sftp.session),
            ACT_SFTP_LIST => Some(self.sftp.list),
            ACT_SFTP_READ => Some(self.sftp.read),
            ACT_SFTP_WRITE => Some(self.sftp.write),
            ACT_SFTP_MKDIR => Some(self.sftp.mkdir),
            ACT_SFTP_SETSTAT => Some(self.sftp.setstat),
            ACT_SFTP_FSETSTAT => Some(self.sftp.fsetstat),
            ACT_SFTP_SYMLINK => Some(self.sftp.symlink),
            ACT_SFTP_RENAME => Some(self.sftp.rename),
            ACT_SFTP_DELETE => Some(self.sftp.delete),
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
pub const TABLE_LOGS: &str = "EVENT_LOG";
pub const TABLE_SESSION_RECORDINGS: &str = "SESSION_RECORDINGS";
pub const TABLE_LIST: [&str; 8] = [
    TABLE_USERS,
    TABLE_TARGETS,
    TABLE_SECRETS,
    TABLE_TARGET_SECRETS,
    TABLE_CASBIN_NAMES,
    TABLE_CASBIN_RULE,
    TABLE_LOGS,
    TABLE_SESSION_RECORDINGS,
];
