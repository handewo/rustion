/// Any subject, object, or role-group whose name begins with “__” is
/// reserved for internal use. Do not create policies that use such names.
pub const OBJ_LOGIN: &str = "__internal_object_login";
pub const OBJ_ADMIN: &str = "__internal_object_admin";

pub const ACT_SHELL: &str = "__internal_action_shell";
pub const ACT_PTY: &str = "__internal_action_pty";
pub const ACT_EXEC: &str = "__internal_action_exec";
pub const ACT_LOGIN: &str = "__internal_action_login";
pub const ACT_DIRECT_TCPIP: &str = "__internal_action_open_direct_tcpip";

pub const INTERNAL_OBJECTS: [&str; 7] = [
    OBJ_LOGIN,
    OBJ_ADMIN,
    ACT_SHELL,
    ACT_DIRECT_TCPIP,
    ACT_EXEC,
    ACT_LOGIN,
    ACT_PTY,
];

pub const TABLE_CASBIN_RULE: &str = "CASBIN_RULE";
pub const TABLE_USERS: &str = "USERS";
pub const TABLE_TARGETS: &str = "TARGETS";
pub const TABLE_SECRETS: &str = "SECRETS";
pub const TABLE_TARGET_SECRETS: &str = "TARGET_SECRETS";
pub const TABLE_INTERNAL_OBJECTS: &str = "INTERNAL_OBJECTS";
pub const TABLE_LOGS: &str = "LOGS";
pub const TABLE_LIST: [&str; 7] = [
    TABLE_USERS,
    TABLE_TARGETS,
    TABLE_SECRETS,
    TABLE_TARGET_SECRETS,
    TABLE_INTERNAL_OBJECTS,
    TABLE_CASBIN_RULE,
    TABLE_LOGS,
];
