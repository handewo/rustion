/// Any subject, object, or role-group whose name begins with “__” is
/// reserved for internal use. Do not create policies that use such names.
pub const OBJ_LOGIN: &str = "__login";
pub const OBJ_ADMIN: &str = "__admin";

pub const INTERNAL_OBJECTS: [&str; 2] = [OBJ_LOGIN, OBJ_ADMIN];

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
