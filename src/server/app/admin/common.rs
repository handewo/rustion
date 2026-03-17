// pub const CMD_QUERY_TARGETS: &str = "query targets";
// pub const CMD_QUERY_USERS: &str = "query users";
// pub const CMD_QUERY_LOGS: &str = "query logs";
// pub const CMD_QUERY_CASBIN_RULES: &str = "query casbin rules";
pub const CMD_DATABASE: &str = "database";
pub const CMD_MANAGE: &str = "manage";
pub const CMD_HELP: &str = "help";
pub const CMD_FLUSH_PRIVILEGES: &str = "flush_privileges";
pub const CMD_QUIT: &str = "quit";
pub const CMD_EXIT: &str = "exit";
pub const COMMAND_LIST: [&str; 5] = [
    CMD_DATABASE,
    CMD_MANAGE,
    CMD_FLUSH_PRIVILEGES,
    CMD_HELP,
    CMD_EXIT,
];

pub const MANAGE_USERS: &str = "Users";
pub const MANAGE_TARGETS: &str = "Targets";
pub const MANAGE_SECRETS: &str = "Secrets";
pub const MANAGE_BIND: &str = "Bind";
pub const MANAGE_ROLE: &str = "Role";
pub const MANAGE_PERMISSIONS: &str = "Permissions";
pub const MANAGE_CASBIN_NAMES: &str = "Groups";
pub const MANAGE_LIST: [&str; 7] = [
    MANAGE_USERS,
    MANAGE_TARGETS,
    MANAGE_SECRETS,
    MANAGE_BIND,
    MANAGE_PERMISSIONS,
    MANAGE_CASBIN_NAMES,
    MANAGE_ROLE,
];

pub const MAX_POPUP_WINDOW_COL: u16 = 60;
pub const MAX_POPUP_WINDOW_ROW: u16 = 40;
pub const MIN_WINDOW_COL: u16 = 20;
pub const MIN_WINDOW_ROW: u16 = 15;
