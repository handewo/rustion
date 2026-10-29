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

pub const MAX_USERNAME_LEN: usize = 40;

/// Applies to a target's name and hostname alike, which is why it is not
/// spelled per-field.
pub const MAX_NAME_LEN: usize = 50;
