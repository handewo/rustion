// pub const CMD_QUERY_TARGETS: &str = "query targets";
// pub const CMD_QUERY_USERS: &str = "query users";
// pub const CMD_QUERY_LOGS: &str = "query logs";
// pub const CMD_QUERY_CASBIN_RULES: &str = "query casbin rules";
pub const CMD_DATABASE: &str = "database";
pub const CMD_MANAGE: &str = "manage";
pub const CMD_HELP: &str = "help";
pub const CMD_QUIT: &str = "quit";
pub const CMD_EXIT: &str = "exit";
pub const COMMAND_LIST: [&str; 4] = [CMD_DATABASE, CMD_MANAGE, CMD_HELP, CMD_EXIT];

pub const MANAGE_USERS: &str = "users";
pub const MANAGE_TARGETS: &str = "targets";
pub const MANAGE_SECRETS: &str = "secrets";
pub const MANAGE_LIST: [&str; 3] = [MANAGE_USERS, MANAGE_TARGETS, MANAGE_SECRETS];
