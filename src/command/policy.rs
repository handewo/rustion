//! Loading a command set's JSON config and checking whole command lines.

use std::collections::{BTreeMap, HashMap};

use regex::RegexSet;
use serde::Deserialize;

use super::{Command, ConfigError, ExecError, Registry, Rejection, lex};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    types: TypesConfig,
    commands: Vec<CommandConfig>,
    /// Regexes over the absolute directories `cd` may enter.
    #[serde(default)]
    cd: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypesConfig {
    /// Name -> regex accepted by `{{path}}`.
    #[serde(default)]
    paths: BTreeMap<String, String>,
    /// Type name -> regex, usable as `{{type_name}}`.
    #[serde(default)]
    custom: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandConfig {
    alias: String,
    exec: String,
    #[serde(default)]
    args_list: Vec<String>,
    #[serde(default)]
    options: Vec<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    pty: bool,
    #[serde(default)]
    stdin: bool,
}

/// Names the limited shell answers itself. A command set cannot define them.
pub const RESERVED_ALIASES: &[&str] = &["help", "cd", "pwd", "exit"];

/// Longest input line accepted, in bytes.
const MAX_LINE_LEN: usize = 4096;

#[derive(Debug)]
struct Entry {
    exec: String,
    command: Command,
    /// Shell quoting in effect where `{{args}}` lands in `exec`.
    quoting: Quoting,
    description: String,
    pty: bool,
    stdin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quoting {
    Bare,
    Single,
    Double,
}

impl Quoting {
    /// Can `args` be pasted here without closing the admin's quote or being
    /// expanded inside it? Bare args are already shell-safe word by word.
    fn admits(self, args: &str) -> bool {
        match self {
            Self::Bare => true,
            Self::Single => !args.contains('\''),
            Self::Double => !args.contains(['"', '$', '`', '\\']),
        }
    }
}

/// Finds the quoting context of every `{{args}}` in `exec`.
/// They must agree, and `exec` must not leave a quote open.
fn args_quoting(exec: &str) -> Result<Quoting, ExecError> {
    let mut state = Quoting::Bare;
    let mut found: Option<Quoting> = None;
    let mut escaped = false;
    let mut i = 0;
    while let Some(c) = exec[i..].chars().next() {
        if !escaped && exec[i..].starts_with("{{args}}") {
            if found.is_some_and(|q| q != state) {
                return Err(ExecError::MixedQuoting);
            }
            found = Some(state);
            i += "{{args}}".len();
            continue;
        }
        match (state, c, escaped) {
            (_, _, true) => escaped = false,
            (Quoting::Single, '\'', _) => state = Quoting::Bare,
            (Quoting::Single, _, _) => {}
            (_, '\\', _) => escaped = true,
            (Quoting::Bare, '\'', _) => state = Quoting::Single,
            (Quoting::Bare, '"', _) => state = Quoting::Double,
            (Quoting::Double, '"', _) => state = Quoting::Bare,
            _ => {}
        }
        i += c.len_utf8();
    }
    if state != Quoting::Bare || escaped {
        return Err(ExecError::Unbalanced);
    }
    // Without `{{args}}` the arguments are appended after the (closed) command.
    Ok(found.unwrap_or(Quoting::Bare))
}

/// Every command a user may run, keyed by alias, and where `cd` may go.
#[derive(Debug)]
pub struct Policy {
    commands: HashMap<String, Entry>,
    cd: RegexSet,
    cd_patterns: Vec<String>,
}

/// An allowed command line, ready to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    /// What runs on the target. Never shown to the user: it holds `exec` and
    /// the hidden `{{{...}}}` text.
    pub command_line: String,
    pub template: String,
    /// Run the command on a pty.
    pub pty: bool,
    /// Forward the user's input to the command.
    pub stdin: bool,
}

/// What `help ALIAS` shows: nothing of `exec` or of hidden text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Help {
    pub alias: String,
    pub description: String,
    /// One line per template, starting with the alias.
    pub usage: Vec<String>,
    pub options: Vec<String>,
}

/// An alias is typed as one plain word, so it must lex as itself.
fn is_valid_alias(alias: &str) -> bool {
    !alias.starts_with('-')
        && !alias.is_empty()
        && alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

impl Policy {
    pub fn from_json(src: &str) -> Result<Self, ConfigError> {
        let config: Config = serde_json::from_str(src)?;
        let registry = Registry::new(
            config.types.paths.values().map(String::as_str),
            config
                .types
                .custom
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        )?;
        let cd = RegexSet::new(config.cd.iter().map(|p| format!("^(?:{p})$")))
            .map_err(ConfigError::CdRegex)?;
        let mut commands = HashMap::new();
        for c in config.commands {
            if RESERVED_ALIASES.contains(&c.alias.as_str()) {
                return Err(ConfigError::ReservedAlias(c.alias));
            }
            if !is_valid_alias(&c.alias) {
                return Err(ConfigError::InvalidAlias(c.alias));
            }
            let command = Command::new(&c.args_list, &c.options, &registry).map_err(|source| {
                ConfigError::Template {
                    alias: c.alias.clone(),
                    source,
                }
            })?;
            let quoting = args_quoting(&c.exec).map_err(|source| ConfigError::Exec {
                alias: c.alias.clone(),
                source,
            })?;
            let entry = Entry {
                exec: c.exec,
                command,
                quoting,
                description: c.description,
                pty: c.pty,
                stdin: c.stdin,
            };
            if commands.insert(c.alias.clone(), entry).is_some() {
                return Err(ConfigError::DuplicateAlias(c.alias));
            }
        }
        Ok(Self {
            commands,
            cd,
            cd_patterns: config.cd,
        })
    }

    /// The aliases this set defines, in no particular order.
    pub fn aliases(&self) -> impl Iterator<Item = &str> {
        self.commands.keys().map(String::as_str)
    }

    /// `alias`'s one-line description, empty when it has none.
    pub fn description(&self, alias: &str) -> Option<&str> {
        self.commands.get(alias).map(|e| e.description.as_str())
    }

    pub fn help(&self, alias: &str) -> Option<Help> {
        let entry = self.commands.get(alias)?;
        Some(Help {
            alias: alias.to_owned(),
            description: entry.description.clone(),
            usage: entry.command.usage(alias),
            options: entry.command.options().to_vec(),
        })
    }

    /// Does the `cd` allowlist take the absolute path `dir`?
    pub fn cd_allows(&self, dir: &str) -> bool {
        self.cd.is_match(dir)
    }

    /// The `cd` allowlist as the admin wrote it.
    pub fn cd_patterns(&self) -> &[String] {
        &self.cd_patterns
    }

    /// Checks a full input line such as `usermod -s /sbin/nologin foo`.
    pub fn check(&self, line: &str, pwd: &str) -> Result<Approved, Rejection> {
        if line.len() > MAX_LINE_LEN {
            return Err(Rejection::TooLong(MAX_LINE_LEN));
        }
        let words = lex::split_words(line)?;
        let (alias, args) = words.split_first().ok_or(Rejection::Empty)?;
        let entry = self
            .commands
            .get(*alias)
            .ok_or_else(|| Rejection::UnknownCommand((*alias).to_owned()))?;
        let verified = entry
            .command
            .verify(args, pwd)
            .ok_or(Rejection::NotAllowed)?;
        if !entry.quoting.admits(&verified.args) {
            return Err(Rejection::BreaksQuoting);
        }
        Ok(Approved {
            command_line: render(&entry.exec, &verified.args),
            template: verified.template.to_owned(),
            pty: entry.pty,
            stdin: entry.stdin,
        })
    }
}

/// Builds the shell command line: `{{args}}` is substituted
/// (or the arguments are appended if it's absent).
fn render(exec: &str, args: &str) -> String {
    let line = if exec.contains("{{args}}") {
        exec.replace("{{args}}", args)
    } else {
        format!("{exec} {args}")
    };
    line.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{RegistryError, TemplateErrorKind};
    use serde_json::{Value, json};

    fn load(config: Value) -> Policy {
        Policy::from_json(&config.to_string()).unwrap()
    }

    fn load_err(config: Value) -> ConfigError {
        Policy::from_json(&config.to_string()).unwrap_err()
    }

    fn one(command: Value) -> Policy {
        load(json!({ "commands": [command] }))
    }

    #[test]
    fn usermod_example() {
        let policy = one(json!({
            "exec": "/usr/sbin/usermod {{args}}", "alias": "usermod",
            "argsList": ["-s /sbin/nologin {{name:LOGIN}}", "-e 1 {{name:LOGIN}}"],
        }));
        let ok = policy.check("usermod -s /sbin/nologin foo", "/").unwrap();
        assert_eq!(ok.command_line, "/usr/sbin/usermod -s /sbin/nologin foo");
        assert!(!ok.pty && !ok.stdin);
        assert_eq!(
            policy.check("usermod -e 1 foo", "/").unwrap().template,
            "-e 1 {{name:LOGIN}}"
        );
        assert_eq!(
            policy.check("usermod -u 1001 foo", "/"),
            Err(Rejection::NotAllowed)
        );
        assert!(matches!(
            policy.check("rm -rf /", "/"),
            Err(Rejection::UnknownCommand(_))
        ));
    }

    // #[test]
    // fn escp_becomes_backslash() {
    //     let policy = one(json!({
    //         "exec": "/usr/bin/rsync -a .ssh/id_rsa .ssh/id_rsa.{{escp}}$USER {{args}}:.ssh",
    //         "argsList": ["{{name:HOST}}"], "alias": "syncKey",
    //     }));
    //     assert_eq!(
    //         policy.check("syncKey web01", "/").unwrap().command_line,
    //         r"/usr/bin/rsync -a .ssh/id_rsa .ssh/id_rsa.\$USER web01:.ssh"
    //     );
    // }

    #[test]
    fn nested_quotes_cannot_be_closed() {
        let policy = one(json!({
            "exec": "su - root -c '/usr/bin/grep {{args}} /etc/passwd'", "alias": "g",
            "argsList": ["{{text}}"],
        }));
        assert_eq!(
            policy.check("g '; id; '", "/"),
            Err(Rejection::BreaksQuoting)
        );
        assert_eq!(
            policy.check(r#"g "root""#, "/").unwrap().command_line,
            r#"su - root -c '/usr/bin/grep "root" /etc/passwd'"#
        );
    }

    #[test]
    fn exec_quoting_is_analyzed() {
        assert_eq!(args_quoting("ls {{args}}"), Ok(Quoting::Bare));
        assert_eq!(args_quoting("su -c 'ls {{args}}'"), Ok(Quoting::Single));
        assert_eq!(
            args_quoting(r#"sudo sh -c "ls {{args}}""#),
            Ok(Quoting::Double)
        );
        assert_eq!(args_quoting(r"echo \'{{args}}"), Ok(Quoting::Bare));
        assert_eq!(
            args_quoting("su -c 'ls {{args}}"),
            Err(ExecError::Unbalanced)
        );
        assert_eq!(
            args_quoting("a '{{args}}' {{args}}"),
            Err(ExecError::MixedQuoting)
        );
    }

    #[test]
    fn long_lines_are_rejected_quickly() {
        let policy =
            one(json!({ "exec": "ping", "alias": "ping", "argsList": ["{{ipv4}}:{{port}}"] }));
        let start = std::time::Instant::now();
        let line = format!("ping {}1:80", "1.".repeat(2000));
        assert_eq!(policy.check(&line, "/"), Err(Rejection::NotAllowed));
        assert_eq!(
            policy.check(&"x".repeat(5000), "/"),
            Err(Rejection::TooLong(MAX_LINE_LEN))
        );
        assert!(start.elapsed().as_millis() < 500);
    }

    #[test]
    fn bad_template_fails_at_load() {
        let err = load_err(json!({
            "commands": [{ "exec": "x", "alias": "x", "argsList": ["{{nope}}"] }],
        }));
        assert!(
            matches!(
                &err,
                ConfigError::Template { alias, source }
                    if alias == "x" && source.kind == TemplateErrorKind::UnknownType("nope".into())
            ),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "command `x`: template `{{nope}}`: unknown type `nope`"
        );
    }

    #[test]
    fn config_errors_are_classified() {
        assert!(matches!(
            load_err(json!({ "commands": 1 })),
            ConfigError::Json(_)
        ));
        assert!(matches!(
            load_err(json!({ "commands": [], "types": { "custom": { "name": "x" } } })),
            ConfigError::Registry(RegistryError::ShadowsBuiltin(n)) if n == "name"
        ));
        assert!(matches!(
            load_err(json!({ "commands": [], "types": { "custom": { "bad": "(" } } })),
            ConfigError::Registry(RegistryError::CustomRegex { name, .. }) if name == "bad"
        ));
        assert!(matches!(
            load_err(json!({ "commands": [{ "exec": "su -c 'x", "alias": "a" }] })),
            ConfigError::Exec {
                source: ExecError::Unbalanced,
                ..
            }
        ));
        assert!(matches!(
            load_err(json!({ "commands": [
                { "exec": "x", "alias": "a" }, { "exec": "y", "alias": "a" },
            ] })),
            ConfigError::DuplicateAlias(a) if a == "a"
        ));
        assert!(matches!(
            load_err(json!({ "commands": [], "cd": ["("] })),
            ConfigError::CdRegex(_)
        ));
    }

    #[test]
    fn unknown_fields_are_errors() {
        // A misspelt field would otherwise be dropped and the command left
        // granting less, or more, than the admin wrote.
        for config in [
            json!({ "commands": [{ "exec": "x", "alias": "a", "argslist": ["-h"] }] }),
            json!({ "commands": [], "cmd": [] }),
            json!({ "commands": [], "types": { "path": {} } }),
        ] {
            assert!(
                matches!(load_err(config.clone()), ConfigError::Json(_)),
                "{config}"
            );
        }
    }

    #[test]
    fn builtins_and_odd_aliases_are_refused() {
        for alias in RESERVED_ALIASES {
            assert!(matches!(
                load_err(json!({ "commands": [{ "exec": "x", "alias": alias }] })),
                ConfigError::ReservedAlias(a) if a == *alias
            ));
        }
        for alias in ["", "-x", "a b", "a;b", "'a'", "a/b", "$x"] {
            assert!(matches!(
                load_err(json!({ "commands": [{ "exec": "x", "alias": alias }] })),
                ConfigError::InvalidAlias(a) if a == alias
            ));
        }
    }

    #[test]
    fn pty_and_stdin_are_per_command() {
        let policy = load(json!({ "commands": [
            { "exec": "/usr/bin/htop", "alias": "htop", "pty": true, "stdin": true },
            { "exec": "/usr/bin/top -b", "alias": "top", "pty": true },
            { "exec": "/usr/bin/df -h", "alias": "df" },
        ] }));
        let flags = |line: &str| {
            let ok = policy.check(line, "/").unwrap();
            (ok.pty, ok.stdin)
        };
        assert_eq!(flags("htop"), (true, true));
        assert_eq!(flags("top"), (true, false));
        assert_eq!(flags("df"), (false, false));
    }

    #[test]
    fn cd_allowlist_is_anchored() {
        let policy = load(json!({ "commands": [], "cd": ["/var/log(/.*)?", "/srv/app"] }));
        assert!(policy.cd_allows("/var/log"));
        assert!(policy.cd_allows("/var/log/nginx"));
        assert!(policy.cd_allows("/srv/app"));
        assert!(!policy.cd_allows("/srv/app/x"));
        assert!(!policy.cd_allows("/var/logs"));
        assert!(!policy.cd_allows("/x/var/log"));
        assert_eq!(policy.cd_patterns(), ["/var/log(/.*)?", "/srv/app"]);
        assert!(!load(json!({ "commands": [] })).cd_allows("/"));
    }

    #[test]
    fn help_shows_aliases_never_exec() {
        let policy = load(json!({ "commands": [
            { "exec": "/usr/bin/sort {{args}}", "alias": "sort", "argsList": [""],
              "options": ["-h", "-n", "-i", "-rn"], "description": "sort lines of text files" },
            { "exec": "/usr/bin/systemctl {{args}}", "alias": "systemctl", "argsList": [
                "start {{name:NAME}}",
                "stop {{name:NAME}}",
                "daemon-reload",
                "restart {{name:NAME}}",
                "set-property user-{{digit:UID}}.slice MemoryHigh={{name:SIZE}}",
                "set-property user-{{digit:UID}}.slice MemoryMax={{name:SIZE}}",
                "set-property user-{{digit:UID}}.slice CPUAccounting=yes CPUQuota={{digit:PERCENT}}%",
                "set-property user-{{digit:UID}}.slice MemorySwapMax={{name:SIZE}}",
                "show {{name:PATTERN}}",
                "status {{name:NAME:o}}",
                "enable {{name:NAME}}",
                "disable {{name:NAME}}",
              ], "description": "Control the systemd system and service manager" },
            { "exec": "/usr/bin/ansible-playbook {{args}}", "alias": "deploy",
              "argsList": ["{{{/opt/playbooks/}}}{{name:PLAYBOOK}} -e ticket={{name}}", "{{name::m}}", "{{alpha::om}}"] },
            { "exec": "/usr/bin/uptime", "alias": "uptime" },
        ] }));

        let sort = policy.help("sort").unwrap();
        assert_eq!(sort.description, "sort lines of text files");
        assert_eq!(sort.usage, ["sort"]);
        assert_eq!(sort.options, ["-h", "-n", "-i", "-rn"]);

        let systemctl = policy.help("systemctl").unwrap();
        assert_eq!(
            systemctl.usage,
            [
                "systemctl start NAME",
                "systemctl stop NAME",
                "systemctl daemon-reload",
                "systemctl restart NAME",
                "systemctl set-property user-UID.slice MemoryHigh=SIZE",
                "systemctl set-property user-UID.slice MemoryMax=SIZE",
                "systemctl set-property user-UID.slice CPUAccounting=yes CPUQuota=PERCENT%",
                "systemctl set-property user-UID.slice MemorySwapMax=SIZE",
                "systemctl show PATTERN",
                "systemctl status [NAME]",
                "systemctl enable NAME",
                "systemctl disable NAME",
            ]
        );
        assert!(systemctl.options.is_empty());

        let deploy = policy.help("deploy").unwrap();
        assert_eq!(
            deploy.usage,
            [
                "deploy PLAYBOOK -e ticket=NAME",
                "deploy NAME...",
                "deploy [ALPHA...]"
            ]
        );
        assert_eq!(deploy.description, "");
        assert_eq!(policy.help("uptime").unwrap().usage, ["uptime"]);
        assert_eq!(policy.help("nope"), None);

        let mut aliases: Vec<_> = policy.aliases().collect();
        aliases.sort();
        assert_eq!(aliases, ["deploy", "sort", "systemctl", "uptime"]);
    }
}
