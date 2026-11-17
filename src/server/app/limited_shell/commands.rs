//! What one line typed at a target means: a built-in, a command from the
//! granted sets, or a refusal. No I/O here, so every decision is testable.

use crate::command::{Approved, LexError, Rejection, kind::normalize, lex};
use crate::i18n::Strings;
use crate::server::CompiledCommandSet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The built-ins, with the usage line help shows for each.
const BUILTINS: [(&str, &str); 4] = [
    ("help", "help [COMMAND]"),
    ("cd", "cd [DIR]"),
    ("pwd", "pwd"),
    ("exit", "exit"),
];

/// The command sets a user holds on one binding, merged.
pub(crate) struct Commands {
    sets: Vec<Arc<CompiledCommandSet>>,
    /// Alias -> index into `sets` of the one set defining it.
    owner: BTreeMap<String, usize>,
    /// Aliases two or more sets define -> those sets' names. They run nowhere.
    duplicates: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cd {
    Home,
    /// `cd -`
    Back,
    /// The directory as typed, quotes removed.
    Dir(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Line {
    Empty,
    Help(Option<String>),
    Cd(Cd),
    Pwd,
    Exit,
    Run {
        alias: String,
        /// The set the alias came from.
        set: String,
        approved: Approved,
    },
}

/// Why a line was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    Rejected {
        alias: Option<String>,
        rejection: Rejection,
    },
    /// The alias is defined by more than one granted set.
    Duplicate(String),
    /// A built-in typed with arguments it does not take: its usage line.
    Usage(&'static str),
}

/// The exit codes a refusal leaves in the prompt, on the scale a shell
/// already uses: 127 a name that is no command, 126 a command that may
/// not run, 2 a line that cannot be read as a command, 1 anything else
/// that failed.
pub(crate) const EXIT_NOT_FOUND: u32 = 127;
pub(crate) const EXIT_NOT_ALLOWED: u32 = 126;
pub(crate) const EXIT_BAD_LINE: u32 = 2;
pub(crate) const EXIT_FAILURE: u32 = 1;

/// A refusal as the audit trail stores it: in no language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DenyReason {
    UnknownCommand,
    NotAllowed,
    BreaksQuoting,
    UnbalancedQuote,
    TooLong,
    DuplicateAlias,
    CdNotAllowed,
    BadUsage,
}

impl DenyReason {
    pub(crate) fn text(self, tr: &Strings) -> &'static str {
        match self {
            DenyReason::UnknownCommand => tr.r_unknown_command,
            DenyReason::NotAllowed => tr.r_not_allowed,
            DenyReason::BreaksQuoting => tr.r_breaks_quoting,
            DenyReason::UnbalancedQuote => tr.r_unbalanced_quote,
            DenyReason::TooLong => tr.r_too_long,
            DenyReason::DuplicateAlias => tr.r_duplicate_alias,
            DenyReason::CdNotAllowed => tr.r_cd_not_allowed,
            DenyReason::BadUsage => tr.r_bad_usage,
        }
    }
}

impl Refusal {
    pub(crate) fn reason(&self) -> DenyReason {
        match self {
            Refusal::Rejected { rejection, .. } => match rejection {
                Rejection::Lex(_) => DenyReason::UnbalancedQuote,
                Rejection::Empty | Rejection::UnknownCommand(_) => DenyReason::UnknownCommand,
                Rejection::TooLong(_) => DenyReason::TooLong,
                Rejection::NotAllowed => DenyReason::NotAllowed,
                Rejection::BreaksQuoting => DenyReason::BreaksQuoting,
            },
            Refusal::Duplicate(_) => DenyReason::DuplicateAlias,
            Refusal::Usage(_) => DenyReason::BadUsage,
        }
    }

    /// The code this refusal leaves in the prompt.
    pub(crate) fn code(&self) -> u32 {
        match self {
            Refusal::Rejected { rejection, .. } => match rejection {
                Rejection::Empty | Rejection::UnknownCommand(_) => EXIT_NOT_FOUND,
                Rejection::Lex(_) => EXIT_BAD_LINE,
                _ => EXIT_NOT_ALLOWED,
            },
            Refusal::Duplicate(_) => EXIT_NOT_ALLOWED,
            Refusal::Usage(_) => EXIT_BAD_LINE,
        }
    }

    /// What the user is told. Never names `exec`.
    pub(crate) fn message(&self, tr: &Strings) -> String {
        use crate::fill;
        match self {
            Refusal::Rejected {
                alias: Some(alias),
                rejection: Rejection::UnknownCommand(_),
            } => fill!(tr.ls_unknown_command, name = alias),
            Refusal::Rejected {
                alias: Some(alias),
                rejection: Rejection::NotAllowed,
            } => fill!(tr.ls_not_allowed, name = alias),
            Refusal::Rejected { .. } => fill!(tr.ls_refused, reason = self.reason().text(tr)),
            Refusal::Duplicate(alias) => fill!(tr.ls_duplicate_alias, name = alias),
            Refusal::Usage(usage) => fill!(tr.ls_usage_is, usage = usage),
        }
    }
}

impl Commands {
    /// `sets` as `command_sets_for` returns them, by name.
    pub(crate) fn new(sets: Vec<Arc<CompiledCommandSet>>) -> Self {
        let mut defined: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, set) in sets.iter().enumerate() {
            for alias in set.policy.aliases() {
                defined.entry(alias.to_owned()).or_default().push(i);
            }
        }
        let mut owner = BTreeMap::new();
        let mut duplicates = BTreeMap::new();
        for (alias, at) in defined {
            if let [one] = at[..] {
                owner.insert(alias, one);
            } else {
                let names = at.iter().map(|&i| sets[i].name.clone()).collect();
                duplicates.insert(alias, names);
            }
        }
        Self {
            sets,
            owner,
            duplicates,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Aliases defined by more than one set, with the sets defining them.
    pub(crate) fn duplicates(&self) -> &BTreeMap<String, Vec<String>> {
        &self.duplicates
    }

    /// What tab completes: the aliases that run, then the built-ins.
    pub(crate) fn completions(&self) -> Vec<String> {
        self.owner
            .keys()
            .cloned()
            .chain(BUILTINS.iter().map(|(name, _)| name.to_string()))
            .collect()
    }

    /// Whether `cd` may enter the absolute, normalised `dir`. Home is always
    /// allowed, so `cd` alone works whatever the sets say.
    pub(crate) fn cd_allows(&self, dir: &str, home: &str) -> bool {
        dir == home || self.sets.iter().any(|s| s.policy.cd_allows(dir))
    }

    /// Read one line typed at a target whose working directory is `pwd`.
    pub(crate) fn parse(&self, line: &str, pwd: &str) -> Result<Line, Refusal> {
        let rejected = |alias: Option<&str>, rejection| Refusal::Rejected {
            alias: alias.map(str::to_owned),
            rejection,
        };
        let words = lex::split_words(line).map_err(|e| rejected(None, Rejection::Lex(e)))?;
        let Some((&first, args)) = words.split_first() else {
            return Ok(Line::Empty);
        };
        let usage = |name: &str| {
            let (_, usage) = BUILTINS.iter().find(|(n, _)| *n == name).unwrap();
            Refusal::Usage(usage)
        };
        match first {
            "help" => match args {
                [] => return Ok(Line::Help(None)),
                [alias] => return Ok(Line::Help(Some((*alias).to_owned()))),
                _ => return Err(usage("help")),
            },
            "cd" => {
                return match args {
                    [] => Ok(Line::Cd(Cd::Home)),
                    ["-"] => Ok(Line::Cd(Cd::Back)),
                    [dir] => unquote(dir).map(|d| Line::Cd(Cd::Dir(d))).ok_or_else(|| {
                        rejected(Some("cd"), Rejection::Lex(LexError { offset: 0 }))
                    }),
                    _ => Err(usage("cd")),
                };
            }
            "pwd" if args.is_empty() => return Ok(Line::Pwd),
            "pwd" => return Err(usage("pwd")),
            "exit" if args.is_empty() => return Ok(Line::Exit),
            "exit" => return Err(usage("exit")),
            _ => {}
        }
        if self.duplicates.contains_key(first) {
            return Err(Refusal::Duplicate(first.to_owned()));
        }
        let Some(&i) = self.owner.get(first) else {
            return Err(rejected(
                Some(first),
                Rejection::UnknownCommand(first.to_owned()),
            ));
        };
        let set = &self.sets[i];
        let approved = set
            .policy
            .check(line, pwd)
            .map_err(|r| rejected(Some(first), r))?;
        Ok(Line::Run {
            alias: first.to_owned(),
            set: set.name.clone(),
            approved,
        })
    }

    /// The directory `cd DIR` names, from `pwd`.
    pub(crate) fn resolve(pwd: &str, dir: &str) -> String {
        normalize(pwd, dir)
    }

    /// `help` alone: the commands with their descriptions, the built-ins, and
    /// where `cd` may go.
    pub(crate) fn help(&self, tr: &Strings) -> Vec<String> {
        let mut rows: Vec<(String, String)> = self
            .owner
            .iter()
            .map(|(alias, &i)| {
                let description = self.sets[i].policy.description(alias).unwrap_or_default();
                (alias.clone(), description.to_owned())
            })
            .collect();
        let builtins: Vec<(String, String)> = BUILTINS
            .iter()
            .map(|(name, usage)| {
                let description = match *name {
                    "help" => tr.ls_help_help,
                    "cd" => tr.ls_help_cd,
                    "pwd" => tr.ls_help_pwd,
                    _ => tr.ls_help_exit,
                };
                (usage.to_string(), description.to_owned())
            })
            .collect();
        let width = rows
            .iter()
            .chain(&builtins)
            .map(|(name, _)| unicode_width::UnicodeWidthStr::width(name.as_str()))
            .max()
            .unwrap_or(0);
        let row = |(name, description): &(String, String)| {
            if description.is_empty() {
                format!("  {name}")
            } else {
                let pad = width - unicode_width::UnicodeWidthStr::width(name.as_str());
                format!("  {name}{}  {description}", " ".repeat(pad))
            }
        };

        let mut out = Vec::new();
        out.push(tr.ls_commands.to_owned());
        if rows.is_empty() {
            out.push(format!("  {}", tr.ls_none));
        }
        out.extend(rows.iter_mut().map(|r| row(r)));
        out.push(String::new());
        out.push(tr.ls_builtins.to_owned());
        out.extend(builtins.iter().map(row));
        let mut cd: Vec<&str> = self
            .sets
            .iter()
            .flat_map(|s| s.policy.cd_patterns())
            .map(String::as_str)
            .collect();
        cd.sort_unstable();
        cd.dedup();
        out.push(String::new());
        out.push(tr.ls_cd_allowed.to_owned());
        out.push(format!("  {}", tr.ls_cd_home));
        out.extend(cd.iter().map(|p| format!("  {p}")));
        out
    }

    /// `help ALIAS`, in the layout of `--help`: name, description, usage
    /// lines, options. `None` for an alias that does not run here.
    pub(crate) fn help_for(&self, alias: &str, tr: &Strings) -> Option<Vec<String>> {
        if let Some((_, usage)) = BUILTINS.iter().find(|(n, _)| *n == alias) {
            return Some(vec![usage.to_string()]);
        }
        let &i = self.owner.get(alias)?;
        let help = self.sets[i].policy.help(alias)?;
        let mut out = vec![help.alias];
        if !help.description.is_empty() {
            out.push(String::new());
            out.push(help.description);
        }
        out.push(String::new());
        out.push(tr.ls_usage.to_owned());
        out.extend(help.usage.iter().map(|u| format!("  {u}")));
        if !help.options.is_empty() {
            out.push(String::new());
            out.push(tr.ls_options.to_owned());
            out.push(format!("  {}", help.options.join(", ")));
        }
        Some(out)
    }
}

/// `cd`'s argument with one level of quotes removed: `'my dir'`, `"my dir"`
/// or `plain`. `None` for anything else, such as quotes in the middle of a
/// word, or a control character. The result is quoted again before it is
/// sent, so no character in it reaches the target's shell as syntax.
fn unquote(word: &str) -> Option<String> {
    let inner = match word.chars().next() {
        Some(q @ ('\'' | '"')) if word.len() >= 2 && word.ends_with(q) => {
            let inner = &word[1..word.len() - 1];
            (!inner.contains(q)).then_some(inner)?
        }
        _ if word.contains(['\'', '"']) => return None,
        _ => word,
    };
    (!inner.is_empty() && !inner.chars().any(char::is_control)).then(|| inner.to_owned())
}

/// The directory `cd DIR` names with `~` read as the home directory: `~`
/// alone and a leading `~/` are the home directory, and nothing else
/// changes. A shell expands `~` textually and leaves `..` for the file
/// system to resolve, so this does too: `~/log/..` reaches the target as
/// written and fails there when `log` does not exist. `~user` stays as
/// written, another user's home on the target being not the bastion's to
/// know, so the allowlist denies it like any other path.
pub(crate) fn expand_tilde(dir: &str, home: &str) -> String {
    if dir == "~" {
        return home.to_owned();
    }
    dir.strip_prefix("~/")
        .map_or_else(|| dir.to_owned(), |rest| format!("{home}/{rest}"))
}

/// `s` as one single-quoted sh word: any byte but `'` stands for itself
/// inside single quotes, and `'` is closed, escaped and reopened.
pub(crate) fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Uuid;
    use crate::i18n::Lang;
    use serde_json::json;

    fn set(name: &str, config: serde_json::Value) -> Arc<CompiledCommandSet> {
        Arc::new(CompiledCommandSet {
            id: Uuid::now_v7(),
            name: name.into(),
            policy: crate::command::Policy::from_json(&config.to_string()).unwrap(),
        })
    }

    fn ops() -> Arc<CompiledCommandSet> {
        set(
            "ops",
            json!({
                "commands": [
                    { "alias": "sort", "exec": "/usr/bin/sort {{args}}", "argsList": [""],
                      "options": ["-h", "-n", "-i", "-rn"], "description": "sort lines of text files" },
                    { "alias": "systemctl", "exec": "/usr/bin/systemctl {{args}}", "argsList": [
                        "start {{name:NAME}}", "status {{name:NAME:o}}",
                      ], "description": "Control the systemd system and service manager" },
                    { "alias": "cat", "exec": "/usr/bin/cat {{args}}", "argsList": ["{{anypath:FILE}}"] },
                    { "alias": "htop", "exec": "/usr/bin/htop", "pty": true, "stdin": true },
                ],
                "cd": ["/var/log(/.*)?"],
            }),
        )
    }

    fn tr() -> &'static Strings {
        Lang::En.strings()
    }

    fn run(commands: &Commands, line: &str, pwd: &str) -> Approved {
        match commands.parse(line, pwd) {
            Ok(Line::Run { approved, .. }) => approved,
            other => panic!("{line}: {other:?}"),
        }
    }

    #[test]
    fn refusals_carry_shell_style_exit_codes() {
        let c = Commands::new(vec![ops()]);
        // 127 a name that is no command; 2 a built-in misused or a line
        // that cannot be read as one.
        assert_eq!(c.parse("nope", "/").unwrap_err().code(), EXIT_NOT_FOUND);
        assert_eq!(c.parse("pwd x", "/").unwrap_err().code(), EXIT_BAD_LINE);
        assert_eq!(c.parse("cd a'b'", "/").unwrap_err().code(), EXIT_BAD_LINE);
    }

    #[test]
    fn builtins_are_read_before_the_sets() {
        let c = Commands::new(vec![ops()]);
        assert_eq!(c.parse("", "/"), Ok(Line::Empty));
        assert_eq!(c.parse("  ", "/"), Ok(Line::Empty));
        assert_eq!(c.parse("help", "/"), Ok(Line::Help(None)));
        assert_eq!(
            c.parse("help sort", "/"),
            Ok(Line::Help(Some("sort".into())))
        );
        assert_eq!(c.parse("pwd", "/"), Ok(Line::Pwd));
        assert_eq!(c.parse("exit", "/"), Ok(Line::Exit));
        assert_eq!(c.parse("cd", "/"), Ok(Line::Cd(Cd::Home)));
        assert_eq!(c.parse("cd -", "/"), Ok(Line::Cd(Cd::Back)));
        assert_eq!(
            c.parse("cd 'my dir'", "/"),
            Ok(Line::Cd(Cd::Dir("my dir".into())))
        );
        assert_eq!(
            c.parse("cd /var/log", "/"),
            Ok(Line::Cd(Cd::Dir("/var/log".into())))
        );
        assert_eq!(c.parse("pwd x", "/"), Err(Refusal::Usage("pwd")));
        assert_eq!(c.parse("cd a b", "/"), Err(Refusal::Usage("cd [DIR]")));
        // Quotes in the middle of a word are not a directory name.
        assert!(c.parse("cd a'b'", "/").is_err());
    }

    #[test]
    fn a_command_runs_as_its_set_says() {
        let c = Commands::new(vec![ops()]);
        let ok = run(&c, "systemctl status nginx", "/");
        assert_eq!(ok.command_line, "/usr/bin/systemctl status nginx");
        assert!(!ok.pty && !ok.stdin);
        assert_eq!(
            run(&c, "systemctl status", "/").command_line,
            "/usr/bin/systemctl status"
        );
        let htop = run(&c, "htop", "/");
        assert!(htop.pty && htop.stdin);
        match c.parse("sort -n", "/") {
            Ok(Line::Run { alias, set, .. }) => {
                assert_eq!((alias.as_str(), set.as_str()), ("sort", "ops"))
            }
            other => panic!("{other:?}"),
        }
    }

    /// Every way to reach the target's shell through a line is refused before
    /// anything is sent.
    #[test]
    fn shell_syntax_never_reaches_the_target() {
        let c = Commands::new(vec![ops()]);
        for line in [
            "systemctl status nginx; sh",
            "systemctl status nginx && sh",
            "systemctl status nginx | sh",
            "systemctl status $(sh)",
            "systemctl status `sh`",
            "systemctl status nginx > /etc/passwd",
            "systemctl stop nginx",
            "cat /etc/shadow; id",
            "cat '/etc/$(id)'",
            "cat /etc/*",
            "sh",
            "/bin/sh",
            "htop -d 1",
            "sort -n -n",
            "systemctl status 'nginx",
        ] {
            assert!(c.parse(line, "/").is_err(), "{line}");
        }
    }

    #[test]
    fn relative_paths_resolve_against_the_working_directory() {
        let c = Commands::new(vec![ops()]);
        assert_eq!(
            run(&c, "cat syslog", "/var/log").command_line,
            "/usr/bin/cat syslog"
        );
        assert_eq!(Commands::resolve("/var/log", "nginx/.."), "/var/log");
        assert_eq!(Commands::resolve("/var/log", "../../etc"), "/etc");
        assert_eq!(Commands::resolve("/var/log", "/tmp"), "/tmp");
    }

    #[test]
    fn cd_goes_home_and_where_the_sets_allow() {
        let base = set("base", json!({ "commands": [], "cd": ["/srv/app"] }));
        let c = Commands::new(vec![ops(), base]);
        assert!(c.cd_allows("/home/u", "/home/u"));
        assert!(c.cd_allows("/var/log/nginx", "/home/u"));
        assert!(c.cd_allows("/srv/app", "/home/u"));
        assert!(!c.cd_allows("/srv/app/x", "/home/u"));
        assert!(!c.cd_allows("/etc", "/home/u"));
        let none = Commands::new(vec![set("x", json!({ "commands": [] }))]);
        assert!(!none.cd_allows("/tmp", "/home/u"));
        assert!(none.cd_allows("/home/u", "/home/u"));
    }

    #[test]
    fn tilde_names_the_home_directory() {
        // Textual, as a shell reads it: `..` is left for the target.
        assert_eq!(expand_tilde("~", "/home/u"), "/home/u");
        assert_eq!(expand_tilde("~/log/..", "/home/u"), "/home/u/log/..");
        assert_eq!(expand_tilde("~root", "/home/u"), "~root");
        assert_eq!(expand_tilde("a~/b", "/home/u"), "a~/b");
        // The lexical form of what was typed is what the allowlist reads.
        let named = expand_tilde("~/log/..", "/home/u");
        assert_eq!(Commands::resolve("/var", &named), "/home/u");
        // And it goes through the same checks: home is always allowed, and
        // anything else still needs a pattern.
        let c = Commands::new(vec![ops()]);
        assert!(c.cd_allows(&expand_tilde("~", "/home/u"), "/home/u"));
        assert!(!c.cd_allows(&expand_tilde("~/etc", "/home/u"), "/home/u"));
    }

    /// An alias two sets define runs nowhere, and is left out of help and
    /// completion. The rest of both sets still runs.
    #[test]
    fn an_alias_from_two_sets_runs_nowhere() {
        let other = set(
            "other",
            json!({ "commands": [
                { "alias": "sort", "exec": "/opt/sort {{args}}", "argsList": [""] },
                { "alias": "df", "exec": "/usr/bin/df -h" },
            ] }),
        );
        let c = Commands::new(vec![ops(), other]);
        assert_eq!(c.parse("sort", "/"), Err(Refusal::Duplicate("sort".into())));
        assert_eq!(
            c.duplicates().get("sort").map(Vec::as_slice),
            Some(&["ops".to_string(), "other".to_string()][..])
        );
        assert_eq!(run(&c, "df", "/").command_line, "/usr/bin/df -h");
        assert_eq!(run(&c, "htop", "/").command_line, "/usr/bin/htop");
        assert!(!c.completions().contains(&"sort".to_string()));
        assert!(!c.help(tr()).iter().any(|l| l.contains("sort")));
        assert_eq!(c.help_for("sort", tr()), None);
    }

    #[test]
    fn help_for_a_command_follows_its_config() {
        let c = Commands::new(vec![ops()]);
        assert_eq!(
            c.help_for("sort", tr()).unwrap().join("\n"),
            "sort\n\nsort lines of text files\n\nUSAGE:\n  sort\n\nOPTIONS:\n  -h, -n, -i, -rn"
        );
        assert_eq!(
            c.help_for("systemctl", tr()).unwrap().join("\n"),
            "systemctl\n\nControl the systemd system and service manager\n\nUSAGE:\n  \
             systemctl start NAME\n  systemctl status [NAME]"
        );
        assert_eq!(
            c.help_for("htop", tr()).unwrap().join("\n"),
            "htop\n\nUSAGE:\n  htop"
        );
        assert_eq!(c.help_for("cd", tr()).unwrap(), ["cd [DIR]"]);
        assert_eq!(c.help_for("rm", tr()), None);
    }

    /// Help names aliases only: nothing of `exec` or hidden text shows.
    #[test]
    fn help_never_shows_exec() {
        let hidden = set(
            "deploy",
            json!({ "commands": [
                { "alias": "deploy", "exec": "/usr/bin/ansible-playbook {{args}}",
                  "argsList": ["{{{/opt/playbooks/}}}{{name:PLAYBOOK}}"], "description": "Run a playbook" },
            ] }),
        );
        let c = Commands::new(vec![hidden]);
        let text = [c.help(tr()), c.help_for("deploy", tr()).unwrap()]
            .concat()
            .join("\n");
        assert!(text.contains("deploy PLAYBOOK"), "{text}");
        assert!(
            !text.contains("ansible") && !text.contains("/opt/"),
            "{text}"
        );
    }

    #[test]
    fn help_lists_commands_builtins_and_cd() {
        let text = Commands::new(vec![ops()]).help(tr()).join("\n");
        for want in [
            "Commands:",
            "  sort            sort lines of text files",
            "  cat",
            "Built-in:",
            "  help [COMMAND]  List the commands",
            "cd may enter:",
            "  your home directory",
            "  /var/log(/.*)?",
        ] {
            assert!(text.contains(want), "{want:?} not in\n{text}");
        }
    }

    #[test]
    fn refusals_say_why_without_exec() {
        let c = Commands::new(vec![ops()]);
        let msg = |line: &str| c.parse(line, "/").unwrap_err().message(tr());
        assert_eq!(
            msg("rm -rf /"),
            "rm: command not found; type help to list commands"
        );
        assert_eq!(
            msg("systemctl stop x"),
            "systemctl: arguments not allowed; see help systemctl"
        );
        assert_eq!(msg("cat 'x"), "Refused: unbalanced quote");
        assert_eq!(
            c.parse("rm", "/").unwrap_err().reason(),
            DenyReason::UnknownCommand
        );
    }

    /// What `sh_quote` makes, `sh` reads back as the same one word.
    #[test]
    fn sh_quote_is_one_word_for_sh() {
        for s in [
            "/home/u", "a b", "it's", "'", "$(id)", "`id`", "a\nb", "\\", "--", "*", "~",
        ] {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf %s {}", sh_quote(s)))
                .output()
                .expect("run sh");
            assert_eq!(String::from_utf8(out.stdout).unwrap(), s, "{s:?}");
        }
    }
}
