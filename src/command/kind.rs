//! Placeholder types (`{{name}}`, `{{port}}`, ...) and how each one recognizes input.
//!
//! Built-in types are plain functions, not regexes. Only admin-supplied types
//! (`path` whitelists and custom types) use the `regex` crate, because the
//! config format defines them as regexes.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::RegistryError;

const BUILTIN: &[&str] = &[
    "text", "path", "any", "anypath", "ipv4", "name", "alpha", "digit", "port", "number",
    "datetime",
];

/// Admin-defined types: path whitelists and custom regex types.
#[derive(Debug, Clone)]
pub struct Registry {
    paths: RegexSet,
    custom: HashMap<String, Custom>,
}

#[derive(Debug, Clone)]
pub struct Custom {
    name: String,
    /// `^(?:re)`, used when the placeholder sits inside a larger word.
    prefix: Regex,
    /// `^(?:re)$`, used when the placeholder is the whole word.
    full: Regex,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            paths: RegexSet::empty(),
            custom: HashMap::new(),
        }
    }
}

impl Registry {
    /// `paths` are the regexes `{{path}}` accepts; `custom` maps a type name to its regex.
    /// Every regex is anchored on both ends.
    pub fn new<'a>(
        paths: impl IntoIterator<Item = &'a str>,
        custom: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, RegistryError> {
        let paths = RegexSet::new(paths.into_iter().map(|p| format!("^(?:{p})$")))
            .map_err(RegistryError::PathRegex)?;
        let mut types = HashMap::new();
        for (name, pattern) in custom {
            let well_formed = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c));
            if !well_formed {
                return Err(RegistryError::InvalidName(name.to_owned()));
            }
            if BUILTIN.contains(&name) {
                return Err(RegistryError::ShadowsBuiltin(name.to_owned()));
            }
            let compile = |re: String| {
                Regex::new(&re).map_err(|source| RegistryError::CustomRegex {
                    name: name.to_owned(),
                    source,
                })
            };
            let custom = Custom {
                name: name.to_owned(),
                prefix: compile(format!("^(?:{pattern})"))?,
                full: compile(format!("^(?:{pattern})$"))?,
            };
            types.insert(name.to_owned(), custom);
        }
        Ok(Self {
            paths,
            custom: types,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Kind {
    Ipv4,
    Port,
    Name,
    Alpha,
    Digit,
    Number,
    Datetime,
    /// A single- or double-quoted string.
    Text,
    Any,
    /// A path matching one of the admin's path regexes.
    Path(RegexSet),
    /// Any well-formed absolute path.
    AnyPath,
    Custom(Custom),
}

/// Longest value an inline placeholder may take inside a larger word.
const MAX_INLINE_LEN: usize = 255;

type CharClass = fn(char) -> bool;
type Validator = fn(&str) -> bool;

impl Kind {
    pub fn resolve(name: &str, registry: &Registry) -> Option<Self> {
        Some(match name {
            "ipv4" => Self::Ipv4,
            "port" => Self::Port,
            "name" => Self::Name,
            "alpha" => Self::Alpha,
            "digit" => Self::Digit,
            "number" => Self::Number,
            "datetime" => Self::Datetime,
            "text" => Self::Text,
            "any" => Self::Any,
            "path" => Self::Path(registry.paths.clone()),
            "anypath" => Self::AnyPath,
            other => Self::Custom(registry.custom.get(other)?.clone()),
        })
    }

    /// Inline types may share a word with literals, like `/opt/{{name}}/data`.
    /// The others must be the whole word.
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Any | Self::Path(_) | Self::AnyPath)
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Port => "port",
            Self::Name => "name",
            Self::Alpha => "alpha",
            Self::Digit => "digit",
            Self::Number => "number",
            Self::Datetime => "datetime",
            Self::Text => "text",
            Self::Any => "any",
            Self::Path(_) => "path",
            Self::AnyPath => "anypath",
            Self::Custom(c) => &c.name,
        }
    }

    /// Does the whole word belong to this type?
    pub fn matches(&self, word: &str, pwd: &str) -> bool {
        match self {
            Self::Text => is_text(word),
            Self::Any => is_any(word),
            // The admin regex alone can't be trusted to exclude shell syntax, and the
            // raw word (not the normalized path) is what reaches the command.
            Self::Path(allowed) => {
                !word.starts_with('-')
                    && is_shell_safe(word)
                    && allowed.is_match(&normalize(pwd, word))
            }
            Self::AnyPath => is_any_path(&normalize(pwd, word)),
            Self::Custom(c) => is_shell_safe(word) && c.full.is_match(word),
            _ => self.lexical().is_some_and(|(_, valid)| valid(word)),
        }
    }

    /// Length of the longest non-empty prefix of `s` belonging to this type.
    /// Only meaningful for inline types.
    pub fn prefix_len(&self, s: &str) -> Option<usize> {
        if let Self::Custom(c) = self {
            return c
                .prefix
                .find(s)
                .map(|m| m.end())
                .filter(|&n| n > 0 && is_shell_safe(&s[..n]));
        }
        if let Self::Text = self {
            // One quoted string. Glued to other text it names part of a path
            // (`/etc/'a b'`), so it must stay within one path component.
            let quote = s.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
            let end = s[1..].find(quote)? + 2;
            let inner = &s[1..end - 1];
            let component = !inner.contains('/') && inner != "." && inner != "..";
            return (component && is_text(&s[..end])).then_some(end);
        }
        let (class, valid) = self.lexical()?;
        let mut run = &s[..s.find(|c| !class(c)).unwrap_or(s.len())];
        // Bound the run so the longest-first scan stays cheap on hostile input.
        // All classes are ASCII, so any byte index is a char boundary.
        run = &run[..run.len().min(MAX_INLINE_LEN)];
        run.char_indices()
            .map(|(i, c)| i + c.len_utf8())
            .rev()
            .find(|&end| valid(&run[..end]))
    }

    /// Character class bounding a match, and the full validator.
    fn lexical(&self) -> Option<(CharClass, Validator)> {
        Some(match self {
            Self::Ipv4 => (|c| c.is_ascii_digit() || c == '.', is_ipv4),
            Self::Port => (|c| c.is_ascii_digit(), is_port),
            Self::Name => (is_name_char, is_name),
            Self::Alpha => (|c| c.is_ascii_alphabetic(), is_alpha),
            Self::Digit => (|c| c.is_ascii_digit(), is_digits),
            Self::Number => (|c| c.is_ascii_digit() || "+-.".contains(c), is_number),
            Self::Datetime => (is_datetime_char, is_datetime),
            _ => return None,
        })
    }
}

/// Characters an unquoted shell word can carry without any expansion or
/// special meaning: no `;|&<>()$\`'"*?[]{}~!#` and no whitespace.
fn is_shell_safe(s: &str) -> bool {
    s.chars()
        .all(|c| is_word_char(c) || "._/+=:,@%-".contains(c))
}

/// An ASCII letter or digit, or a letter or digit of any other script (`报表`).
///
/// Non-ASCII is safe for the shell: every UTF-8 byte of a non-ASCII char is at
/// least 0x80, so it can never be read as a metacharacter. `is_alphanumeric`
/// excludes invisible format chars (U+200B, U+202E) and symbols like the
/// full-width slash `／`, so a word can't look different from what it is.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric()
}

/// Invisible or direction-changing characters that would make a logged command
/// read differently from what runs: format chars (U+200B zero-width space,
/// U+202E right-to-left override, U+FEFF), private use, unassigned, and the
/// Unicode line and paragraph separators.
static INVISIBLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]").unwrap());

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_alpha(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._=+-".contains(c)
}

/// At least two characters, starting with a letter or digit.
fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() >= 2
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(is_name_char)
}

/// `[+-]digits[.digits]`
fn is_number(s: &str) -> bool {
    let s = s.strip_prefix(['+', '-']).unwrap_or(s);
    match s.split_once('.') {
        Some((int, frac)) => is_digits(int) && is_digits(frac),
        None => is_digits(s),
    }
}

fn is_datetime_char(c: char) -> bool {
    c.is_ascii_digit() || ":/-".contains(c)
}

/// Loose date/time shape like `2021-01-03` or `18:00:00`.
fn is_datetime(s: &str) -> bool {
    (6..=10).contains(&s.len()) && s.chars().all(is_datetime_char)
}

/// 1..=65535 without leading zeros.
fn is_port(s: &str) -> bool {
    is_digits(s)
        && !s.starts_with('0')
        && s.len() <= 5
        && s.parse::<u32>().is_ok_and(|p| p <= 65535)
}

/// Dotted quad without leading zeros: many tools read `010` as octal 8.
fn is_ipv4(s: &str) -> bool {
    s.len() <= 15
        && s.split('.').count() == 4
        && s.split('.').all(|o| {
            is_digits(o)
                && o.len() <= 3
                && (o == "0" || !o.starts_with('0'))
                && o.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// One quoted string with nothing glued to it, safe to hand to a shell.
///
/// Inside double quotes the shell still expands `$` and `` ` `` and honours `\`
/// (`"a\"` would leave the string open), so all three are rejected there.
/// A leading `-` is rejected because the target command would read it as an
/// option once the shell strips the quotes (`tar '--checkpoint-action=exec=sh'`).
fn is_text(s: &str) -> bool {
    let Some(quote) = s.chars().next().filter(|c| matches!(c, '\'' | '"')) else {
        return false;
    };
    if s.len() < 3 || !s.ends_with(quote) {
        return false;
    }
    let inner = &s[1..s.len() - 1];
    if inner.contains(quote)
        || inner.starts_with('-')
        || inner.contains("$(")
        || inner.contains('`')
        || inner.chars().any(char::is_control)
        || INVISIBLE.is_match(inner)
    {
        return false;
    }
    quote == '\'' || !inner.contains(['$', '\\'])
}

fn is_any(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || ".:_/-".contains(c))
}

/// Every segment of a normalized absolute path is `[W._][W.:_-]*`, where `W` is a
/// letter or digit of any script (see [`is_word_char`]).
fn is_any_path(path: &str) -> bool {
    path == "/"
        || path[1..].split('/').all(|seg| {
            let mut chars = seg.chars();
            chars
                .next()
                .is_some_and(|c| is_word_char(c) || "._".contains(c))
                && chars.all(|c| is_word_char(c) || ".:_-".contains(c))
        })
}

/// Resolves `word` against `pwd` and removes `.`, `..` and empty segments, so a
/// whitelist like `/etc/fstab` can't be bypassed with `/etc/fstab/../shadow`.
pub fn normalize(pwd: &str, word: &str) -> String {
    let joined = if word.starts_with('/') {
        word.to_owned()
    } else {
        format!("{pwd}/{word}")
    };
    let mut parts = Vec::new();
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            seg => parts.push(seg),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_longest_valid() {
        assert_eq!(Kind::Ipv4.prefix_len("192.168.255.455:3333"), Some(14));
        assert_eq!(Kind::Port.prefix_len("83333"), Some(4));
        assert_eq!(Kind::Name.prefix_len("etc/fstab"), Some(3));
        assert_eq!(Kind::Number.prefix_len("1.5.3"), Some(3));
        assert_eq!(Kind::Name.prefix_len("1/foo"), None);
    }

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize("/etc", "fstab"), "/etc/fstab");
        assert_eq!(normalize("/etc", "/etc/fstab/../shadow"), "/etc/shadow");
        assert_eq!(normalize("/etc", "../../.."), "/");
    }

    #[test]
    fn text_is_shell_safe() {
        assert!(is_text("'$HOME \\ ok'"));
        assert!(is_text(r#""plain words""#));
        for bad in [
            r#""$HOME""#,
            r#""${x}""#,
            r#""a\""#,
            "'$(id)'",
            "'`id`'",
            "''",
            "'a\nb'",
            "'\x1b[2J'",
            "'-rf'",
            "'--checkpoint-action=exec=sh'",
        ] {
            assert!(!is_text(bad), "{bad}");
        }
    }

    #[test]
    fn loose_admin_regexes_stay_shell_safe() {
        let reg = Registry::new(["/var/log/.+"], [("host", ".+")]).unwrap();
        let path = Kind::resolve("path", &reg).unwrap();
        let host = Kind::resolve("host", &reg).unwrap();
        assert!(path.matches("/var/log/messages", "/"));
        for bad in [
            "/var/log/x;id",
            "/var/log/$(id)",
            "/var/log/`id`",
            "/var/log/*",
        ] {
            assert!(!path.matches(bad, "/"), "{bad}");
        }
        // Relative words are checked as /var/log/<word>, but reach the command raw.
        assert!(!path.matches("-rf", "/var/log"));
        assert!(!path.matches("~root", "/var/log"));
        assert!(!host.matches("a;id", "/"));
        assert_eq!(host.prefix_len("a|b"), None);
    }

    #[test]
    fn ipv4_rejects_octal_looking_octets() {
        assert!(is_ipv4("10.0.0.1"));
        assert!(!is_ipv4("010.0.0.1"));
        assert!(!is_ipv4("10.00.0.1"));
    }

    #[test]
    fn unicode_paths() {
        assert!(Kind::AnyPath.matches("/data/报表/2026年.csv", "/"));
        assert!(Kind::AnyPath.matches("文档", "/home/张三"));
        assert!(Kind::AnyPath.matches("/srv/café", "/"));
        for bad in [
            "/data/\u{202E}vsc.exe", // right-to-left override
            "/data/a\u{200B}b",      // zero-width space
            "/data/\u{FEFF}x",       // BOM
            "/data/a／..／b",        // full-width slash is a symbol, not a separator
            "/data/a\u{3000}b",      // ideographic space
            "/data/\u{E000}",        // private use
        ] {
            assert!(!Kind::AnyPath.matches(bad, "/"), "{bad:?}");
        }

        let reg = Registry::new(["/data/.+"], []).unwrap();
        let path = Kind::resolve("path", &reg).unwrap();
        assert!(path.matches("/data/报表.csv", "/"));
        assert!(!path.matches("/data/报表\u{202E}.csv", "/"));
    }

    #[test]
    fn text_rejects_invisible_chars() {
        assert!(is_text("'中文 文件'"));
        assert!(is_text("'全角　空格'")); // U+3000 is visible spacing inside quotes
        for bad in ["'a\u{202E}b'", "'a\u{200B}b'", "'\u{2028}'", "'\u{FEFF}x'"] {
            assert!(!is_text(bad), "{bad:?}");
        }
    }

    #[test]
    fn path_whitelist_is_anchored() {
        let reg = Registry::new(["/etc/(fstab|passwd)"], []).unwrap();
        let path = Kind::resolve("path", &reg).unwrap();
        assert!(path.matches("fstab", "/etc"));
        assert!(!path.matches("/etc/fstab/../shadow", "/"));
        assert!(!path.matches("/x/etc/fstab", "/"));
        assert!(!path.matches("/etc/passwdX", "/"));
    }
}
