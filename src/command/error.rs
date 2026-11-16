//! Error types.
//!
//! Config problems ([`ConfigError`] and the errors it wraps) are found once, when
//! a command set is saved or loaded. A [`Rejection`] is the per-line verdict for
//! a user's input.

use thiserror::Error;

/// The user's line contains a quote that is never closed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unbalanced quote at byte {offset}")]
pub struct LexError {
    pub offset: usize,
}

/// A bad `argsList` entry.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("template `{template}`: {kind}")]
pub struct TemplateError {
    pub template: String,
    pub kind: TemplateErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TemplateErrorKind {
    /// `{{` or `{{{` without its closing braces.
    #[error("unclosed `{0}`")]
    UnclosedBrace(String),
    #[error("unclosed quote `{0}`")]
    UnclosedQuote(char),
    #[error("placeholder `{{{{{0}}}}}` has too many `:`")]
    TooManyFields(String),
    #[error("placeholder `{{{{{0}}}}}`: only the description may contain whitespace")]
    Whitespace(String),
    #[error("unknown mode `{mode}` in `{{{{{spec}}}}}`")]
    UnknownMode { spec: String, mode: String },
    #[error("placeholder `{{{{{0}}}}}` has no type")]
    EmptyType(String),
    #[error("unknown type `{0}`")]
    UnknownType(String),
    /// `text`, `any`, `path` and `anypath` can't share a word with other text.
    #[error("`{{{{{0}}}}}` must be a whole word")]
    NotInline(String),
    /// Optional or repeated placeholders can't share a word with other text.
    #[error("optional/repeated `{{{{{0}}}}}` must be a whole word")]
    ModeNotInline(String),
}

/// A bad `[types]` section.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid path regex: {0}")]
    PathRegex(#[source] regex::Error),
    #[error("invalid regex for custom type `{name}`: {source}")]
    CustomRegex {
        name: String,
        #[source]
        source: regex::Error,
    },
    #[error("custom type `{0}` shadows a built-in type")]
    ShadowsBuiltin(String),
    /// Names must be non-empty `[A-Za-z0-9_-]`, so they can be written as `{{name}}`.
    #[error("invalid custom type name `{0}`")]
    InvalidName(String),
}

/// A bad `exec` string.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecError {
    #[error("`{{{{args}}}}` appears in different quoting contexts")]
    MixedQuoting,
    #[error("unbalanced quote or trailing `\\`")]
    Unbalanced,
}

/// Anything wrong with a command set's config.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid `cd` regex: {0}")]
    CdRegex(#[source] regex::Error),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error("command `{alias}`: {source}")]
    Template {
        alias: String,
        #[source]
        source: TemplateError,
    },
    #[error("command `{alias}`: exec: {source}")]
    Exec {
        alias: String,
        #[source]
        source: ExecError,
    },
    #[error("duplicate alias `{0}`")]
    DuplicateAlias(String),
    /// `help`, `cd`, `pwd` and `exit` belong to the limited shell.
    #[error("alias `{0}` is reserved")]
    ReservedAlias(String),
    /// Aliases are `[A-Za-z0-9._+-]`, not starting with `-`.
    #[error("invalid alias `{0}`")]
    InvalidAlias(String),
}

/// Why a user's line was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Rejection {
    #[error(transparent)]
    Lex(#[from] LexError),
    #[error("empty command")]
    Empty,
    #[error("line longer than {0} bytes")]
    TooLong(usize),
    #[error("unknown command `{0}`")]
    UnknownCommand(String),
    #[error("arguments not allowed")]
    NotAllowed,
    /// The arguments would close or expand inside a quote in `exec`.
    #[error("arguments would break the command's quoting")]
    BreaksQuoting,
}
