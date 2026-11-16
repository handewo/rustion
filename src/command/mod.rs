//! Argument whitelisting for the limited shell's commands.
//!
//! Vendored from `command_demo`, with its config read as JSON, the
//! `description`, `pty`, `stdin` and `cd` fields, and help lines built from the
//! templates.
//!
//! An admin describes the allowed argument shapes of a command with templates such as
//! `-s /sbin/nologin {{name:LOGIN}}`. A user's input line is accepted only when it
//! matches one of them.
//!
//! The pipeline has three small stages instead of one big regex-driven loop:
//!
//! 1. [`lex::split_words`] splits the user's line into shell-like words (quotes kept).
//! 2. [`Template::parse`] turns each template into a list of [`template::Word`]s.
//! 3. The matcher walks templates and words in lockstep, PEG style: every placeholder
//!    is greedy and never gives input back, and the first template that matches wins.

pub mod error;
pub mod kind;
pub mod lex;
pub mod policy;
pub mod template;
#[cfg(test)]
mod test;

pub use error::{
    ConfigError, ExecError, LexError, RegistryError, Rejection, TemplateError, TemplateErrorKind,
};
pub use kind::Registry;
pub use policy::{Approved, Policy};
pub use template::Template;

/// The allowed argument shapes of one command.
#[derive(Debug, Clone)]
pub struct Command {
    templates: Vec<Template>,
    options: Vec<String>,
}

/// A successful match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<'c> {
    /// Arguments to execute: user words plus hidden `{{{...}}}` text, single-space joined.
    pub args: String,
    /// The template that matched.
    pub template: &'c str,
}

impl Command {
    /// Compiles every template up front, so a bad config fails at load time
    /// instead of silently rejecting users at run time.
    pub fn new<S: AsRef<str>>(
        args_list: &[S],
        options: &[S],
        registry: &Registry,
    ) -> Result<Self, TemplateError> {
        let templates = args_list
            .iter()
            .map(|src| Template::parse(src.as_ref(), registry))
            .collect::<Result<_, _>>()?;
        let options = options.iter().map(|o| o.as_ref().to_owned()).collect();
        Ok(Self { templates, options })
    }

    /// One help line per template, each starting with `alias`. A command with
    /// no templates takes no arguments, so its one line is the bare alias.
    pub fn usage(&self, alias: &str) -> Vec<String> {
        if self.templates.is_empty() {
            return vec![alias.to_owned()];
        }
        self.templates
            .iter()
            .map(|t| match t.usage() {
                u if u.is_empty() => alias.to_owned(),
                u => format!("{alias} {u}"),
            })
            .collect()
    }

    pub fn options(&self) -> &[String] {
        &self.options
    }

    /// Checks the user's arguments (the words after the command name).
    ///
    /// `pwd` is the user's working directory, used to resolve relative paths.
    pub fn verify(&self, args: &[&str], pwd: &str) -> Option<Verified<'_>> {
        // No templates at all means "no arguments, not even options".
        if self.templates.is_empty() {
            return args.is_empty().then(|| Verified {
                args: String::new(),
                template: "",
            });
        }
        self.templates.iter().find_map(|t| {
            t.match_words(args, &self.options, pwd)
                .map(|args| Verified {
                    args,
                    template: t.source(),
                })
        })
    }
}
