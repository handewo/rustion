//! Parsing and matching of argument templates.
//!
//! Template grammar:
//!
//! ```text
//! template    := word (SPACE word)*
//! word        := (literal | hidden | placeholder)+
//! hidden      := "{{{" text "}}}"          emitted to the command, never typed by the user
//! placeholder := "{{" type [":" description [":" mode]] "}}"
//! mode        := "o" | "m" | "om" | "mo"   optional / repeated
//! ```
//!
//! Spaces inside a quoted literal (`'+%Y%m%d %H:%M:%S'`) don't split words, which
//! mirrors how the user's line is split.

use std::borrow::Cow;

use logos::{Lexer, Logos};

use super::{
    TemplateError, TemplateErrorKind,
    kind::{Kind, Registry},
};

#[derive(Logos, Debug)]
enum Piece<'s> {
    #[token("{{{", |lex| closed_by(lex, "}}}"))]
    Hidden(&'s str),
    #[token("{{", |lex| closed_by(lex, "}}"))]
    Placeholder(&'s str),
    #[regex(r"[ \t]+", |lex| lex.slice())]
    Space(&'s str),
    #[regex(r"[^{ \t]+", |lex| lex.slice())]
    #[token("{", |lex| lex.slice())]
    Text(&'s str),
}

/// Consumes up to and including `delim`, returning the text in between.
fn closed_by<'s>(lex: &mut Lexer<'s, Piece<'s>>, delim: &str) -> Option<&'s str> {
    let rest = lex.remainder();
    let end = rest.find(delim)?;
    lex.bump(end + delim.len());
    Some(&rest[..end])
}

#[derive(Debug, Clone)]
struct Slot {
    kind: Kind,
    optional: bool,
    repeated: bool,
    /// What help shows for it: the description, or the type name in capitals.
    label: String,
}

impl Slot {
    /// `NAME`, `[NAME]`, `NAME...` or `[NAME...]`.
    fn usage(&self) -> String {
        let repeated = if self.repeated { "..." } else { "" };
        if self.optional {
            format!("[{}{repeated}]", self.label)
        } else {
            format!("{}{repeated}", self.label)
        }
    }
}

#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Hidden(String),
    Slot(Slot),
}

#[derive(Debug, Clone)]
enum Word {
    /// Only hidden text: consumes no input.
    Hidden(String),
    /// Literals, hidden text and plain inline placeholders sharing one input word.
    Mixed(Vec<Segment>),
    /// A lone placeholder; the only place `o`/`m` modes are allowed.
    Slot(Slot),
}

#[derive(Debug, Clone)]
pub struct Template {
    source: String,
    words: Vec<Word>,
}

impl Template {
    pub fn parse(source: &str, registry: &Registry) -> Result<Self, TemplateError> {
        Self::parse_words(source, registry)
            .map(|words| Self {
                source: source.to_owned(),
                words,
            })
            .map_err(|kind| TemplateError {
                template: source.to_owned(),
                kind,
            })
    }

    fn parse_words(source: &str, registry: &Registry) -> Result<Vec<Word>, TemplateErrorKind> {
        let mut words = Vec::new();
        let mut segments = Vec::new();
        let mut quote = None;
        let mut lexer = Piece::lexer(source);
        while let Some(piece) = lexer.next() {
            let piece =
                piece.map_err(|()| TemplateErrorKind::UnclosedBrace(lexer.slice().to_owned()))?;
            match piece {
                Piece::Space(_) if quote.is_none() => {
                    push_word(&mut words, std::mem::take(&mut segments))?;
                }
                Piece::Space(s) => push_literal(&mut segments, s),
                Piece::Text(s) => {
                    for c in s.chars() {
                        quote = match quote {
                            Some(q) if q == c => None,
                            None if c == '\'' || c == '"' => Some(c),
                            q => q,
                        };
                    }
                    push_literal(&mut segments, s);
                }
                Piece::Hidden(s) => segments.push(Segment::Hidden(s.to_owned())),
                Piece::Placeholder(spec) => {
                    segments.push(Segment::Slot(parse_slot(spec, registry)?));
                }
            }
        }
        if let Some(q) = quote {
            return Err(TemplateErrorKind::UnclosedQuote(q));
        }
        push_word(&mut words, segments)?;
        Ok(words)
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// The template as help shows it: literals as written, each placeholder by
    /// its label, hidden text left out.
    pub fn usage(&self) -> String {
        let words: Vec<String> = self
            .words
            .iter()
            .filter_map(|word| match word {
                Word::Hidden(_) => None,
                Word::Slot(slot) => Some(slot.usage()),
                Word::Mixed(segments) => Some(
                    segments
                        .iter()
                        .map(|seg| match seg {
                            Segment::Literal(lit) => lit.clone(),
                            Segment::Hidden(_) => String::new(),
                            Segment::Slot(slot) => slot.usage(),
                        })
                        .collect(),
                ),
            })
            .filter(|w: &String| !w.is_empty())
            .collect();
        words.join(" ")
    }

    /// Matches the user's words, returning the arguments to execute.
    ///
    /// Options may appear before any input-consuming word and at the end, each at
    /// most once. Every placeholder is greedy and possessive: once it takes a word
    /// it keeps it.
    pub(crate) fn match_words<'a>(
        &'a self,
        input: &[&'a str],
        options: &[String],
        pwd: &str,
    ) -> Option<String> {
        let mut out: Vec<Cow<'a, str>> = Vec::new();
        let mut used = Vec::new();
        let mut rest = input;
        for word in &self.words {
            match word {
                Word::Hidden(text) => out.push(Cow::Borrowed(text)),
                Word::Mixed(segments) => {
                    take_options(&mut rest, options, &mut used, &mut out)?;
                    let (first, tail) = rest.split_first()?;
                    out.push(Cow::Owned(match_mixed(segments, first)?));
                    rest = tail;
                }
                Word::Slot(slot) => {
                    take_options(&mut rest, options, &mut used, &mut out)?;
                    let mut taken = 0;
                    while (taken == 0 || slot.repeated)
                        && let [first, tail @ ..] = rest
                        && slot.kind.matches(first, pwd)
                    {
                        out.push(Cow::Borrowed(first));
                        rest = tail;
                        taken += 1;
                    }
                    if taken == 0 && !slot.optional {
                        return None;
                    }
                }
            }
        }
        take_options(&mut rest, options, &mut used, &mut out)?;
        rest.is_empty().then(|| out.join(" "))
    }
}

fn push_literal(segments: &mut Vec<Segment>, s: &str) {
    match segments.last_mut() {
        Some(Segment::Literal(lit)) => lit.push_str(s),
        _ => segments.push(Segment::Literal(s.to_owned())),
    }
}

fn push_word(words: &mut Vec<Word>, mut segments: Vec<Segment>) -> Result<(), TemplateErrorKind> {
    let word = match segments.as_slice() {
        [] => return Ok(()),
        [Segment::Slot(_)] => match segments.pop() {
            Some(Segment::Slot(slot)) => Word::Slot(slot),
            _ => unreachable!(),
        },
        segs if segs.iter().all(|s| matches!(s, Segment::Hidden(_))) => Word::Hidden(
            segs.iter()
                .filter_map(|s| match s {
                    Segment::Hidden(h) => Some(h.as_str()),
                    _ => None,
                })
                .collect(),
        ),
        segs => {
            for seg in segs {
                if let Segment::Slot(slot) = seg {
                    let name = || slot.kind.name().to_owned();
                    if slot.kind.is_inline() {
                        return Err(TemplateErrorKind::NotInline(name()));
                    }
                    if slot.optional || slot.repeated {
                        return Err(TemplateErrorKind::ModeNotInline(name()));
                    }
                }
            }
            Word::Mixed(segments)
        }
    };
    words.push(word);
    Ok(())
}

/// Parses `type[:description[:mode]]`. The description is a tip for humans, may contain
/// spaces, and is only used by help.
fn parse_slot(spec: &str, registry: &Registry) -> Result<Slot, TemplateErrorKind> {
    let mut parts = spec.split(':');
    let type_name = parts.next().unwrap_or_default();
    let description = parts.next().unwrap_or_default();
    let mode = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err(TemplateErrorKind::TooManyFields(spec.to_owned()));
    }
    if type_name.is_empty() {
        return Err(TemplateErrorKind::EmptyType(spec.to_owned()));
    }
    if type_name.contains(char::is_whitespace) || mode.contains(char::is_whitespace) {
        return Err(TemplateErrorKind::Whitespace(spec.to_owned()));
    }
    let (optional, repeated) = match mode {
        "" => (false, false),
        "o" => (true, false),
        "m" => (false, true),
        "om" | "mo" => (true, true),
        other => {
            return Err(TemplateErrorKind::UnknownMode {
                spec: spec.to_owned(),
                mode: other.to_owned(),
            });
        }
    };
    let kind = Kind::resolve(type_name, registry)
        .ok_or_else(|| TemplateErrorKind::UnknownType(type_name.to_owned()))?;
    let label = if description.is_empty() {
        type_name.to_uppercase()
    } else {
        description.to_owned()
    };
    Ok(Slot {
        kind,
        optional,
        repeated,
        label,
    })
}

/// Consumes leading option words. Fails if an option repeats one already used.
fn take_options<'a>(
    rest: &mut &[&'a str],
    options: &[String],
    used: &mut Vec<&'a str>,
    out: &mut Vec<Cow<'a, str>>,
) -> Option<()> {
    while let [first, tail @ ..] = *rest
        && options.iter().any(|o| o == first)
    {
        if used.contains(first) {
            return None;
        }
        used.push(first);
        out.push(Cow::Borrowed(first));
        *rest = tail;
    }
    Some(())
}

fn match_mixed(segments: &[Segment], word: &str) -> Option<String> {
    let mut rest = word;
    let mut out = String::new();
    for segment in segments {
        match segment {
            Segment::Literal(lit) => {
                rest = rest.strip_prefix(lit.as_str())?;
                out.push_str(lit);
            }
            Segment::Hidden(text) => out.push_str(text),
            Segment::Slot(slot) => {
                let n = slot.kind.prefix_len(rest)?;
                out.push_str(&rest[..n]);
                rest = &rest[n..];
            }
        }
    }
    rest.is_empty().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Result<Template, TemplateError> {
        Template::parse(src, &Registry::default())
    }

    #[test]
    fn rejects_bad_templates() {
        use TemplateErrorKind as K;
        let s = String::from;
        let cases = [
            ("{{na me}}", K::Whitespace(s("na me"))),
            ("{{name:tip:o m}}", K::Whitespace(s("name:tip:o m"))),
            ("{{name:a:o:x}}", K::TooManyFields(s("name:a:o:x"))),
            ("foo{{anypath}}", K::NotInline(s("anypath"))),
            ("{{any}}x", K::NotInline(s("any"))),
            ("/etc/{{text::o}}", K::ModeNotInline(s("text"))),
            ("{{{x}}}{{port::om}}", K::ModeNotInline(s("port"))),
            ("{{datetime::o}}-00:00", K::ModeNotInline(s("datetime"))),
            ("{{nope}}", K::UnknownType(s("nope"))),
            ("{{:A:}}", K::EmptyType(s(":A:"))),
            ("{{}}", K::EmptyType(s(""))),
            (
                "{{name::x}}",
                K::UnknownMode {
                    spec: s("name::x"),
                    mode: s("x"),
                },
            ),
            ("{{name", K::UnclosedBrace(s("{{"))),
            ("'unclosed", K::UnclosedQuote('\'')),
        ];
        for (src, kind) in cases {
            let err = parse(src).unwrap_err();
            assert_eq!(err.kind, kind, "{src}");
            assert_eq!(err.template, src);
        }
    }

    #[test]
    fn text_inside_a_path() {
        let t = parse("/etc/{{text:MSG}}.conf").unwrap();
        let check = |word: &str| t.match_words(&[word], &[], "/");
        assert_eq!(
            check("/etc/'a b c'.conf").as_deref(),
            Some("/etc/'a b c'.conf")
        );
        assert_eq!(
            check(r#"/etc/"my file".conf"#).as_deref(),
            Some(r#"/etc/"my file".conf"#)
        );
        for bad in [
            "/etc/'../root/.ssh/id_rsa'.conf", // traversal
            "/etc/'..'.conf",
            "/etc/'.'.conf",
            "/etc/'a/b'.conf",
            "/etc/'-rf'.conf",      // option-looking content
            r#"/etc/"$HOME".conf"#, // expansion
            "/etc/'$(id)'.conf",
            "/etc/''.conf",     // empty
            "/etc/'a''b'.conf", // second string glued on
            "/etc/'a b'",       // missing `.conf`
            "/etc/a b.conf",    // unquoted
        ] {
            assert_eq!(check(bad), None, "{bad}");
        }
        // `..` as a substring of a name is fine, only a whole `..` component escapes.
        assert!(check("/etc/'a..b'.conf").is_some());
    }

    #[test]
    fn description_may_contain_spaces() {
        let t = parse("-s {{name:login name of the user:o}} -k").unwrap();
        assert_eq!(t.words.len(), 3);
        assert!(matches!(&t.words[1], Word::Slot(s) if s.optional));
    }

    #[test]
    fn quoted_literal_is_one_word() {
        let t = parse("'+%Y%m%d %H:%M:%S'").unwrap();
        assert_eq!(t.words.len(), 1);
    }
}
