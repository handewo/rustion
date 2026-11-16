//! Splits a user's input line into words.

use logos::Logos;

use super::LexError;

#[derive(Logos, Debug, PartialEq)]
#[logos(skip r"[ \t\r\n]+")]
enum Raw {
    /// Unquoted runs and quoted strings glued together, like a shell word:
    /// `foo`, `'a b'`, `/etc/'x y'`. Quotes are kept so `{{text}}` can see them.
    #[regex(r#"([^ \t\r\n'"]|'[^']*'|"[^"]*")+"#)]
    Word,
}

/// Splits `line` on whitespace, keeping quoted strings (and their quotes) intact.
pub fn split_words(line: &str) -> Result<Vec<&str>, LexError> {
    let mut lexer = Raw::lexer(line);
    let mut words = Vec::new();
    while let Some(token) = lexer.next() {
        match token {
            Ok(Raw::Word) => words.push(lexer.slice()),
            Err(()) => {
                return Err(LexError {
                    offset: lexer.span().start,
                });
            }
        }
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_quoted_spaces() {
        assert_eq!(
            split_words(r#"  grep   "default 0 0"  /etc/'a b'c "#).unwrap(),
            [r#"grep"#, r#""default 0 0""#, "/etc/'a b'c"]
        );
    }

    #[test]
    fn rejects_unbalanced_quotes() {
        assert!(split_words(r#"echo hello world!""#).is_err());
        assert!(split_words("echo 'hello world!").is_err());
    }
}
