use nu_ansi_term::Style;

use reedline::{Completer, CompletionResult, Span, Suggestion};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::Chars,
    sync::Arc,
};

pub struct BastionCompleter {
    root: CompletionNode,
    min_word_len: usize,
}

impl Default for BastionCompleter {
    fn default() -> Self {
        let inclusions = Arc::new(BTreeSet::new());
        Self {
            root: CompletionNode::new(inclusions),
            min_word_len: 2,
        }
    }
}
impl Completer for BastionCompleter {
    /// Returns a vector of completions and the position in which they must be replaced;
    /// based on the provided input.
    ///
    /// # Arguments
    ///
    /// * `line`    The line to complete
    /// * `pos`   The cursor position
    ///
    /// # Example
    /// ```
    /// use reedline::{DefaultCompleter,Completer,Span,Suggestion};
    ///
    /// let mut completions = DefaultCompleter::default();
    /// completions.insert(vec!["batman","robin","batmobile","batcave","robber"].iter().map(|s| s.to_string()).collect());
    /// assert_eq!(
    ///     completions.complete("bat",3),
    ///     vec![
    ///         Suggestion {value: "batcave".into(), description: None, style: None, extra: None, span: Span { start: 0, end: 3 }, append_whitespace: false},
    ///         Suggestion {value: "batman".into(), description: None, style: None, extra: None, span: Span { start: 0, end: 3 }, append_whitespace: false},
    ///         Suggestion {value: "batmobile".into(), description: None, style: None, extra: None, span: Span { start: 0, end: 3 }, append_whitespace: false},
    ///     ]);
    ///
    /// assert_eq!(
    ///     completions.complete("to the\r\nbat",11),
    ///     vec![
    ///         Suggestion {value: "batcave".into(), description: None, style: None, extra: None, span: Span { start: 8, end: 11 }, append_whitespace: false},
    ///         Suggestion {value: "batman".into(), description: None, style: None, extra: None, span: Span { start: 8, end: 11 }, append_whitespace: false},
    ///         Suggestion {value: "batmobile".into(), description: None, style: None, extra: None, span: Span { start: 8, end: 11 }, append_whitespace: false},
    ///     ]);
    /// ```
    fn complete(&mut self, line: &str, pos: usize) -> CompletionResult {
        let mut span_line_whitespaces = 0;
        let mut completions = vec![];
        // Trimming in case someone passes in text containing stuff after the cursor, if
        // `only_buffer_difference` is false
        let line = if line.len() > pos { &line[..pos] } else { line };
        if !line.is_empty() {
            // When editing a multiline buffer, there can be new line characters in it.
            // Also, by replacing the new line character with a space, the insert
            // position is maintain in the line buffer.
            let line = line.replace("\r\n", "  ").replace('\n', " ");
            let split = line.split(' ').rev();
            let mut span_line: String = String::new();
            for s in split {
                if s.is_empty() {
                    span_line_whitespaces += 1;
                    continue;
                }
                if span_line.is_empty() {
                    span_line = s.to_string();
                } else {
                    span_line = format!("{s} {span_line}");
                }
                if let Some(extensions) = self.root.complete(span_line.chars()) {
                    completions.extend(
                        natural_order(&span_line, &extensions, span_line_whitespaces).map(|ext| {
                            suggestion(
                                &span_line,
                                ext,
                                Span::new(pos - span_line.len() - span_line_whitespaces, pos),
                            )
                        }),
                    );
                }
            }
        } else {
            let extensions = self.root.collect();
            completions.extend(
                natural_order("", &extensions, span_line_whitespaces)
                    .map(|ext| suggestion("", ext, Span::new(pos - span_line_whitespaces, pos))),
            );
        }
        completions.dedup();
        CompletionResult::fresh(completions)
    }
}

impl BastionCompleter {
    /// Insert `external_commands` list in the object root
    ///
    /// # Arguments
    ///
    /// * `line`    A vector of `String` containing the external commands
    ///
    /// # Example
    /// ```
    /// use reedline::{DefaultCompleter,Completer};
    ///
    /// let mut completions = DefaultCompleter::default();
    ///
    /// // Insert multiple words
    /// completions.insert(vec!["a","line","with","many","words"].iter().map(|s| s.to_string()).collect());
    ///
    /// // The above line is equal to the following:
    /// completions.insert(vec!["a","line","with"].iter().map(|s| s.to_string()).collect());
    /// completions.insert(vec!["many","words"].iter().map(|s| s.to_string()).collect());
    /// ```
    pub fn insert(&mut self, words: Vec<String>) {
        for word in words {
            if word.len() >= self.min_word_len {
                self.root.insert(word.chars());
            }
        }
    }

    /// Sets the minimum word length to complete on. Smaller words are
    /// ignored. This only affects future calls to `insert()` -
    /// changing this won't start completing on smaller words that
    /// were added in the past, nor will it exclude larger words
    /// already inserted into the completion tree.
    #[must_use]
    pub fn set_min_word_len(mut self, len: usize) -> Self {
        self.min_word_len = len;
        self
    }

    /// Create a new `DefaultCompleter` with provided non alphabet characters whitelisted.
    /// The default `DefaultCompleter` will only parse alphabet characters (a-z, A-Z). Use this to
    /// introduce additional accepted special characters.
    ///
    /// # Arguments
    ///
    /// * `incl`    An array slice with allowed characters
    ///
    /// # Example
    /// ```
    /// use reedline::{DefaultCompleter,Completer,Span,Suggestion};
    ///
    /// let mut completions = DefaultCompleter::default();
    /// completions.insert(vec!["test-hyphen","test_underscore"].iter().map(|s| s.to_string()).collect());
    /// assert_eq!(
    ///     completions.complete("te",2),
    ///     vec![Suggestion {value: "test".into(), description: None, style: None, extra: None, span: Span { start: 0, end: 2 }, append_whitespace: false}]);
    ///
    /// let mut completions = DefaultCompleter::with_inclusions(&['-', '_']);
    /// completions.insert(vec!["test-hyphen","test_underscore"].iter().map(|s| s.to_string()).collect());
    /// assert_eq!(
    ///     completions.complete("te",2),
    ///     vec![
    ///         Suggestion {value: "test-hyphen".into(), description: None, style: None, extra: None, span: Span { start: 0, end: 2 }, append_whitespace: false},
    ///         Suggestion {value: "test_underscore".into(), description: None, style: None, extra: None, span: Span { start: 0, end: 2 }, append_whitespace: false},
    ///     ]);
    /// ```
    pub fn with_inclusions(incl: &[char]) -> Self {
        let mut set = BTreeSet::new();
        set.extend(incl.iter());
        let inclusions = Arc::new(set);
        Self {
            root: CompletionNode::new(inclusions),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
struct CompletionNode {
    subnodes: BTreeMap<char, CompletionNode>,
    leaf: bool,
    inclusions: Arc<BTreeSet<char>>,
}

impl CompletionNode {
    fn new(incl: Arc<BTreeSet<char>>) -> Self {
        Self {
            subnodes: BTreeMap::new(),
            leaf: false,
            inclusions: incl,
        }
    }

    fn insert(&mut self, mut iter: Chars) {
        if let Some(c) = iter.next() {
            if self.inclusions.contains(&c) || c.is_alphanumeric() || c.is_whitespace() {
                let inclusions = self.inclusions.clone();
                let subnode = self
                    .subnodes
                    .entry(c)
                    .or_insert_with(|| CompletionNode::new(inclusions));
                subnode.insert(iter);
            } else {
                self.leaf = true;
            }
        } else {
            self.leaf = true;
        }
    }

    fn complete(&self, mut iter: Chars) -> Option<Vec<String>> {
        if let Some(c) = iter.next() {
            if let Some(subnode) = self.subnodes.get(&c) {
                subnode.complete(iter)
            } else {
                None
            }
        } else {
            Some(self.collect())
        }
    }

    /// Every word stored below this node, in key order.
    fn collect(&self) -> Vec<String> {
        let mut completions = vec![];
        let mut partial = String::new();
        self.collect_into(&mut partial, &mut completions);
        completions
    }

    /// Collects through one shared buffer: each level appends its character and
    /// takes it back, so a word is copied once, when it is pushed, instead of
    /// once per character on the way down.
    fn collect_into(&self, partial: &mut String, completions: &mut Vec<String>) {
        if self.leaf {
            completions.push(partial.clone());
        }
        for (c, node) in &self.subnodes {
            partial.push(*c);
            node.collect_into(partial, completions);
            partial.truncate(partial.len() - c.len_utf8());
        }
    }
}

/// The order the natural comparison gives `prefix + rest`, without building the
/// concatenation.
///
/// That comparison splits a string at its first ASCII digit and orders by the
/// alpha part before the number, so the split lands either in `prefix` or in
/// `rest`:
///
/// * `prefix` holds a digit: every key from the same `prefix` shares its alpha
///   part, kept empty here and so comparing equal, and the number reads the
///   digits from that point through the end of `rest`.
/// * it does not: the shared `prefix` cancels out of the alpha comparison and
///   the split falls to `rest` alone.
///
/// The number is what `u64::from_str` makes of the tail: the whole tail must
/// be digits and in range, and anything else parses as zero.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NaturalKey<'a> {
    alpha: &'a str,
    num: u64,
}

impl<'a> NaturalKey<'a> {
    fn new(prefix: &str, rest: &'a str) -> Self {
        if let Some(at) = prefix.find(|c: char| c.is_ascii_digit()) {
            let tail = &prefix[at..];
            let num = if tail.bytes().all(|b| b.is_ascii_digit())
                && rest.bytes().all(|b| b.is_ascii_digit())
            {
                parse_digits(tail.as_bytes(), rest.as_bytes())
            } else {
                0
            };
            Self { alpha: "", num }
        } else {
            let at = rest
                .find(|c: char| c.is_ascii_digit())
                .unwrap_or(rest.len());
            let tail = &rest[at..];
            let num = if tail.bytes().all(|b| b.is_ascii_digit()) {
                parse_digits(tail.as_bytes(), &[])
            } else {
                0
            };
            Self {
                alpha: &rest[..at],
                num,
            }
        }
    }
}

/// The digits of `first` then `then`, read as one number that comes out zero
/// on overflow, as a failed `u64::from_str` does.
fn parse_digits(first: &[u8], then: &[u8]) -> u64 {
    let mut num: u64 = 0;
    for &b in first.iter().chain(then) {
        let digit = u64::from(b - b'0');
        if num > (u64::MAX - digit) / 10 {
            return 0;
        }
        num = num * 10 + digit;
    }
    num
}

/// Sorts `extensions` by the natural order of `prefix` + extension — one key
/// per extension, instead of one concatenation per comparison — and yields the
/// ones that replace more than they cover: the suggestion's value is `prefix` +
/// extension and its span is `prefix.len() + whitespaces` wide, so what stays
/// is `ext.len() > whitespaces`.
fn natural_order<'a>(
    prefix: &str,
    extensions: &'a [String],
    whitespaces: usize,
) -> impl Iterator<Item = &'a str> {
    let mut ranked: Vec<(NaturalKey<'a>, &'a str)> = extensions
        .iter()
        .map(|ext| (NaturalKey::new(prefix, ext), ext.as_str()))
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0));
    ranked
        .into_iter()
        .filter(move |(_, ext)| ext.len() > whitespaces)
        .map(|(_, ext)| ext)
}

/// The suggestion that replaces `span` with `prefix` + `ext`.
fn suggestion(prefix: &str, ext: &str, span: Span) -> Suggestion {
    Suggestion {
        value: format!("{prefix}{ext}"),
        display_override: None,
        description: None,
        style: Some(Style::new()),
        extra: None,
        span,
        append_whitespace: false,
        match_indices: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The comparator `NaturalKey` stands in for, kept as the oracle.
    fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
        let (a_prefix, a_num) = split_alpha_num(a);
        let (b_prefix, b_num) = split_alpha_num(b);

        match a_prefix.cmp(b_prefix) {
            std::cmp::Ordering::Equal => a_num.cmp(&b_num),
            ord => ord,
        }
    }

    fn split_alpha_num(s: &str) -> (&str, u64) {
        let idx = s.find(|c: char| c.is_ascii_digit()).unwrap_or(s.len());
        let num = s[idx..].parse().unwrap_or(0);
        (&s[..idx], num)
    }

    /// The key orders exactly as comparing the built concatenations did,
    /// whichever side of the prefix/extension boundary the digits fall on.
    #[test]
    fn the_key_orders_like_the_built_concatenations() {
        let words = [
            "",
            "1",
            "9",
            "10",
            "a",
            "a1",
            "a2",
            "a10",
            "a01",
            "a1x",
            "aa",
            "b0000000000000000000009",
            "b18446744073709551615",
            "b18446744073709551616",
            "b9999999999999999999999",
            " 3",
            "z 09",
        ];
        for prefix in ["", "x", "cmd ", "x2", "x2y", "d1 ", "123"] {
            for a in words {
                for b in words {
                    assert_eq!(
                        NaturalKey::new(prefix, a).cmp(&NaturalKey::new(prefix, b)),
                        natural_cmp(&format!("{prefix}{a}"), &format!("{prefix}{b}")),
                        "{prefix:?} + {a:?} vs {b:?}"
                    );
                }
            }
        }
    }

    /// Numbers order by value, not by their digits: file2 before file10, and a
    /// number cut short by a letter orders as zero.
    #[test]
    fn numbers_order_by_value() {
        let mut completer = BastionCompleter::default();
        completer.insert(
            ["file1", "file1b", "file2", "file10", "other"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        let done = completer.complete("file", 4);
        let values: Vec<&str> = done
            .suggestions()
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        assert_eq!(values, ["file1b", "file1", "file2", "file10"]);
        assert!(done.suggestions().iter().all(|s| s.span == Span::new(0, 4)));
    }

    /// A completion may span several words, and the span then reaches back
    /// over every word it replaces.
    #[test]
    fn a_completion_may_span_several_words() {
        let mut completer = BastionCompleter::default();
        completer.insert(vec!["git pull".to_string(), "git push".to_string()]);
        let done = completer.complete("git p", 5);
        let values: Vec<&str> = done
            .suggestions()
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        assert_eq!(values, ["git pull", "git push"]);
        assert!(done.suggestions().iter().all(|s| s.span == Span::new(0, 5)));
    }

    /// A newline before the word counts as the whitespace it is replaced by.
    #[test]
    fn a_newline_before_the_word_widens_the_span() {
        let mut completer = BastionCompleter::default();
        completer.insert(vec!["batman".to_string(), "batmobile".to_string()]);
        let done = completer.complete("to the\r\nbat", 11);
        let values: Vec<&str> = done
            .suggestions()
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        assert_eq!(values, ["batman", "batmobile"]);
        assert!(
            done.suggestions()
                .iter()
                .all(|s| s.span == Span::new(8, 11))
        );
    }

    /// An empty line offers every word, still in natural order.
    #[test]
    fn an_empty_line_offers_every_word() {
        let mut completer = BastionCompleter::default();
        completer.insert(vec![
            "a1".to_string(),
            "a10".to_string(),
            "a2".to_string(),
            "zz".to_string(),
        ]);
        let done = completer.complete("", 0);
        let values: Vec<&str> = done
            .suggestions()
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        assert_eq!(values, ["a1", "a2", "a10", "zz"]);
        assert!(done.suggestions().iter().all(|s| s.span == Span::new(0, 0)));
    }
}
