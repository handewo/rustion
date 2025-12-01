use nu_ansi_term::Style;

use reedline::{Completer, Span, Suggestion};
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
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
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
            let mut split = line.split(' ').rev();
            let mut span_line: String = String::new();
            for _ in 0..split.clone().count() {
                if let Some(s) = split.next() {
                    if s.is_empty() {
                        span_line_whitespaces += 1;
                        continue;
                    }
                    if span_line.is_empty() {
                        span_line = s.to_string();
                    } else {
                        span_line = format!("{s} {span_line}");
                    }
                    // TODO: Improve sort performance
                    if let Some(mut extensions) = self.root.complete(span_line.chars()) {
                        extensions.sort_by(|a, b| {
                            let sa = [span_line.as_str(), a.as_str()].concat();
                            let sb = [span_line.as_str(), b.as_str()].concat();
                            natural_cmp(&sa, &sb)
                        });
                        completions.extend(
                            extensions
                                .iter()
                                .map(|ext| {
                                    let span = Span::new(
                                        pos - span_line.len() - span_line_whitespaces,
                                        pos,
                                    );

                                    Suggestion {
                                        value: format!("{span_line}{ext}"),
                                        description: None,
                                        style: Some(Style::new()),
                                        extra: None,
                                        span,
                                        append_whitespace: false,
                                        match_indices: None,
                                    }
                                })
                                .filter(|t| t.value.len() > (t.span.end - t.span.start))
                                .collect::<Vec<Suggestion>>(),
                        );
                    }
                }
            }
        } else {
            let mut extensions = self.root.collect("");
            extensions.sort_by(|a, b| natural_cmp(a, b));
            completions.extend(
                extensions
                    .iter()
                    .map(|ext| {
                        let span = Span::new(pos - span_line_whitespaces, pos);

                        Suggestion {
                            value: ext.clone(),
                            description: None,
                            style: Some(Style::new()),
                            extra: None,
                            span,
                            append_whitespace: false,
                            match_indices: None,
                        }
                    })
                    .filter(|t| t.value.len() > (t.span.end - t.span.start))
                    .collect::<Vec<Suggestion>>(),
            );
        }
        completions.dedup();
        completions
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
            Some(self.collect(""))
        }
    }

    fn collect(&self, partial: &str) -> Vec<String> {
        let mut completions = vec![];
        if self.leaf {
            completions.push(partial.to_string());
        }

        if !self.subnodes.is_empty() {
            for (c, node) in &self.subnodes {
                let mut partial = partial.to_string();
                partial.push(*c);
                completions.append(&mut node.collect(&partial));
            }
        }
        completions
    }
}

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
