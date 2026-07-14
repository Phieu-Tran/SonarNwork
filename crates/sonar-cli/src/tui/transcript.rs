use std::collections::VecDeque;

pub(super) const DEFAULT_MAX_LINES: usize = 2_000;
pub(super) const DEFAULT_MAX_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TranscriptKind {
    Command,
    Stdout,
    Stderr,
    Warning,
    Status,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TranscriptEntry {
    pub(super) kind: TranscriptKind,
    pub(super) text: String,
}

#[derive(Debug)]
pub(super) struct BoundedTranscript {
    entries: VecDeque<TranscriptEntry>,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    truncated: bool,
}

impl BoundedTranscript {
    pub(super) fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_LINES, DEFAULT_MAX_BYTES)
    }

    pub(super) fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            max_lines,
            max_bytes,
            truncated: false,
        }
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
        self.truncated = false;
    }

    pub(super) fn push(&mut self, kind: TranscriptKind, text: impl Into<String>) {
        if self.max_lines == 0 || self.max_bytes == 0 {
            self.truncated = true;
            return;
        }

        let original = text.into();
        let (text, truncated_line) = truncate_tail(original, self.max_bytes);
        let text_bytes = text.len();
        let mut evicted = 0;
        while self.entries.len() >= self.max_lines
            || self.bytes.saturating_add(text_bytes) > self.max_bytes
        {
            let Some(entry) = self.entries.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(entry.text.len());
            evicted += 1;
        }

        self.bytes = self.bytes.saturating_add(text_bytes);
        self.entries.push_back(TranscriptEntry { kind, text });
        self.truncated |= truncated_line || evicted > 0;
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &TranscriptEntry> {
        self.entries.iter()
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn was_truncated(&self) -> bool {
        self.truncated
    }

    #[cfg(test)]
    fn byte_len(&self) -> usize {
        self.bytes
    }
}

fn truncate_tail(text: String, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }

    const ELLIPSIS: &str = "…";
    if max_bytes < ELLIPSIS.len() {
        return (String::new(), true);
    }
    let tail_budget = max_bytes - ELLIPSIS.len();
    let mut start = text.len().saturating_sub(tail_budget);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    (format!("{ELLIPSIS}{}", &text[start..]), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_line_and_byte_caps() {
        let mut transcript = BoundedTranscript::new(3, 8);
        transcript.push(TranscriptKind::Stdout, "one");
        transcript.push(TranscriptKind::Stdout, "two");
        transcript.push(TranscriptKind::Stderr, "three");

        assert_eq!(transcript.len(), 2);
        assert!(transcript.byte_len() <= 8);
        assert!(transcript.was_truncated());
        assert_eq!(
            transcript
                .iter()
                .map(|entry| entry.text.as_str())
                .collect::<Vec<_>>(),
            ["two", "three"]
        );
    }

    #[test]
    fn truncates_an_oversized_utf8_line_at_a_character_boundary() {
        let mut transcript = BoundedTranscript::new(2, 10);
        transcript.push(TranscriptKind::Stdout, "đầu-cuối-cùng");
        let entry = transcript.iter().next().expect("entry");

        assert!(transcript.was_truncated());
        assert!(entry.text.starts_with('…'));
        assert!(entry.text.len() <= 10);
        assert!(std::str::from_utf8(entry.text.as_bytes()).is_ok());
    }

    #[test]
    fn clear_resets_the_truncation_marker() {
        let mut transcript = BoundedTranscript::new(1, 4);
        transcript.push(TranscriptKind::Stdout, "first");
        assert!(transcript.was_truncated());

        transcript.clear();

        assert!(transcript.is_empty());
        assert!(!transcript.was_truncated());
    }
}
