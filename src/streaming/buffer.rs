/// Word-boundary buffer for SSE streaming enforcement.
/// Accumulates bytes and flushes on: word boundary, size cap, timeout, or stream end.
pub struct WordBoundaryBuffer {
    data: Vec<u8>,
    size_cap: usize,
    pub flush_counts: FlushCounts,
}

#[derive(Debug, Default, Clone)]
pub struct FlushCounts {
    pub on_boundary: usize,
    pub on_size_cap: usize,
    pub on_stream_end: usize,
}

pub enum FlushReason {
    Boundary,
    SizeCap,
    StreamEnd,
}

impl WordBoundaryBuffer {
    pub fn new(size_cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(size_cap),
            size_cap,
            flush_counts: FlushCounts::default(),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Option<(Vec<u8>, FlushReason)> {
        self.data.extend_from_slice(bytes);

        // Check size cap first
        if self.data.len() >= self.size_cap {
            self.flush_counts.on_size_cap += 1;
            return Some((self.take(), FlushReason::SizeCap));
        }

        // Check for word boundary (whitespace)
        if bytes
            .iter()
            .any(|b| *b == b' ' || *b == b'\n' || *b == b'\r' || *b == b'\t')
        {
            self.flush_counts.on_boundary += 1;
            return Some((self.take(), FlushReason::Boundary));
        }

        None
    }

    /// Flush remaining content at stream end.
    pub fn flush_end(&mut self) -> Option<Vec<u8>> {
        if self.data.is_empty() {
            return None;
        }
        self.flush_counts.on_stream_end += 1;
        Some(self.take())
    }

    fn take(&mut self) -> Vec<u8> {
        let d = self.data.clone();
        self.data.clear();
        d
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_flushes_on_word_boundary_space() {
        let mut buf = WordBoundaryBuffer::new(1024);
        let result = buf.push(b"hello world");
        assert!(result.is_some());
        let (flushed, _) = result.unwrap();
        assert_eq!(flushed, b"hello world");
        assert_eq!(buf.flush_counts.on_boundary, 1);
    }

    #[test]
    fn push_flushes_on_word_boundary_newline() {
        let mut buf = WordBoundaryBuffer::new(1024);
        let result = buf.push(b"line\n");
        assert!(result.is_some());
        assert_eq!(buf.flush_counts.on_boundary, 1);
    }

    #[test]
    fn push_flushes_on_size_cap() {
        let mut buf = WordBoundaryBuffer::new(4);
        // Push bytes that exceed the cap with no whitespace
        let result = buf.push(b"12345");
        assert!(result.is_some());
        let (_, reason) = result.unwrap();
        assert!(matches!(reason, FlushReason::SizeCap));
        assert_eq!(buf.flush_counts.on_size_cap, 1);
    }

    #[test]
    fn push_returns_none_when_below_cap_and_no_boundary() {
        let mut buf = WordBoundaryBuffer::new(1024);
        let result = buf.push(b"hello");
        assert!(result.is_none());
        assert!(!buf.is_empty());
    }

    #[test]
    fn flush_end_returns_remaining_and_increments_count() {
        let mut buf = WordBoundaryBuffer::new(1024);
        buf.push(b"partial"); // no boundary, stays in buffer
        let result = buf.flush_end();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"partial");
        assert_eq!(buf.flush_counts.on_stream_end, 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn flush_end_returns_none_when_empty() {
        let mut buf = WordBoundaryBuffer::new(1024);
        let result = buf.flush_end();
        assert!(result.is_none());
        assert_eq!(buf.flush_counts.on_stream_end, 0);
    }

    #[test]
    fn flush_counts_accumulate_across_multiple_flushes() {
        let mut buf = WordBoundaryBuffer::new(1024);
        buf.push(b"word1 "); // boundary flush #1
        buf.push(b"word2\n"); // boundary flush #2
        buf.push(b"word3"); // no flush — stays buffered
        buf.flush_end(); // stream-end flush #1

        assert_eq!(buf.flush_counts.on_boundary, 2);
        assert_eq!(buf.flush_counts.on_stream_end, 1);
        assert_eq!(buf.flush_counts.on_size_cap, 0);
    }
}
