use std::io::{BufRead, BufReader, Read};

/// A [`Read`] adapter that strips `grep -C` separator lines (`--\n`) from the
/// input stream.
///
/// When piping grep output into the parser (`grep -C5 pattern dump | parser`),
/// grep inserts `--` lines between match groups. These corrupt the binary frame
/// stream. Wrap the input in `GrepFilter` to transparently remove them.
///
/// Only exact `--\n` and `--\r\n` lines are stripped. Similar lines like
/// `---\n` or `-- \n` pass through unchanged.
pub struct GrepFilter<R> {
    inner: BufReader<R>,
    /// Accumulates a partial line when `--\n` / `--\r\n` detection straddles
    /// a BufReader buffer boundary.
    partial: Vec<u8>,
    partial_pos: usize,
}

impl<R: Read> GrepFilter<R> {
    /// Create a new filter wrapping the given reader.
    pub fn new(reader: R) -> Self {
        Self {
            inner: BufReader::new(reader),
            partial: Vec::new(),
            partial_pos: 0,
        }
    }
}

fn is_grep_separator(line: &[u8]) -> bool {
    line == b"--\n" || line == b"--\r\n"
}

impl<R: Read> Read for GrepFilter<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        // Drain leftover partial line from a previous call
        if self.partial_pos < self.partial.len() {
            let available = &self.partial[self.partial_pos..];
            let n = out.len().min(available.len());
            out[..n].copy_from_slice(&available[..n]);
            self.partial_pos += n;
            if self.partial_pos == self.partial.len() {
                self.partial.clear();
                self.partial_pos = 0;
            }
            return Ok(n);
        }

        loop {
            let buf = self.inner.fill_buf()?;
            if buf.is_empty() {
                return Ok(0);
            }

            match memchr::memchr(b'\n', buf) {
                Some(nl) => {
                    let line_len = nl + 1;
                    if is_grep_separator(&buf[..line_len]) {
                        self.inner.consume(line_len);
                        continue;
                    }
                    let n = out.len().min(line_len);
                    out[..n].copy_from_slice(&buf[..n]);
                    if n < line_len {
                        self.partial.extend_from_slice(&buf[n..line_len]);
                        self.partial_pos = 0;
                    }
                    self.inner.consume(line_len);
                    return Ok(n);
                }
                None => {
                    // No newline — partial line, can't be a separator.
                    let buf_len = buf.len();
                    let n = out.len().min(buf_len);
                    out[..n].copy_from_slice(&buf[..n]);
                    if n < buf_len {
                        self.partial.extend_from_slice(&buf[n..buf_len]);
                        self.partial_pos = 0;
                    }
                    self.inner.consume(buf_len);
                    return Ok(n);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn filter(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        GrepFilter::new(input).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn strip_separator() {
        assert_eq!(filter(b"hello\n--\nworld\n"), b"hello\nworld\n");
    }

    #[test]
    fn strip_crlf_separator() {
        assert_eq!(filter(b"hello\n--\r\nworld\n"), b"hello\nworld\n");
    }

    #[test]
    fn passthrough_no_separators() {
        let input = b"line one\nline two\nline three\n";
        assert_eq!(filter(input), input);
    }

    #[test]
    fn consecutive_separators() {
        assert_eq!(filter(b"a\n--\n--\n--\nb\n"), b"a\nb\n");
    }

    #[test]
    fn separator_at_start() {
        assert_eq!(filter(b"--\nhello\n"), b"hello\n");
    }

    #[test]
    fn partial_separator_preserved() {
        let input = b"---\n-- \n--x\n";
        assert_eq!(filter(input), input);
    }

    #[test]
    fn empty_input() {
        assert_eq!(filter(b""), b"");
    }

    #[test]
    fn only_separators() {
        assert_eq!(filter(b"--\n--\n--\n"), b"");
    }

    #[test]
    fn no_trailing_newline() {
        assert_eq!(filter(b"hello"), b"hello");
    }

    #[test]
    fn binary_content_with_separator_like_bytes() {
        let input = b"data\x00--\nmore\n";
        assert_eq!(filter(input), input);
    }

    #[test]
    fn frame_iterator_grep_separator_between_frames() {
        use crate::FrameIterator;

        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(
            b"sent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n",
        );

        let filtered = GrepFilter::new(&data[..]);
        let frames: Vec<_> = FrameIterator::new(filtered)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[1].content, b"world");
    }

    #[test]
    fn frame_iterator_grep_partial_context() {
        use crate::FrameIterator;

        let mut data = Vec::new();
        data.extend_from_slice(
            b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n",
        );
        data.extend_from_slice(b"Accept: application/sdp\r\nContent-Length: 0\r\n\r\n");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(b"sent 3 bytes to tcp/2.2.2.2:5060 at 00:00:01.000000:\nbye\x0B\n");

        let filtered = GrepFilter::new(&data[..]);
        let items: Vec<_> = FrameIterator::new(filtered).collect();
        let frames: Vec<_> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[1].content, b"bye");
    }

    #[test]
    fn frame_iterator_grep_separator_strips_from_content() {
        use crate::FrameIterator;

        let content = b"SIP/2.0 200 OK\r\nVia: a\r\nContent-Length: 0\r\n\r\n";
        let mut data = Vec::new();
        let header = format!(
            "recv {} bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n",
            content.len()
        );
        data.extend_from_slice(header.as_bytes());
        data.extend_from_slice(b"SIP/2.0 200 OK\r\nVia: a\r\n--\nContent-Length: 0\r\n\r\n");
        data.extend_from_slice(b"\x0B\n");

        let filtered = GrepFilter::new(&data[..]);
        let frames: Vec<_> = FrameIterator::new(filtered)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, content);
    }
}
