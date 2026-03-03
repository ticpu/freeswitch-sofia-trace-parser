use std::io::{BufRead, BufReader, Read};

pub struct GrepFilter<R> {
    inner: BufReader<R>,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: Read> GrepFilter<R> {
    pub fn new(reader: R) -> Self {
        Self {
            inner: BufReader::new(reader),
            buf: Vec::new(),
            pos: 0,
        }
    }
}

fn is_grep_separator(line: &[u8]) -> bool {
    line == b"--\n" || line == b"--\r\n"
}

impl<R: Read> Read for GrepFilter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.buf.len() {
            let available = &self.buf[self.pos..];
            let n = buf.len().min(available.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.pos += n;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Ok(n);
        }

        self.buf.clear();
        self.pos = 0;

        while self.buf.len() < buf.len() {
            let old_len = self.buf.len();
            let n = self.inner.read_until(b'\n', &mut self.buf)?;
            if n == 0 {
                break;
            }
            if is_grep_separator(&self.buf[old_len..]) {
                self.buf.truncate(old_len);
            }
        }

        let n = buf.len().min(self.buf.len());
        buf[..n].copy_from_slice(&self.buf[..n]);
        self.pos = n;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        Ok(n)
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
