use std::io::Read;

use memchr::memmem;
use tracing::{debug, trace, warn};

use crate::types::{Direction, Frame, Timestamp, Transport};

#[derive(Debug)]
pub enum ParseError {
    InvalidHeader(String),
    Io(std::io::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidHeader(msg) => write!(f, "invalid frame header: {msg}"),
            ParseError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

use std::fmt;

fn parse_u8(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() || bytes.len() > 3 {
        return None;
    }
    let mut val: u8 = 0;
    for &b in bytes {
        val = val.checked_mul(10)?.checked_add(b.checked_sub(b'0')?)?;
    }
    Some(val)
}

fn parse_u16(bytes: &[u8]) -> Option<u16> {
    if bytes.is_empty() || bytes.len() > 5 {
        return None;
    }
    let mut val: u16 = 0;
    for &b in bytes {
        val = val.checked_mul(10)?.checked_add(u16::from(b.checked_sub(b'0')?))?;
    }
    Some(val)
}

fn parse_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 10 {
        return None;
    }
    let mut val: u32 = 0;
    for &b in bytes {
        val = val.checked_mul(10)?.checked_add(u32::from(b.checked_sub(b'0')?))?;
    }
    Some(val)
}

fn parse_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || bytes.len() > 10 {
        return None;
    }
    let mut val: usize = 0;
    for &b in bytes {
        val = val.checked_mul(10)?.checked_add(usize::from(b.checked_sub(b'0')?))?;
    }
    Some(val)
}

/// Parse timestamp from bytes: either `HH:MM:SS.usec` or `YYYY-MM-DD HH:MM:SS.usec`
fn parse_timestamp(bytes: &[u8]) -> Option<Timestamp> {
    // Try full datetime first: YYYY-MM-DD HH:MM:SS.usec (min 26 bytes)
    if bytes.len() >= 26 && bytes[4] == b'-' && bytes[7] == b'-' && bytes[10] == b' ' {
        let year = parse_u16(&bytes[0..4])?;
        let month = parse_u8(&bytes[5..7])?;
        let day = parse_u8(&bytes[8..10])?;
        let ts = parse_time_part(&bytes[11..])?;
        return Some(Timestamp::DateTime {
            year,
            month,
            day,
            hour: ts.0,
            min: ts.1,
            sec: ts.2,
            usec: ts.3,
        });
    }
    // Time-only: HH:MM:SS.usec (min 15 bytes)
    let (hour, min, sec, usec) = parse_time_part(bytes)?;
    Some(Timestamp::TimeOnly {
        hour,
        min,
        sec,
        usec,
    })
}

/// Parse `HH:MM:SS.usec` from bytes, returns (hour, min, sec, usec)
fn parse_time_part(bytes: &[u8]) -> Option<(u8, u8, u8, u32)> {
    if bytes.len() < 15 {
        return None;
    }
    if bytes[2] != b':' || bytes[5] != b':' || bytes[8] != b'.' {
        return None;
    }
    let hour = parse_u8(&bytes[0..2])?;
    let min = parse_u8(&bytes[3..5])?;
    let sec = parse_u8(&bytes[6..8])?;
    let usec = parse_u32(&bytes[9..15])?;
    Some((hour, min, sec, usec))
}

/// Parse a frame header line from `&[u8]`.
///
/// Expected format:
/// `(recv|sent) <N> bytes (from|to) <transport>/<address> at <timestamp>:\n`
///
/// Returns `(Frame header fields, header_len)` where header_len includes the trailing `\n`.
pub fn parse_frame_header(data: &[u8]) -> Result<(Direction, usize, Transport, String, Timestamp, usize), ParseError> {
    let newline_pos = memchr::memchr(b'\n', data)
        .ok_or_else(|| ParseError::InvalidHeader("no newline in header".into()))?;
    let line = &data[..newline_pos];
    // Strip trailing \r if present
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    // Must end with ':'
    let line = line.strip_suffix(b":")
        .ok_or_else(|| ParseError::InvalidHeader("header does not end with ':'".into()))?;

    // Direction — both "recv " and "sent " are 5 bytes
    let direction = if line.starts_with(b"recv ") {
        Direction::Recv
    } else if line.starts_with(b"sent ") {
        Direction::Sent
    } else {
        return Err(ParseError::InvalidHeader("expected 'recv' or 'sent'".into()));
    };
    let mut pos = 5;

    // Byte count: digits until ' '
    let space = memchr::memchr(b' ', &line[pos..])
        .ok_or_else(|| ParseError::InvalidHeader("no space after byte count".into()))?;
    let byte_count = parse_usize(&line[pos..pos + space])
        .ok_or_else(|| ParseError::InvalidHeader("invalid byte count".into()))?;
    pos += space + 1;

    // " bytes from/to "
    let expected_recv = b"bytes from ";
    let expected_sent = b"bytes to ";
    if direction == Direction::Recv {
        if !line[pos..].starts_with(expected_recv) {
            return Err(ParseError::InvalidHeader("expected 'bytes from '".into()));
        }
        pos += expected_recv.len();
    } else {
        if !line[pos..].starts_with(expected_sent) {
            return Err(ParseError::InvalidHeader("expected 'bytes to '".into()));
        }
        pos += expected_sent.len();
    }

    // Transport: tcp/ udp/ tls/ wss/
    let transport = if line[pos..].starts_with(b"tcp/") {
        pos += 4;
        Transport::Tcp
    } else if line[pos..].starts_with(b"udp/") {
        pos += 4;
        Transport::Udp
    } else if line[pos..].starts_with(b"tls/") {
        pos += 4;
        Transport::Tls
    } else if line[pos..].starts_with(b"wss/") {
        pos += 4;
        Transport::Wss
    } else {
        return Err(ParseError::InvalidHeader("unknown transport".into()));
    };

    // Address: until " at "
    let at_marker = b" at ";
    let at_pos = memmem::find(&line[pos..], at_marker)
        .ok_or_else(|| ParseError::InvalidHeader("no ' at ' in header".into()))?;
    let address = String::from_utf8_lossy(&line[pos..pos + at_pos]).into_owned();
    pos += at_pos + at_marker.len();

    // Timestamp: rest of line (after stripping trailing ':' already done)
    let timestamp = parse_timestamp(&line[pos..])
        .ok_or_else(|| ParseError::InvalidHeader("invalid timestamp".into()))?;

    Ok((direction, byte_count, transport, address, timestamp, newline_pos + 1))
}

/// Check if data at given position looks like a valid frame header start.
/// Used to validate `\x0B\n` boundaries.
pub fn is_frame_header(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let starts_valid = data.starts_with(b"recv ") || data.starts_with(b"sent ");
    if !starts_valid {
        return false;
    }
    // Check that after direction there are digits followed by " bytes "
    let rest = &data[5..];
    let space = match memchr::memchr(b' ', rest) {
        Some(p) => p,
        None => return false,
    };
    if space == 0 || space > 10 {
        return false;
    }
    for &b in &rest[..space] {
        if !b.is_ascii_digit() {
            return false;
        }
    }
    rest[space..].starts_with(b" bytes ")
}

const READ_BUF_SIZE: usize = 32 * 1024;

pub struct FrameIterator<R> {
    reader: R,
    buf: Vec<u8>,
    eof: bool,
    frame_count: u64,
}

impl<R: Read> FrameIterator<R> {
    pub fn new(reader: R) -> Self {
        FrameIterator {
            reader,
            buf: Vec::with_capacity(READ_BUF_SIZE * 2),
            eof: false,
            frame_count: 0,
        }
    }

    fn fill_buf(&mut self) -> Result<bool, std::io::Error> {
        if self.eof {
            return Ok(false);
        }
        let old_len = self.buf.len();
        self.buf.resize(old_len + READ_BUF_SIZE, 0);
        let n = self.reader.read(&mut self.buf[old_len..])?;
        self.buf.truncate(old_len + n);
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        Ok(true)
    }

    /// Find the next `\x0B\n` boundary that is followed by a valid frame header.
    fn find_boundary(&self, start: usize) -> Option<usize> {
        let finder = memmem::Finder::new(b"\x0B\n");
        let mut search_from = start;
        loop {
            let pos = finder.find(&self.buf[search_from..])?;
            let abs_pos = search_from + pos;
            let after = abs_pos + 2;
            if after >= self.buf.len() {
                // Boundary at very end — could be real, but we can't validate header yet
                // If EOF, accept it as boundary (content ends at \x0B)
                if self.eof {
                    return Some(abs_pos);
                }
                return None; // Need more data
            }
            if is_frame_header(&self.buf[after..]) {
                return Some(abs_pos);
            }
            // \x0B\n in content, not a boundary — skip past it
            trace!(
                offset = abs_pos,
                "found \\x0B\\n in content (not a boundary), skipping"
            );
            search_from = abs_pos + 2;
        }
    }

    /// Skip to the first valid frame header in the buffer (for partial first frames).
    fn skip_to_first_header(&mut self) -> Option<usize> {
        if is_frame_header(&self.buf) {
            return Some(0);
        }
        // Look for \x0B\n followed by a valid header
        let finder = memmem::Finder::new(b"\x0B\n");
        let mut search_from = 0;
        loop {
            if let Some(pos) = finder.find(&self.buf[search_from..]) {
                let abs_pos = search_from + pos;
                let after = abs_pos + 2;
                if after < self.buf.len() && is_frame_header(&self.buf[after..]) {
                    warn!(
                        skipped_bytes = after,
                        "skipped partial first frame"
                    );
                    return Some(after);
                }
                search_from = abs_pos + 2;
            } else {
                return None;
            }
        }
    }
}

impl<R: Read> Iterator for FrameIterator<R> {
    type Item = Result<Frame, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Ensure we have data
        if self.buf.is_empty() && !self.eof {
            if let Err(e) = self.fill_buf() {
                return Some(Err(ParseError::Io(e)));
            }
        }

        if self.buf.is_empty() {
            return None;
        }

        // On first call, skip to first valid header if needed
        if self.frame_count == 0 {
            loop {
                match self.skip_to_first_header() {
                    Some(offset) => {
                        if offset > 0 {
                            self.buf.drain(..offset);
                        }
                        break;
                    }
                    None => {
                        if self.eof {
                            debug!("no valid frame header found in entire input");
                            return None;
                        }
                        if let Err(e) = self.fill_buf() {
                            return Some(Err(ParseError::Io(e)));
                        }
                    }
                }
            }
        }

        if self.buf.is_empty() {
            return None;
        }

        // Parse frame header at current position
        let header = match parse_frame_header(&self.buf) {
            Ok(h) => h,
            Err(e) => {
                // Try to recover by finding next boundary
                warn!(error = %e, "failed to parse frame header, attempting recovery");
                if let Some(boundary) = self.find_boundary(0) {
                    self.buf.drain(..boundary + 2);
                    return self.next();
                }
                return Some(Err(e));
            }
        };

        let (direction, byte_count, transport, address, timestamp, header_len) = header;
        let content_start = header_len;

        // Find the boundary for this frame
        loop {
            if let Some(boundary_pos) = self.find_boundary(content_start) {
                // Content is between header end and \x0B
                let content = self.buf[content_start..boundary_pos].to_vec();
                // Consume up to and including \x0B\n
                self.buf.drain(..boundary_pos + 2);
                self.frame_count += 1;

                if content.len() != byte_count {
                    debug!(
                        frame = self.frame_count,
                        expected = byte_count,
                        actual = content.len(),
                        "frame content size mismatch"
                    );
                }

                return Some(Ok(Frame {
                    direction,
                    byte_count,
                    transport,
                    address,
                    timestamp,
                    content,
                }));
            }

            if self.eof {
                // Last frame — no trailing \x0B\n
                // Check if there's a \x0B at the very end (without \n)
                let end = if self.buf.last() == Some(&0x0B) {
                    self.buf.len() - 1
                } else {
                    self.buf.len()
                };
                let content = self.buf[content_start..end].to_vec();
                self.buf.clear();
                self.frame_count += 1;

                if content.len() != byte_count {
                    debug!(
                        frame = self.frame_count,
                        expected = byte_count,
                        actual = content.len(),
                        "last frame content size mismatch"
                    );
                }

                return Some(Ok(Frame {
                    direction,
                    byte_count,
                    transport,
                    address,
                    timestamp,
                    content,
                }));
            }

            // Need more data
            if let Err(e) = self.fill_buf() {
                return Some(Err(ParseError::Io(e)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_recv_ipv4_tcp() {
        let header = b"recv 100 bytes from tcp/192.168.1.1:5060 at 00:00:01.350874:\n";
        let (dir, count, transport, addr, ts, len) = parse_frame_header(header).unwrap();
        assert_eq!(dir, Direction::Recv);
        assert_eq!(count, 100);
        assert_eq!(transport, Transport::Tcp);
        assert_eq!(addr, "192.168.1.1:5060");
        assert_eq!(
            ts,
            Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 1,
                usec: 350874
            }
        );
        assert_eq!(len, header.len());
    }

    #[test]
    fn parse_recv_ipv6_tcp() {
        let header =
            b"recv 1440 bytes from tcp/[2001:4958:10:14::4]:30046 at 13:03:21.674883:\n";
        let (dir, count, transport, addr, ts, _) = parse_frame_header(header).unwrap();
        assert_eq!(dir, Direction::Recv);
        assert_eq!(count, 1440);
        assert_eq!(transport, Transport::Tcp);
        assert_eq!(addr, "[2001:4958:10:14::4]:30046");
        assert_eq!(
            ts,
            Timestamp::TimeOnly {
                hour: 13,
                min: 3,
                sec: 21,
                usec: 674883
            }
        );
    }

    #[test]
    fn parse_sent_ipv6_tcp() {
        let header =
            b"sent 681 bytes to tcp/[2001:4958:10:14::4]:30046 at 13:03:21.675500:\n";
        let (dir, count, transport, addr, _, _) = parse_frame_header(header).unwrap();
        assert_eq!(dir, Direction::Sent);
        assert_eq!(count, 681);
        assert_eq!(transport, Transport::Tcp);
        assert_eq!(addr, "[2001:4958:10:14::4]:30046");
    }

    #[test]
    fn parse_recv_udp() {
        let header = b"recv 457 bytes from udp/10.0.0.1:5060 at 00:19:47.123456:\n";
        let (dir, _, transport, _, _, _) = parse_frame_header(header).unwrap();
        assert_eq!(dir, Direction::Recv);
        assert_eq!(transport, Transport::Udp);
    }

    #[test]
    fn parse_sent_tls() {
        let header = b"sent 500 bytes to tls/10.0.0.1:5061 at 12:00:00.000000:\n";
        let (dir, count, transport, _, _, _) = parse_frame_header(header).unwrap();
        assert_eq!(dir, Direction::Sent);
        assert_eq!(count, 500);
        assert_eq!(transport, Transport::Tls);
    }

    #[test]
    fn parse_full_datetime_timestamp() {
        let header =
            b"recv 100 bytes from tcp/192.168.1.1:5060 at 2026-02-01 10:00:00.000000:\n";
        let (_, _, _, _, ts, _) = parse_frame_header(header).unwrap();
        assert_eq!(
            ts,
            Timestamp::DateTime {
                year: 2026,
                month: 2,
                day: 1,
                hour: 10,
                min: 0,
                sec: 0,
                usec: 0
            }
        );
    }

    #[test]
    fn parse_invalid_header() {
        assert!(parse_frame_header(b"invalid header\n").is_err());
        assert!(parse_frame_header(b"recv abc bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n").is_err());
    }

    #[test]
    fn is_frame_header_valid() {
        assert!(is_frame_header(b"recv 100 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n"));
        assert!(is_frame_header(b"sent 681 bytes to tcp/[::1]:5060 at 00:00:00.000000:\n"));
        assert!(!is_frame_header(b"not a header"));
        assert!(!is_frame_header(b"recv abc bytes"));
        assert!(!is_frame_header(b""));
    }

    #[test]
    fn frame_iterator_single_frame() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n";
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[0].byte_count, 5);
    }

    #[test]
    fn frame_iterator_multiple_frames() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\nsent 5 bytes to tcp/1.1.1.1:5060 at 00:00:00.000001:\nworld\x0B\n";
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].content, b"hello");
        assert_eq!(frames[0].direction, Direction::Recv);
        assert_eq!(frames[1].content, b"world");
        assert_eq!(frames[1].direction, Direction::Sent);
    }

    #[test]
    fn frame_iterator_vt_in_content() {
        // \x0B in content but not followed by valid header — should NOT split
        let mut data = Vec::new();
        data.extend_from_slice(b"recv 15 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\n");
        data.extend_from_slice(b"he\x0B\nllo world!!");
        data.extend_from_slice(b"\x0B\n");
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"he\x0B\nllo world!!");
    }

    #[test]
    fn frame_iterator_eof_without_boundary() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello";
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
    }

    #[test]
    fn frame_iterator_eof_with_lone_vt() {
        let data = b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B";
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
    }

    #[test]
    fn frame_iterator_partial_first_frame() {
        // Data starts with garbage, then a valid boundary + frame
        let mut data = Vec::new();
        data.extend_from_slice(b"partial garbage data");
        data.extend_from_slice(b"\x0B\n");
        data.extend_from_slice(b"recv 5 bytes from tcp/1.1.1.1:5060 at 00:00:00.000000:\nhello\x0B\n");
        let frames: Vec<Frame> = FrameIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].content, b"hello");
    }
}
