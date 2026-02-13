use std::sync::LazyLock;

use memchr::memmem;
use tracing::{debug, trace};

use crate::frame::{FrameIterator, ParseError};
use crate::types::{Frame, SipMessage, Transport};

static CRLF: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new(b"\r\n"));
static CRLFCRLF: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new(b"\r\n\r\n"));

pub struct MessageIterator<R> {
    frames: FrameIterator<R>,
    pending: Option<Frame>,
}

impl<R: std::io::Read> MessageIterator<R> {
    pub fn new(reader: R) -> Self {
        MessageIterator {
            frames: FrameIterator::new(reader),
            pending: None,
        }
    }

    fn next_frame(&mut self) -> Option<Result<Frame, ParseError>> {
        if let Some(frame) = self.pending.take() {
            return Some(Ok(frame));
        }
        self.frames.next()
    }
}

impl<R: std::io::Read> Iterator for MessageIterator<R> {
    type Item = Result<SipMessage, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let first_frame = match self.next_frame()? {
            Ok(f) => f,
            Err(e) => return Some(Err(e)),
        };

        let direction = first_frame.direction;
        let transport = first_frame.transport;
        let address = first_frame.address.clone();
        let timestamp = first_frame.timestamp;
        let mut content = first_frame.content;
        let mut frame_count: usize = 1;

        // For TCP/TLS/WSS: group consecutive frames with same direction + address
        if transport != Transport::Udp {
            loop {
                match self.frames.next() {
                    Some(Ok(next_frame)) => {
                        if next_frame.direction == direction && next_frame.address == address {
                            trace!(
                                frame = frame_count + 1,
                                bytes = next_frame.content.len(),
                                "appending continuation frame"
                            );
                            content.extend_from_slice(&next_frame.content);
                            frame_count += 1;
                        } else {
                            self.pending = Some(next_frame);
                            break;
                        }
                    }
                    Some(Err(e)) => return Some(Err(e)),
                    None => break,
                }
            }
        }

        if frame_count > 1 {
            debug!(
                frame_count,
                total_bytes = content.len(),
                address,
                "reassembled multi-frame message"
            );
        }

        // Try to split aggregated messages (multiple SIP messages in one frame/reassembly)
        let split = split_aggregated(&content);
        if split.len() > 1 {
            debug!(
                count = split.len(),
                "split aggregated messages by Content-Length"
            );
            // Return first, queue the rest as synthetic single-frame messages
            // We only support returning one at a time from the iterator, so we'll
            // handle this by returning the first and storing remainder in pending content
            let first_end = split[0];
            let remainder = content[first_end..].to_vec();
            content.truncate(first_end);

            // Create a synthetic frame for the remainder
            if !remainder.is_empty() {
                self.pending = Some(Frame {
                    direction,
                    byte_count: remainder.len(),
                    transport,
                    address: address.clone(),
                    timestamp,
                    content: remainder,
                });
            }
        }

        Some(Ok(SipMessage {
            direction,
            transport,
            address,
            timestamp,
            content,
            frame_count,
        }))
    }
}

/// Find Content-Length header value in SIP message bytes.
/// Returns the value as usize if found.
fn find_content_length(data: &[u8]) -> Option<usize> {
    let header_end = CRLFCRLF.find(data)?;
    let headers = &data[..header_end];

    let mut pos = 0;
    while pos < headers.len() {
        let line_end = CRLF.find(&headers[pos..]).unwrap_or(headers.len() - pos);
        let line = &headers[pos..pos + line_end];

        if let Some(value) = extract_header_value(line, b"Content-Length") {
            return parse_content_length(value);
        }
        if let Some(value) = extract_compact_header_value(line, b'l') {
            return parse_content_length(value);
        }

        pos += line_end + 2; // skip \r\n
    }
    None
}

fn extract_header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if line.len() <= name.len() + 1 {
        return None;
    }
    // Case-insensitive prefix match
    if !line[..name.len()].eq_ignore_ascii_case(name) {
        return None;
    }
    if line[name.len()] != b':' {
        return None;
    }
    Some(trim_bytes(&line[name.len() + 1..]))
}

fn extract_compact_header_value(line: &[u8], compact: u8) -> Option<&[u8]> {
    // Compact form: single letter followed by ':'
    // Must be at start of line and followed by ':' then optional whitespace
    if line.len() < 2 {
        return None;
    }
    if line[0] != compact || line[1] != b':' {
        return None;
    }
    Some(trim_bytes(&line[2..]))
}

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(b.len());
    let end = b.iter().rposition(|&c| c != b' ' && c != b'\t').map_or(start, |p| p + 1);
    &b[start..end]
}

fn parse_content_length(value: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(value).ok()?;
    s.parse().ok()
}

/// Check if data at given position starts with a SIP request or response line.
fn is_sip_start(data: &[u8]) -> bool {
    if data.starts_with(b"SIP/2.0 ") {
        return true;
    }
    // Check for known SIP methods
    const METHODS: &[&[u8]] = &[
        b"INVITE ", b"ACK ", b"BYE ", b"CANCEL ", b"OPTIONS ",
        b"REGISTER ", b"PRACK ", b"SUBSCRIBE ", b"NOTIFY ",
        b"PUBLISH ", b"INFO ", b"REFER ", b"MESSAGE ", b"UPDATE ",
    ];
    for method in METHODS {
        if data.starts_with(method) {
            return true;
        }
    }
    false
}

/// Split aggregated SIP messages in a single content blob.
/// Returns byte offsets where each message ends (exclusive).
/// If no aggregation detected, returns a single-element vec with the total length.
fn split_aggregated(content: &[u8]) -> Vec<usize> {
    if !is_sip_start(content) {
        return vec![content.len()];
    }

    let mut boundaries = Vec::new();
    let mut pos = 0;

    loop {
        let header_end = match CRLFCRLF.find(&content[pos..]) {
            Some(offset) => pos + offset,
            None => {
                boundaries.push(content.len());
                break;
            }
        };
        let body_start = header_end + 4; // past \r\n\r\n

        // Find Content-Length in this message's headers
        match find_content_length(&content[pos..]) {
            Some(cl) => {
                let msg_end = body_start + cl;
                if msg_end < content.len() && is_sip_start(&content[msg_end..]) {
                    boundaries.push(msg_end);
                    pos = msg_end;
                    continue;
                }
                // No more messages after this one
                boundaries.push(content.len());
                break;
            }
            None => {
                // No Content-Length — rest is this message
                boundaries.push(content.len());
                break;
            }
        }
    }

    boundaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Direction, Timestamp};

    fn make_frame(direction: Direction, transport: Transport, addr: &str, content: &[u8]) -> Vec<u8> {
        let dir_str = match direction {
            Direction::Recv => "recv",
            Direction::Sent => "sent",
        };
        let prep = match direction {
            Direction::Recv => "from",
            Direction::Sent => "to",
        };
        let transport_str = match transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Tls => "tls",
            Transport::Wss => "wss",
        };
        let header = format!(
            "{dir_str} {} bytes {prep} {transport_str}/{addr} at 00:00:00.000000:\n",
            content.len()
        );
        let mut data = header.into_bytes();
        data.extend_from_slice(content);
        data.extend_from_slice(b"\x0B\n");
        data
    }

    #[test]
    fn single_udp_message() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let data = make_frame(Direction::Recv, Transport::Udp, "1.1.1.1:5060", content);
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, content);
        assert_eq!(msgs[0].frame_count, 1);
        assert_eq!(msgs[0].transport, Transport::Udp);
    }

    #[test]
    fn tcp_reassembly_two_frames() {
        let part1 = b"NOTIFY sip:user@host SIP/2.0\r\n";
        let part2 = b"Content-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", part1);
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", part2));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].frame_count, 2);
        let mut expected = Vec::new();
        expected.extend_from_slice(part1);
        expected.extend_from_slice(part2);
        assert_eq!(msgs[0].content, expected);
    }

    #[test]
    fn direction_change_splits_messages() {
        let recv_content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let sent_content = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", recv_content);
        data.extend_from_slice(&make_frame(Direction::Sent, Transport::Tcp, "[::1]:5060", sent_content));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].direction, Direction::Recv);
        assert_eq!(msgs[1].direction, Direction::Sent);
    }

    #[test]
    fn address_change_splits_messages() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", content);
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tcp, "[::2]:5060", content));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert_eq!(msgs[1].address, "[::2]:5060");
    }

    #[test]
    fn udp_no_reassembly() {
        let content1 = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let content2 = b"OPTIONS sip:b SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Udp, "1.1.1.1:5060", content1);
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Udp, "1.1.1.1:5060", content2));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2, "UDP frames should not be reassembled");
        assert_eq!(msgs[0].frame_count, 1);
        assert_eq!(msgs[1].frame_count, 1);
    }

    #[test]
    fn aggregated_messages_split_by_content_length() {
        // Two SIP messages back-to-back in one frame
        let msg1 = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";
        let msg2 = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut combined = Vec::new();
        combined.extend_from_slice(msg1);
        combined.extend_from_slice(msg2);
        let data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", &combined);
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, msg1);
        assert_eq!(msgs[1].content, msg2);
    }

    #[test]
    fn find_content_length_standard() {
        let data = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(find_content_length(data), Some(42));
    }

    #[test]
    fn find_content_length_compact() {
        let data = b"NOTIFY sip:a SIP/2.0\r\nl: 42\r\n\r\n";
        assert_eq!(find_content_length(data), Some(42));
    }

    #[test]
    fn find_content_length_missing() {
        let data = b"NOTIFY sip:a SIP/2.0\r\nCSeq: 1 NOTIFY\r\n\r\n";
        assert_eq!(find_content_length(data), None);
    }

    #[test]
    fn is_sip_start_request() {
        assert!(is_sip_start(b"INVITE sip:user@host SIP/2.0\r\n"));
        assert!(is_sip_start(b"OPTIONS sip:user@host SIP/2.0\r\n"));
        assert!(is_sip_start(b"NOTIFY sip:user@host SIP/2.0\r\n"));
        assert!(is_sip_start(b"ACK sip:user@host SIP/2.0\r\n"));
    }

    #[test]
    fn is_sip_start_response() {
        assert!(is_sip_start(b"SIP/2.0 200 OK\r\n"));
        assert!(is_sip_start(b"SIP/2.0 100 Trying\r\n"));
    }

    #[test]
    fn is_sip_start_not_sip() {
        assert!(!is_sip_start(b"some random data"));
        assert!(!is_sip_start(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn split_aggregated_single_message() {
        let data = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";
        let splits = split_aggregated(data);
        assert_eq!(splits, vec![data.len()]);
    }

    #[test]
    fn split_aggregated_two_messages() {
        let msg1 = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";
        let msg2 = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut combined = Vec::new();
        combined.extend_from_slice(msg1);
        combined.extend_from_slice(msg2);
        let splits = split_aggregated(&combined);
        assert_eq!(splits, vec![msg1.len(), combined.len()]);
    }

    #[test]
    fn message_preserves_metadata() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let data = make_frame(Direction::Sent, Transport::Tls, "[2001:db8::1]:5061", content);
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Sent);
        assert_eq!(msgs[0].transport, Transport::Tls);
        assert_eq!(msgs[0].address, "[2001:db8::1]:5061");
        assert_eq!(
            msgs[0].timestamp,
            Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0
            }
        );
    }
}
