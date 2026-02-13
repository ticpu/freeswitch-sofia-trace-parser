use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use memchr::memmem;
use tracing::{debug, trace, warn};

use crate::frame::{FrameIterator, ParseError};
use crate::types::{Direction, SipMessage, Timestamp, Transport};

static CRLF: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new(b"\r\n"));
static CRLFCRLF: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(b"\r\n\r\n"));

pub struct MessageIterator<R> {
    frames: FrameIterator<R>,
    buffers: HashMap<(Direction, String), ConnectionBuffer>,
    ready: VecDeque<SipMessage>,
    exhausted: bool,
}

struct ConnectionBuffer {
    transport: Transport,
    timestamp: Timestamp,
    content: Vec<u8>,
    frame_count: usize,
}

impl<R: std::io::Read> MessageIterator<R> {
    pub fn new(reader: R) -> Self {
        MessageIterator {
            frames: FrameIterator::new(reader),
            buffers: HashMap::new(),
            ready: VecDeque::new(),
            exhausted: false,
        }
    }

    fn flush_all(&mut self) {
        let keys: Vec<_> = self.buffers.keys().cloned().collect();
        for key in keys {
            if let Some(buf) = self.buffers.get_mut(&key) {
                let msgs = extract_complete(buf, &key);
                self.ready.extend(msgs);

                if !buf.content.is_empty() {
                    let content = std::mem::take(&mut buf.content);
                    self.ready.push_back(SipMessage {
                        direction: key.0,
                        transport: buf.transport,
                        address: key.1.clone(),
                        timestamp: buf.timestamp,
                        content,
                        frame_count: buf.frame_count,
                    });
                    buf.frame_count = 0;
                }
            }
        }
    }
}

impl<R: std::io::Read> Iterator for MessageIterator<R> {
    type Item = Result<SipMessage, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(msg) = self.ready.pop_front() {
            return Some(Ok(msg));
        }

        if self.exhausted {
            return None;
        }

        loop {
            match self.frames.next() {
                Some(Ok(frame)) => {
                    if frame.transport == Transport::Udp {
                        return Some(Ok(SipMessage {
                            direction: frame.direction,
                            transport: frame.transport,
                            address: frame.address,
                            timestamp: frame.timestamp,
                            content: frame.content,
                            frame_count: 1,
                        }));
                    }

                    let key = (frame.direction, frame.address.clone());

                    let buf = self
                        .buffers
                        .entry(key.clone())
                        .or_insert_with(|| ConnectionBuffer {
                            transport: frame.transport,
                            timestamp: frame.timestamp,
                            content: Vec::new(),
                            frame_count: 0,
                        });

                    if buf.content.is_empty() {
                        buf.timestamp = frame.timestamp;
                    }

                    trace!(
                        frame = buf.frame_count + 1,
                        bytes = frame.content.len(),
                        address = %key.1,
                        "buffering TCP frame"
                    );

                    buf.content.extend_from_slice(&frame.content);
                    buf.frame_count += 1;

                    let msgs = extract_complete(buf, &key);
                    self.ready.extend(msgs);

                    if let Some(msg) = self.ready.pop_front() {
                        return Some(Ok(msg));
                    }
                }
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    self.exhausted = true;
                    self.flush_all();
                    return self.ready.pop_front().map(Ok);
                }
            }
        }
    }
}

/// Extract complete SIP messages from a connection buffer.
/// Messages are complete when we find headers (\r\n\r\n) and have
/// Content-Length bytes of body available.
fn extract_complete(buf: &mut ConnectionBuffer, key: &(Direction, String)) -> Vec<SipMessage> {
    let mut messages = Vec::new();

    loop {
        if buf.content.is_empty() {
            break;
        }

        // Skip non-SIP prefix (body fragments from incomplete prior messages)
        if !is_sip_start(&buf.content) {
            // Skip leading CRLF (inter-message padding)
            let mut crlf_skip = 0;
            while crlf_skip + 1 < buf.content.len()
                && buf.content[crlf_skip] == b'\r'
                && buf.content[crlf_skip + 1] == b'\n'
            {
                crlf_skip += 2;
            }
            if crlf_skip > 0
                && crlf_skip < buf.content.len()
                && is_sip_start(&buf.content[crlf_skip..])
            {
                trace!(
                    skipped_bytes = crlf_skip,
                    "skipped inter-message CRLF padding"
                );
                buf.content.drain(..crlf_skip);
                continue;
            }

            match find_sip_start(&buf.content) {
                Some(offset) if offset > 0 => {
                    warn!(
                        skipped_bytes = offset,
                        address = %key.1,
                        "skipped non-SIP prefix in TCP buffer"
                    );
                    buf.content.drain(..offset);
                    continue;
                }
                _ => break, // No SIP start found, wait for more data
            }
        }

        // Find header/body boundary
        let header_end = match CRLFCRLF.find(&buf.content) {
            Some(offset) => offset,
            None => break, // Headers incomplete, wait for more data
        };
        let body_start = header_end + 4;

        let msg_end = match find_content_length(&buf.content) {
            Some(cl) => {
                let end = body_start + cl;
                if end > buf.content.len() {
                    break; // Body incomplete, wait for more data
                }
                end
            }
            None => body_start, // No CL = no body (RFC 3261 Section 18.3)
        };

        let msg_content: Vec<u8> = buf.content.drain(..msg_end).collect();

        // Skip trailing CRLF between messages
        while buf.content.len() >= 2 && buf.content[0] == b'\r' && buf.content[1] == b'\n' {
            buf.content.drain(..2);
        }

        let frame_count = if messages.is_empty() {
            buf.frame_count
        } else {
            0
        };

        if frame_count > 1 {
            debug!(
                frame_count,
                bytes = msg_content.len(),
                address = %key.1,
                "extracted reassembled TCP message"
            );
        }

        messages.push(SipMessage {
            direction: key.0,
            transport: buf.transport,
            address: key.1.clone(),
            timestamp: buf.timestamp,
            content: msg_content,
            frame_count,
        });

        buf.frame_count = 0;
    }

    messages
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
    if !line[..name.len()].eq_ignore_ascii_case(name) {
        return None;
    }
    if line[name.len()] != b':' {
        return None;
    }
    Some(trim_bytes(&line[name.len() + 1..]))
}

fn extract_compact_header_value(line: &[u8], compact: u8) -> Option<&[u8]> {
    if line.len() < 2 {
        return None;
    }
    if line[0] != compact || line[1] != b':' {
        return None;
    }
    Some(trim_bytes(&line[2..]))
}

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(start, |p| p + 1);
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
    const METHODS: &[&[u8]] = &[
        b"INVITE ",
        b"ACK ",
        b"BYE ",
        b"CANCEL ",
        b"OPTIONS ",
        b"REGISTER ",
        b"PRACK ",
        b"SUBSCRIBE ",
        b"NOTIFY ",
        b"PUBLISH ",
        b"INFO ",
        b"REFER ",
        b"MESSAGE ",
        b"UPDATE ",
    ];
    for method in METHODS {
        if data.starts_with(method) {
            return true;
        }
    }
    false
}

/// Scan for the first SIP message start at a CRLF boundary within data.
fn find_sip_start(data: &[u8]) -> Option<usize> {
    if is_sip_start(data) {
        return Some(0);
    }
    let mut pos = 0;
    while let Some(offset) = CRLF.find(&data[pos..]) {
        let candidate = pos + offset + 2;
        if candidate >= data.len() {
            break;
        }
        if is_sip_start(&data[candidate..]) {
            return Some(candidate);
        }
        pos = candidate;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Direction;

    fn make_frame(
        direction: Direction,
        transport: Transport,
        addr: &str,
        content: &[u8],
    ) -> Vec<u8> {
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
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            part2,
        ));
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
    fn tcp_reassembly_across_interleaved_frames() {
        // Frame 1: recv from A (partial INVITE)
        // Frame 2: sent to A (response on same connection — interrupts)
        // Frame 3: recv from A (rest of INVITE)
        let part1 = b"INVITE sip:user@host SIP/2.0\r\n";
        let part2 = b"Content-Length: 3\r\n\r\nSDP";
        let response = b"SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n";

        let mut data = make_frame(Direction::Recv, Transport::Tcp, "10.0.0.1:5060", part1);
        data.extend_from_slice(&make_frame(
            Direction::Sent,
            Transport::Tcp,
            "10.0.0.1:5060",
            response,
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "10.0.0.1:5060",
            part2,
        ));

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(msgs.len(), 2);

        // 100 Trying completes first (single frame)
        let trying = &msgs[0];
        assert_eq!(trying.direction, Direction::Sent);
        assert_eq!(trying.content, response);

        // INVITE completes when frame 3 arrives (reassembled from frames 1+3)
        let invite = &msgs[1];
        assert_eq!(invite.direction, Direction::Recv);
        let mut expected_invite = Vec::new();
        expected_invite.extend_from_slice(part1);
        expected_invite.extend_from_slice(part2);
        assert_eq!(invite.content, expected_invite);
    }

    #[test]
    fn direction_change_splits_messages() {
        let recv_content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let sent_content = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", recv_content);
        data.extend_from_slice(&make_frame(
            Direction::Sent,
            Transport::Tcp,
            "[::1]:5060",
            sent_content,
        ));
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
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::2]:5060",
            content,
        ));
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
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Udp,
            "1.1.1.1:5060",
            content2,
        ));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 2, "UDP frames should not be reassembled");
        assert_eq!(msgs[0].frame_count, 1);
        assert_eq!(msgs[1].frame_count, 1);
    }

    #[test]
    fn aggregated_messages_split_by_content_length() {
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
    fn find_sip_start_at_beginning() {
        let data = b"INVITE sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_sip_start(data), Some(0));
    }

    #[test]
    fn find_sip_start_after_prefix() {
        let data = b"</xml>\r\nNOTIFY sip:user@host SIP/2.0\r\n";
        assert_eq!(find_sip_start(data), Some(8));
    }

    #[test]
    fn find_sip_start_none() {
        let data = b"no SIP here at all";
        assert_eq!(find_sip_start(data), None);
    }

    #[test]
    fn message_preserves_metadata() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let data = make_frame(
            Direction::Sent,
            Transport::Tls,
            "[2001:db8::1]:5061",
            content,
        );
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

    #[test]
    fn extract_handles_crlf_between_messages() {
        let msg1 = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";
        let msg2 = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(msg1);
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(msg2);

        let key = (Direction::Recv, "[::1]:5060".to_string());
        let mut buf = ConnectionBuffer {
            transport: Transport::Tcp,
            timestamp: Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content,
            frame_count: 1,
        };
        let msgs = extract_complete(&mut buf, &key);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, msg1);
        assert_eq!(msgs[1].content, msg2);
    }

    #[test]
    fn extract_skips_non_sip_prefix() {
        let prefix = b"</conference-info>\r\n";
        let msg = b"NOTIFY sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(prefix);
        content.extend_from_slice(msg);

        let key = (Direction::Recv, "[::1]:5060".to_string());
        let mut buf = ConnectionBuffer {
            transport: Transport::Tcp,
            timestamp: Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content,
            frame_count: 1,
        };
        let msgs = extract_complete(&mut buf, &key);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, msg);
    }

    #[test]
    fn extract_waits_for_incomplete_body() {
        // Headers complete but body is missing
        let content = b"INVITE sip:a SIP/2.0\r\nContent-Length: 100\r\n\r\npartial".to_vec();

        let key = (Direction::Recv, "[::1]:5060".to_string());
        let mut buf = ConnectionBuffer {
            transport: Transport::Tcp,
            timestamp: Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content,
            frame_count: 1,
        };
        let msgs = extract_complete(&mut buf, &key);
        assert!(msgs.is_empty(), "should wait for body to complete");
        assert!(!buf.content.is_empty(), "buffer should retain data");
    }

    #[test]
    fn extract_waits_for_incomplete_headers() {
        // Headers not complete (no \r\n\r\n)
        let content = b"INVITE sip:a SIP/2.0\r\nContent-Length: 0\r\n".to_vec();

        let key = (Direction::Recv, "[::1]:5060".to_string());
        let mut buf = ConnectionBuffer {
            transport: Transport::Tcp,
            timestamp: Timestamp::TimeOnly {
                hour: 0,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content,
            frame_count: 1,
        };
        let msgs = extract_complete(&mut buf, &key);
        assert!(msgs.is_empty(), "should wait for headers to complete");
    }
}
