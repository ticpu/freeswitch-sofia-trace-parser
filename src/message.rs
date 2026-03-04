use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use memchr::memmem;
use tracing::{debug, trace, warn};

use crate::frame::{FrameIterator, ParseError};
use crate::types::{
    Direction, ParseStats, SipMessage, SkipTracking, Timestamp, Transport, UnparsedRegion,
};

static CRLF: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new(b"\r\n"));
static CRLFCRLF: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(b"\r\n\r\n"));

/// RFC 793 default TCP keepalive timeout.
/// Connection buffers inactive for longer than this are considered stale
/// and evicted to prevent unbounded memory growth when processing
/// multi-day dump file streams with ephemeral TLS source ports.
const STALE_TIMEOUT_SECS: u64 = 7200;

/// Level 2 streaming parser: reassembles TCP segments into complete SIP messages.
///
/// Wraps a [`FrameIterator`] and groups TCP frames by `(Direction, Address)`.
/// Messages are emitted when headers and Content-Length body bytes are fully
/// available. UDP frames pass through as-is (1:1 mapping).
///
/// Stale TCP connection buffers are evicted after 2 hours of inactivity to
/// maintain constant memory on multi-day dump streams.
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use freeswitch_sofia_trace_parser::MessageIterator;
///
/// let file = File::open("profile.dump").unwrap();
/// for msg in MessageIterator::new(file) {
///     let msg = msg.unwrap();
///     println!("{} {} {} ({} frames)",
///         msg.timestamp, msg.direction, msg.address, msg.frame_count);
/// }
/// ```
pub struct MessageIterator<R> {
    frames: FrameIterator<R>,
    buffers: HashMap<(Direction, String), ConnectionBuffer>,
    ready: VecDeque<SipMessage>,
    exhausted: bool,
    current_day: u32,
    last_time_secs: u32,
    last_sweep_abs_secs: u64,
}

struct ConnectionBuffer {
    transport: Transport,
    timestamp: Timestamp,
    content: Vec<u8>,
    frame_count: usize,
    last_seen_day: u32,
    last_seen_time_secs: u32,
}

impl<R: std::io::Read> MessageIterator<R> {
    /// Create a new message iterator reading from the given source.
    pub fn new(reader: R) -> Self {
        MessageIterator {
            frames: FrameIterator::new(reader),
            buffers: HashMap::new(),
            ready: VecDeque::new(),
            exhausted: false,
            current_day: 0,
            last_time_secs: 0,
            last_sweep_abs_secs: 0,
        }
    }

    /// Enable capturing of skipped bytes in the underlying [`FrameIterator`].
    pub fn capture_skipped(mut self, enable: bool) -> Self {
        self.frames = self.frames.capture_skipped(enable);
        self
    }

    /// Set the level of detail for unparsed region tracking.
    pub fn skip_tracking(mut self, tracking: SkipTracking) -> Self {
        self.frames = self.frames.skip_tracking(tracking);
        self
    }

    /// Borrow the accumulated parse statistics from the underlying frame parser.
    pub fn parse_stats(&self) -> &ParseStats {
        self.frames.stats()
    }

    /// Mutably borrow the parse statistics.
    pub fn parse_stats_mut(&mut self) -> &mut ParseStats {
        self.frames.stats_mut()
    }

    /// Take all accumulated unparsed regions, leaving the list empty.
    pub fn drain_unparsed(&mut self) -> Vec<UnparsedRegion> {
        self.frames.drain_unparsed()
    }

    fn update_time_tracking(&mut self, time_secs: u32) {
        if time_secs < self.last_time_secs && self.last_time_secs - time_secs > 43200 {
            self.current_day += 1;
            debug!(
                day = self.current_day,
                prev_secs = self.last_time_secs,
                curr_secs = time_secs,
                "detected day rollover"
            );
        }
        self.last_time_secs = time_secs;
    }

    fn current_abs_secs(&self) -> u64 {
        self.current_day as u64 * 86400 + self.last_time_secs as u64
    }

    fn sweep_stale_buffers(&mut self) {
        let current_abs = self.current_abs_secs();
        self.buffers.retain(|key, buf| {
            let buf_abs = buf.last_seen_day as u64 * 86400 + buf.last_seen_time_secs as u64;
            let elapsed = current_abs.saturating_sub(buf_abs);
            if elapsed > STALE_TIMEOUT_SECS {
                if buf.content.is_empty() {
                    trace!(
                        address = %key.1,
                        direction = %key.0,
                        elapsed_secs = elapsed,
                        "evicted empty stale connection buffer"
                    );
                } else {
                    warn!(
                        address = %key.1,
                        direction = %key.0,
                        elapsed_secs = elapsed,
                        pending_bytes = buf.content.len(),
                        "evicted stale connection buffer with incomplete data"
                    );
                }
                return false;
            }
            true
        });
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
        self.buffers.clear();
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

                    let time_secs = frame.timestamp.time_of_day_secs();
                    self.update_time_tracking(time_secs);

                    let current_abs = self.current_abs_secs();
                    if current_abs.saturating_sub(self.last_sweep_abs_secs) >= STALE_TIMEOUT_SECS {
                        self.sweep_stale_buffers();
                        self.last_sweep_abs_secs = current_abs;
                    }

                    let key = (frame.direction, frame.address);

                    let buf = match self.buffers.get_mut(&key) {
                        Some(buf) => buf,
                        None => self.buffers.entry(key.clone()).or_insert(ConnectionBuffer {
                            transport: frame.transport,
                            timestamp: frame.timestamp,
                            content: Vec::new(),
                            frame_count: 0,
                            last_seen_day: self.current_day,
                            last_seen_time_secs: time_secs,
                        }),
                    };

                    buf.last_seen_day = self.current_day;
                    buf.last_seen_time_secs = time_secs;

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

                    if buf.frame_count == 0 && buf.content.is_empty() {
                        self.buffers.remove(&key);
                    }

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
            // Drain leading whitespace (CRLF padding, bare LF keep-alives, etc.)
            let ws_len = buf
                .content
                .iter()
                .position(|&b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
                .unwrap_or(buf.content.len());

            if ws_len > 0 {
                if ws_len == buf.content.len() {
                    trace!(
                        bytes = ws_len,
                        address = %key.1,
                        "drained transport whitespace"
                    );
                    buf.content.clear();
                    break;
                }
                if is_sip_start(&buf.content[ws_len..]) {
                    trace!(bytes = ws_len, "drained inter-message whitespace padding");
                    buf.content.drain(..ws_len);
                    continue;
                }
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

        let remaining = buf.content.split_off(msg_end);
        let msg_content = std::mem::replace(&mut buf.content, remaining);

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
    fn tcp_reassembly_interleaved_different_addresses() {
        // Two different addresses both sending multi-frame messages,
        // frames arriving interleaved:
        //   Frame 1: recv from A (partial INVITE)
        //   Frame 2: recv from B (partial NOTIFY)
        //   Frame 3: recv from A (rest of INVITE — completes A)
        //   Frame 4: recv from B (rest of NOTIFY — completes B)
        let a_part1 = b"INVITE sip:user@host SIP/2.0\r\n";
        let a_part2 = b"Content-Length: 3\r\n\r\nSDP";
        let b_part1 = b"NOTIFY sip:user@host SIP/2.0\r\n";
        let b_part2 = b"Content-Length: 4\r\n\r\nBODY";

        let mut data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", a_part1);
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::2]:5060",
            b_part1,
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            a_part2,
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            "[::2]:5060",
            b_part2,
        ));

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(msgs.len(), 2);

        // INVITE from [::1] completes first (frame 3 arrives before frame 4)
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert_eq!(msgs[0].frame_count, 2);
        let mut expected_a = Vec::new();
        expected_a.extend_from_slice(a_part1);
        expected_a.extend_from_slice(a_part2);
        assert_eq!(msgs[0].content, expected_a);

        // NOTIFY from [::2] completes second
        assert_eq!(msgs[1].address, "[::2]:5060");
        assert_eq!(msgs[1].frame_count, 2);
        let mut expected_b = Vec::new();
        expected_b.extend_from_slice(b_part1);
        expected_b.extend_from_slice(b_part2);
        assert_eq!(msgs[1].content, expected_b);
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
            last_seen_day: 0,
            last_seen_time_secs: 0,
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
            last_seen_day: 0,
            last_seen_time_secs: 0,
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
            last_seen_day: 0,
            last_seen_time_secs: 0,
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
            last_seen_day: 0,
            last_seen_time_secs: 0,
        };
        let msgs = extract_complete(&mut buf, &key);
        assert!(msgs.is_empty(), "should wait for headers to complete");
    }

    #[test]
    fn tcp_body_split_across_five_frames() {
        // Simulate REQUEST.md scenario: NOTIFY with Content-Length: 6424
        // body split across 5 TCP frames (like NG9-1-1 abandoned call JSON)
        let body_len: usize = 6424;
        let body: Vec<u8> = (0..body_len).map(|i| b'A' + (i % 26) as u8).collect();

        let mut headers = Vec::new();
        headers.extend_from_slice(b"NOTIFY sip:user@host SIP/2.0\r\n");
        headers
            .extend_from_slice(b"Via: SIP/2.0/TCP [2001:4958:10:11::6]:45538;branch=z9hG4bK-1\r\n");
        headers.extend_from_slice(b"Call-ID: fragmented-notify@host\r\n");
        headers.extend_from_slice(b"CSeq: 1 NOTIFY\r\n");
        headers.extend_from_slice(
            b"Content-Type: application/emergencyCallData.AbandonedCall+json\r\n",
        );
        headers.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
        headers.extend_from_slice(b"\r\n");

        let mut full_content = headers.clone();
        full_content.extend_from_slice(&body);

        // Split into 5 frames like real TCP segments
        let frame1_len = 1500.min(full_content.len());
        let remaining = &full_content[frame1_len..];
        let frame2_len = 1428.min(remaining.len());
        let remaining = &remaining[frame2_len..];
        let frame3_len = 1428.min(remaining.len());
        let remaining = &remaining[frame3_len..];
        let frame4_len = 1428.min(remaining.len());
        let remaining = &remaining[frame4_len..];
        let frame5_len = remaining.len();

        let addr = "[2001:4958:10:11::6]:45538";
        let mut data = make_frame(
            Direction::Recv,
            Transport::Tcp,
            addr,
            &full_content[..frame1_len],
        );
        let mut offset = frame1_len;
        for len in [frame2_len, frame3_len, frame4_len, frame5_len] {
            data.extend_from_slice(&make_frame(
                Direction::Recv,
                Transport::Tcp,
                addr,
                &full_content[offset..offset + len],
            ));
            offset += len;
        }
        assert_eq!(offset, full_content.len());

        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(
            msgs.len(),
            1,
            "should produce exactly one reassembled message"
        );
        assert_eq!(msgs[0].frame_count, 5, "should track all 5 frames");
        assert_eq!(
            msgs[0].content, full_content,
            "content should be fully reassembled"
        );
        assert_eq!(msgs[0].direction, Direction::Recv);
        assert_eq!(msgs[0].address, addr);
    }

    #[test]
    fn parse_stats_delegates() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let data = make_frame(Direction::Recv, Transport::Udp, "1.1.1.1:5060", content);
        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<_> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(msgs.len(), 1);
        let stats = iter.parse_stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        assert_eq!(stats.bytes_skipped, 0);
    }

    #[test]
    fn tcp_body_split_parsed_message() {
        // Same scenario but verified through Level 3 (ParsedSipMessage)
        let body_len: usize = 6424;
        let body: Vec<u8> = (0..body_len).map(|i| b'A' + (i % 26) as u8).collect();

        let mut headers = Vec::new();
        headers.extend_from_slice(b"NOTIFY sip:user@host SIP/2.0\r\n");
        headers.extend_from_slice(b"Call-ID: fragmented-parsed@host\r\n");
        headers.extend_from_slice(b"CSeq: 1 NOTIFY\r\n");
        headers.extend_from_slice(
            b"Content-Type: application/emergencyCallData.AbandonedCall+json\r\n",
        );
        headers.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
        headers.extend_from_slice(b"\r\n");

        let mut full_content = headers.clone();
        full_content.extend_from_slice(&body);

        // Split into 3 frames
        let split1 = 1500.min(full_content.len());
        let split2 = (split1 + 3000).min(full_content.len());

        let addr = "[2001:db8::1]:5060";
        let mut data = make_frame(
            Direction::Recv,
            Transport::Tcp,
            addr,
            &full_content[..split1],
        );
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            addr,
            &full_content[split1..split2],
        ));
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tcp,
            addr,
            &full_content[split2..],
        ));

        let parsed: Vec<crate::types::ParsedSipMessage> =
            crate::sip::ParsedMessageIterator::new(&data[..])
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

        assert_eq!(parsed.len(), 1, "should produce one parsed message");
        assert_eq!(parsed[0].content_length(), Some(body_len));
        assert_eq!(parsed[0].body.len(), body_len, "body should be complete");
        assert_eq!(parsed[0].body, body, "body content should match");
        assert_eq!(parsed[0].frame_count, 3);
        assert_eq!(parsed[0].method(), Some("NOTIFY"));
    }

    #[test]
    fn tls_keepalive_single_lf_drained() {
        let data = make_frame(Direction::Recv, Transport::Tls, "[10.0.0.1]:5061", b"\n");
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 0, "keep-alive \\n should produce no messages");
    }

    #[test]
    fn tls_keepalive_multiple_lf_drained() {
        let addr = "[10.0.0.1]:5061";
        let mut data = make_frame(Direction::Recv, Transport::Tls, addr, b"\n");
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tls, addr, b"\n"));
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tls, addr, b"\n"));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            msgs.len(),
            0,
            "multiple keep-alive \\n should produce no messages"
        );
    }

    #[test]
    fn tls_keepalive_interleaved_with_sip() {
        let addr = "[10.0.0.1]:5061";
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tls, addr, b"\n");
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tls, addr, sip));
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tls, addr, b"\n"));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1, "only the SIP message should be emitted");
        assert_eq!(msgs[0].content, sip);
    }

    #[test]
    fn tls_bare_lf_before_sip_start() {
        let addr = "[10.0.0.1]:5061";
        let sip_part1 = b"\nOPTIONS sip:host SIP/2.0\r\n";
        let sip_part2 = b"Content-Length: 0\r\n\r\n";
        let mut data = make_frame(Direction::Recv, Transport::Tls, addr, sip_part1);
        data.extend_from_slice(&make_frame(
            Direction::Recv,
            Transport::Tls,
            addr,
            sip_part2,
        ));
        let msgs: Vec<SipMessage> = MessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(msgs.len(), 1, "SIP after bare LF should be extracted");
        assert!(
            msgs[0].content.starts_with(b"OPTIONS"),
            "message should start with SIP method, not \\n"
        );
    }

    fn make_frame_at(
        direction: Direction,
        transport: Transport,
        addr: &str,
        content: &[u8],
        timestamp: &str,
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
            "{dir_str} {} bytes {prep} {transport_str}/{addr} at {timestamp}:\n",
            content.len()
        );
        let mut data = header.into_bytes();
        data.extend_from_slice(content);
        data.extend_from_slice(b"\x0B\n");
        data
    }

    #[test]
    fn empty_buffer_removed_after_complete_message() {
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let addr_a = "[::1]:5060";
        let addr_b = "[::2]:5060";

        let mut data = make_frame(Direction::Recv, Transport::Tcp, addr_a, sip);
        data.extend_from_slice(&make_frame(Direction::Recv, Transport::Tcp, addr_b, sip));

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(
            iter.buffers.is_empty(),
            "all buffers should be removed after complete messages are extracted"
        );
    }

    #[test]
    fn stale_buffer_evicted_after_timeout() {
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let partial = b"INVITE sip:host SIP/2.0\r\n";

        let mut data = Vec::new();
        // Partial frame from stale addr at 10:00:00
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tls,
            "[::99]:44444",
            partial,
            "2026-02-16 10:00:00.000000",
        ));
        // Complete msg from another addr at 12:00:01 (>2h later, triggers sweep)
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tls,
            "[::1]:5060",
            sip,
            "2026-02-16 12:00:01.000000",
        ));

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(msgs.len(), 1, "should produce the complete message");
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert!(
            iter.buffers.is_empty(),
            "stale buffer for [::99]:44444 should have been evicted"
        );
    }

    #[test]
    fn day_rollover_detection_with_time_only() {
        let sip = b"OPTIONS sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let partial = b"INVITE sip:host SIP/2.0\r\n";

        let mut data = Vec::new();
        // Partial frame at 23:59:00
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tcp,
            "[::99]:44444",
            partial,
            "23:59:00.000000",
        ));
        // Complete msg at 02:00:01 (next day — rollover detected, >2h from 23:59)
        data.extend_from_slice(&make_frame_at(
            Direction::Recv,
            Transport::Tcp,
            "[::1]:5060",
            sip,
            "02:00:01.000000",
        ));

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].address, "[::1]:5060");
        assert_eq!(iter.current_day, 1, "should have detected one day rollover");
        assert!(
            iter.buffers.is_empty(),
            "stale buffer should have been evicted after day rollover"
        );
    }

    #[test]
    fn flush_all_clears_buffers() {
        let partial = b"INVITE sip:host SIP/2.0\r\n";
        let data = make_frame(Direction::Recv, Transport::Tcp, "[::1]:5060", partial);

        let mut iter = MessageIterator::new(&data[..]);
        let msgs: Vec<SipMessage> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(msgs.len(), 1, "partial should be flushed at EOF");
        assert!(
            iter.buffers.is_empty(),
            "flush_all should clear the HashMap"
        );
    }
}
