use std::borrow::Cow;
use std::fmt;

/// Why a region of the input stream was not parsed into a frame.
///
/// Every byte in the input is either parsed or classified with one of these
/// reasons, enabling byte-level coverage accounting via [`ParseStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Truncated frame at the start of a file, typically from logrotate
    /// cutting mid-write. Capped at 65,535 bytes.
    PartialFirstFrame,
    /// Skip region exceeds 65,535 bytes at file start, indicating the input
    /// is not a dump file (e.g., compressed or binary data).
    OversizedFrame,
    /// Unrecoverable bytes skipped between valid frames mid-stream.
    MidStreamSkip,
    /// Logrotate wrote a partial frame tail at the start of the new file.
    /// Detected by the `\r\n\r\n\x0B\n` suffix pattern.
    ReplayedFrame,
    /// Frame at EOF with fewer content bytes than declared in the header.
    IncompleteFrame,
    /// Data starts with `recv`/`sent` but fails frame header parsing.
    InvalidHeader,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkipReason::PartialFirstFrame => f.write_str("partial first frame"),
            SkipReason::OversizedFrame => f.write_str("oversized frame"),
            SkipReason::MidStreamSkip => f.write_str("mid-stream skip"),
            SkipReason::ReplayedFrame => f.write_str("replayed frame (logrotate)"),
            SkipReason::IncompleteFrame => f.write_str("incomplete frame"),
            SkipReason::InvalidHeader => f.write_str("invalid header"),
        }
    }
}

/// Controls how much detail the parser records about unparsed regions.
///
/// Defaults to `CountOnly` for constant-memory operation. Higher levels
/// allocate per-region and should only be enabled for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipTracking {
    /// Track only `bytes_read` and `bytes_skipped` counters. No allocation.
    CountOnly,
    /// Record offset, length, and reason for each unparsed region.
    TrackRegions,
    /// Like `TrackRegions`, but also capture the skipped bytes themselves.
    CaptureData,
}

/// A contiguous region of the input that was not parsed into a frame.
#[derive(Debug, Clone)]
pub struct UnparsedRegion {
    /// Byte offset from the start of the input stream.
    pub offset: u64,
    /// Number of bytes in this region.
    pub length: u64,
    /// Why this region was skipped.
    pub reason: SkipReason,
    /// The raw bytes, populated only when [`SkipTracking::CaptureData`] is enabled.
    pub data: Option<Vec<u8>>,
}

/// Byte-level parse coverage statistics.
///
/// Available from all three iterator levels via `stats()` or `parse_stats()`.
/// Every byte consumed from the reader is accounted for as either parsed
/// (`bytes_read - bytes_skipped`) or skipped (`bytes_skipped`).
#[derive(Debug, Default, Clone)]
pub struct ParseStats {
    /// Total bytes consumed from the reader.
    pub bytes_read: u64,
    /// Bytes that were skipped (not parsed into frames).
    pub bytes_skipped: u64,
    /// Detailed unparsed region records. Only populated when
    /// [`SkipTracking`] is `TrackRegions` or `CaptureData`.
    pub unparsed_regions: Vec<UnparsedRegion>,
}

impl ParseStats {
    /// Take all accumulated unparsed regions, leaving the list empty.
    pub fn drain_regions(&mut self) -> Vec<UnparsedRegion> {
        std::mem::take(&mut self.unparsed_regions)
    }
}

/// Whether a frame was received or sent by FreeSWITCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Received from the network.
    Recv,
    /// Sent to the network.
    Sent,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Recv => f.write_str("recv"),
            Direction::Sent => f.write_str("sent"),
        }
    }
}

impl Direction {
    /// Returns `"from"` for `Recv`, `"to"` for `Sent`.
    pub fn preposition(&self) -> &'static str {
        match self {
            Direction::Recv => "from",
            Direction::Sent => "to",
        }
    }
}

/// SIP transport protocol as reported in the frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Transport Layer Security.
    Tls,
    /// WebSocket Secure (RFC 7118).
    Wss,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Tcp => f.write_str("tcp"),
            Transport::Udp => f.write_str("udp"),
            Transport::Tls => f.write_str("tls"),
            Transport::Wss => f.write_str("wss"),
        }
    }
}

/// Frame timestamp, either time-only or full date+time.
///
/// Older FreeSWITCH versions write `HH:MM:SS.usec`, newer versions write
/// `YYYY-MM-DD HH:MM:SS.usec`. Both formats are supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timestamp {
    /// `HH:MM:SS.usec` — no date component.
    TimeOnly {
        /// Hour (0-23).
        hour: u8,
        /// Minute (0-59).
        min: u8,
        /// Second (0-59).
        sec: u8,
        /// Microseconds (0-999999).
        usec: u32,
    },
    /// `YYYY-MM-DD HH:MM:SS.usec` — full date and time.
    DateTime {
        /// Year.
        year: u16,
        /// Month (1-12).
        month: u8,
        /// Day (1-31).
        day: u8,
        /// Hour (0-23).
        hour: u8,
        /// Minute (0-59).
        min: u8,
        /// Second (0-59).
        sec: u8,
        /// Microseconds (0-999999).
        usec: u32,
    },
}

impl Timestamp {
    /// Seconds since midnight, ignoring microseconds.
    pub fn time_of_day_secs(&self) -> u32 {
        let (h, m, s) = match self {
            Timestamp::TimeOnly { hour, min, sec, .. } => (*hour, *min, *sec),
            Timestamp::DateTime { hour, min, sec, .. } => (*hour, *min, *sec),
        };
        h as u32 * 3600 + m as u32 * 60 + s as u32
    }

    /// Tuple suitable for chronological ordering.
    /// `TimeOnly` timestamps sort before any `DateTime` (year/month/day = 0).
    pub fn sort_key(&self) -> (u16, u8, u8, u8, u8, u8, u32) {
        match self {
            Timestamp::TimeOnly {
                hour,
                min,
                sec,
                usec,
            } => (0, 0, 0, *hour, *min, *sec, *usec),
            Timestamp::DateTime {
                year,
                month,
                day,
                hour,
                min,
                sec,
                usec,
            } => (*year, *month, *day, *hour, *min, *sec, *usec),
        }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Timestamp::TimeOnly {
                hour,
                min,
                sec,
                usec,
            } => write!(f, "{hour:02}:{min:02}:{sec:02}.{usec:06}"),
            Timestamp::DateTime {
                year,
                month,
                day,
                hour,
                min,
                sec,
                usec,
            } => write!(
                f,
                "{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}.{usec:06}"
            ),
        }
    }
}

/// A single frame from the dump file (Level 1 output).
///
/// Each frame corresponds to one `send()` or `recv()` call logged by
/// `mod_sofia`. The `byte_count` field is the value FreeSWITCH wrote in the
/// header; `content` is the actual payload between boundaries.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Whether this frame was received or sent.
    pub direction: Direction,
    /// Byte count declared in the frame header.
    pub byte_count: usize,
    /// Transport protocol.
    pub transport: Transport,
    /// Remote address as `ip:port` (e.g., `"10.0.0.1:5060"`).
    pub address: String,
    /// When this frame was logged.
    pub timestamp: Timestamp,
    /// Raw frame payload.
    pub content: Vec<u8>,
}

/// A reassembled SIP message (Level 2 output).
///
/// For TCP, consecutive frames from the same connection are concatenated and
/// split by Content-Length. For UDP, each frame becomes one message (1:1).
#[derive(Debug, Clone)]
pub struct SipMessage {
    /// Whether this message was received or sent.
    pub direction: Direction,
    /// Transport protocol.
    pub transport: Transport,
    /// Remote address as `ip:port`.
    pub address: String,
    /// Timestamp of the first frame in this message.
    pub timestamp: Timestamp,
    /// Reassembled message bytes (headers + body).
    pub content: Vec<u8>,
    /// Number of Level 1 frames that were reassembled into this message.
    pub frame_count: usize,
}

/// SIP request or response first line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessageType {
    /// `METHOD uri SIP/2.0`
    Request {
        /// SIP method (e.g., `"INVITE"`, `"BYE"`).
        method: String,
        /// Request URI.
        uri: String,
    },
    /// `SIP/2.0 code reason`
    Response {
        /// Status code (e.g., 200, 404).
        code: u16,
        /// Reason phrase (e.g., `"OK"`, `"Not Found"`).
        reason: String,
    },
}

impl fmt::Display for SipMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipMessageType::Request { method, uri } => write!(f, "{method} {uri}"),
            SipMessageType::Response { code, reason } => write!(f, "{code} {reason}"),
        }
    }
}

impl SipMessageType {
    /// Short description: the method name for requests, `"code reason"` for responses.
    pub fn summary(&self) -> Cow<'_, str> {
        match self {
            SipMessageType::Request { method, .. } => Cow::Borrowed(method),
            SipMessageType::Response { code, reason } => Cow::Owned(format!("{code} {reason}")),
        }
    }
}

/// A fully parsed SIP message (Level 3 output).
///
/// Provides typed access to the request/response line, headers, and body.
/// For JSON content types, [`body_text()`](Self::body_text) unescapes RFC 8259
/// string sequences. For multipart bodies, [`body_parts()`](Self::body_parts)
/// splits into individual MIME parts.
#[derive(Debug, Clone)]
pub struct ParsedSipMessage {
    /// Whether this message was received or sent.
    pub direction: Direction,
    /// Transport protocol.
    pub transport: Transport,
    /// Remote address as `ip:port`.
    pub address: String,
    /// When this message was logged.
    pub timestamp: Timestamp,
    /// Parsed request or response first line.
    pub message_type: SipMessageType,
    /// Headers in wire order as `(name, value)` pairs. Names preserve
    /// original casing; lookups are case-insensitive.
    pub headers: Vec<(String, String)>,
    /// Raw body bytes after the `\r\n\r\n` header terminator.
    pub body: Vec<u8>,
    /// Number of Level 1 frames that were reassembled into this message.
    pub frame_count: usize,
}

/// A `message/sipfrag` body (RFC 3420): any prefix of a SIP message.
///
/// Unlike [`ParsedSipMessage`], every element is optional — a fragment may
/// carry a start line, headers, a body, or any combination, and needs no
/// trailing CRLF. It has no transport metadata of its own; that belongs to
/// the message carrying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipFragment {
    /// Request or status line, when the fragment begins with one.
    pub message_type: Option<SipMessageType>,
    /// Headers in wire order as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Body bytes after the `\r\n\r\n` terminator, empty when absent.
    pub body: Vec<u8>,
}

impl SipFragment {
    /// Case-insensitive header lookup, first match in wire order. Compact forms
    /// are not resolved: ask for the name the fragment is expected to carry.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A single part from a multipart MIME body.
#[derive(Debug, Clone)]
pub struct MimePart {
    /// MIME part headers (e.g., Content-Type, Content-ID).
    pub headers: Vec<(String, String)>,
    /// Part body bytes.
    pub body: Vec<u8>,
}

impl MimePart {
    /// Returns the Content-Type header value, if present.
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, v)| v.as_str())
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the Content-ID header value, if present.
    pub fn content_id(&self) -> Option<&str> {
        self.header_value("Content-ID")
    }

    /// Returns the Content-Disposition header value, if present.
    pub fn content_disposition(&self) -> Option<&str> {
        self.header_value("Content-Disposition")
    }

    /// Returns the Content-Transfer-Encoding header value, if present. A value
    /// the caller does not recognize means the part's bytes are not what its
    /// media type describes.
    pub fn content_transfer_encoding(&self) -> Option<&str> {
        self.header_value("Content-Transfer-Encoding")
    }
}

impl ParsedSipMessage {
    /// Returns the Call-ID header value. Checks both `Call-ID` and
    /// the compact form `i`.
    pub fn call_id(&self) -> Option<&str> {
        self.header_value("Call-ID")
            .or_else(|| self.header_value("i"))
    }

    /// Returns the Content-Type header value. Checks both `Content-Type` and
    /// the compact form `c`.
    pub fn content_type(&self) -> Option<&str> {
        self.header_value("Content-Type")
            .or_else(|| self.header_value("c"))
    }

    /// Returns the Content-Length header value as `usize`. Checks both
    /// `Content-Length` and the compact form `l`.
    pub fn content_length(&self) -> Option<usize> {
        self.header_value("Content-Length")
            .or_else(|| self.header_value("l"))
            .and_then(|v| v.trim().parse().ok())
    }

    /// Returns the CSeq header value (e.g., `"1 INVITE"`).
    pub fn cseq(&self) -> Option<&str> {
        self.header_value("CSeq")
    }

    /// Returns the SIP method: from the request line for requests,
    /// or from the CSeq header for responses.
    pub fn method(&self) -> Option<&str> {
        match &self.message_type {
            SipMessageType::Request { method, .. } => Some(method),
            SipMessageType::Response { .. } => {
                self.cseq().and_then(|cs| cs.split_whitespace().nth(1))
            }
        }
    }

    /// Raw body bytes interpreted as UTF-8 (lossy). No processing is applied
    /// regardless of Content-Type.
    pub fn body_data(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// Reconstruct the SIP message as wire-format bytes (first line + headers + body).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.message_type {
            SipMessageType::Request { method, uri } => {
                out.extend_from_slice(format!("{method} {uri} SIP/2.0\r\n").as_bytes());
            }
            SipMessageType::Response { code, reason } => {
                out.extend_from_slice(format!("SIP/2.0 {code} {reason}\r\n").as_bytes());
            }
        }
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        if !self.body.is_empty() {
            out.extend_from_slice(&self.body);
        }
        out
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_parsed(
        msg_type: SipMessageType,
        headers: Vec<(&str, &str)>,
        body: &[u8],
    ) -> ParsedSipMessage {
        ParsedSipMessage {
            direction: Direction::Recv,
            transport: Transport::Tcp,
            address: "10.0.0.1:5060".into(),
            timestamp: Timestamp::TimeOnly {
                hour: 12,
                min: 0,
                sec: 0,
                usec: 0,
            },
            message_type: msg_type,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
            frame_count: 1,
        }
    }

    #[test]
    fn to_bytes_request_no_body() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "OPTIONS".into(),
                uri: "sip:host".into(),
            },
            vec![("Call-ID", "test")],
            b"",
        );
        let bytes = msg.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("OPTIONS sip:host SIP/2.0\r\n"));
        assert!(text.contains("Call-ID: test\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn to_bytes_request_with_body() {
        let body = b"v=0\r\ns=-\r\n";
        let msg = make_parsed(
            SipMessageType::Request {
                method: "INVITE".into(),
                uri: "sip:host".into(),
            },
            vec![("Call-ID", "test")],
            body,
        );
        let bytes = msg.to_bytes();
        assert!(bytes.ends_with(body));
    }

    #[test]
    fn to_bytes_response() {
        let msg = make_parsed(
            SipMessageType::Response {
                code: 200,
                reason: "OK".into(),
            },
            vec![("Call-ID", "resp-test")],
            b"",
        );
        let bytes = msg.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
    }

    #[test]
    fn body_data_valid_utf8() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "MESSAGE".into(),
                uri: "sip:host".into(),
            },
            vec![],
            b"hello world",
        );
        assert_eq!(&*msg.body_data(), "hello world");
    }

    #[test]
    fn body_data_empty() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "OPTIONS".into(),
                uri: "sip:host".into(),
            },
            vec![],
            b"",
        );
        assert_eq!(&*msg.body_data(), "");
    }

    #[test]
    fn body_data_binary() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "MESSAGE".into(),
                uri: "sip:host".into(),
            },
            vec![],
            &[0xFF, 0xFE],
        );
        assert!(msg.body_data().contains('\u{FFFD}'));
    }

    #[test]
    fn body_text_non_json_passthrough() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "INVITE".into(),
                uri: "sip:host".into(),
            },
            vec![("Content-Type", "application/sdp")],
            b"v=0\r\ns=-\r\n",
        );
        assert_eq!(msg.body_text().as_ref(), msg.body_data().as_ref());
    }

    #[test]
    fn body_text_json_unescapes_newlines() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "NOTIFY".into(),
                uri: "sip:host".into(),
            },
            vec![("Content-Type", "application/json")],
            br#"{"invite":"INVITE sip:host SIP/2.0\r\nTo: <sip:host>\r\n"}"#,
        );
        let text = msg.body_text();
        assert!(
            text.contains("INVITE sip:host SIP/2.0\r\nTo: <sip:host>\r\n"),
            "JSON \\r\\n should be unescaped to actual CRLF, got: {text:?}"
        );
    }

    #[test]
    fn body_text_plus_json_content_type() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "NOTIFY".into(),
                uri: "sip:host".into(),
            },
            vec![(
                "Content-Type",
                "application/emergencyCallData.AbandonedCall+json",
            )],
            br#"{"invite":"line1\nline2"}"#,
        );
        let text = msg.body_text();
        assert!(
            text.contains("line1\nline2"),
            "application/*+json should trigger unescaping, got: {text:?}"
        );
    }

    #[test]
    fn body_data_preserves_json_escapes() {
        let raw = br#"{"key":"value\nwith\\escapes"}"#;
        let msg = make_parsed(
            SipMessageType::Request {
                method: "NOTIFY".into(),
                uri: "sip:host".into(),
            },
            vec![("Content-Type", "application/json")],
            raw,
        );
        assert_eq!(
            msg.body_data().as_ref(),
            r#"{"key":"value\nwith\\escapes"}"#,
            "body_data() must preserve raw escapes"
        );
    }
}
