use std::borrow::Cow;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Recv,
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
    pub fn preposition(&self) -> &'static str {
        match self {
            Direction::Recv => "from",
            Direction::Sent => "to",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    Tls,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timestamp {
    TimeOnly {
        hour: u8,
        min: u8,
        sec: u8,
        usec: u32,
    },
    DateTime {
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        min: u8,
        sec: u8,
        usec: u32,
    },
}

impl Timestamp {
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

#[derive(Debug, Clone)]
pub struct Frame {
    pub direction: Direction,
    pub byte_count: usize,
    pub transport: Transport,
    pub address: String,
    pub timestamp: Timestamp,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SipMessage {
    pub direction: Direction,
    pub transport: Transport,
    pub address: String,
    pub timestamp: Timestamp,
    pub content: Vec<u8>,
    pub frame_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessageType {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
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
    pub fn summary(&self) -> Cow<'_, str> {
        match self {
            SipMessageType::Request { method, .. } => Cow::Borrowed(method),
            SipMessageType::Response { code, reason } => Cow::Owned(format!("{code} {reason}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedSipMessage {
    pub direction: Direction,
    pub transport: Transport,
    pub address: String,
    pub timestamp: Timestamp,
    pub message_type: SipMessageType,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub frame_count: usize,
}

#[derive(Debug, Clone)]
pub struct MimePart {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MimePart {
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

    pub fn content_id(&self) -> Option<&str> {
        self.header_value("Content-ID")
    }

    pub fn content_disposition(&self) -> Option<&str> {
        self.header_value("Content-Disposition")
    }
}

impl ParsedSipMessage {
    pub fn call_id(&self) -> Option<&str> {
        self.header_value("Call-ID")
            .or_else(|| self.header_value("i"))
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header_value("Content-Type")
            .or_else(|| self.header_value("c"))
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header_value("Content-Length")
            .or_else(|| self.header_value("l"))
            .and_then(|v| v.trim().parse().ok())
    }

    pub fn cseq(&self) -> Option<&str> {
        self.header_value("CSeq")
    }

    pub fn method(&self) -> Option<&str> {
        match &self.message_type {
            SipMessageType::Request { method, .. } => Some(method),
            SipMessageType::Response { .. } => {
                self.cseq().and_then(|cs| cs.split_whitespace().nth(1))
            }
        }
    }

    pub fn body_text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

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
    fn body_text_valid_utf8() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "MESSAGE".into(),
                uri: "sip:host".into(),
            },
            vec![],
            b"hello world",
        );
        assert_eq!(&*msg.body_text(), "hello world");
    }

    #[test]
    fn body_text_empty() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "OPTIONS".into(),
                uri: "sip:host".into(),
            },
            vec![],
            b"",
        );
        assert_eq!(&*msg.body_text(), "");
    }

    #[test]
    fn body_text_binary() {
        let msg = make_parsed(
            SipMessageType::Request {
                method: "MESSAGE".into(),
                uri: "sip:host".into(),
            },
            vec![],
            &[0xFF, 0xFE],
        );
        assert!(msg.body_text().contains('\u{FFFD}'));
    }
}
