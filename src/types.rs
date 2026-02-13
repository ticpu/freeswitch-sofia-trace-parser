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

    fn header_value(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}
