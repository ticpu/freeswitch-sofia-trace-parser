use std::sync::LazyLock;

use memchr::memmem;

use crate::frame::ParseError;
use crate::message::MessageIterator;
use crate::types::{MimePart, ParsedSipMessage, SipMessage, SipMessageType};

static CRLF: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new(b"\r\n"));
static CRLFCRLF: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(b"\r\n\r\n"));

impl SipMessage {
    pub fn parse(&self) -> Result<ParsedSipMessage, ParseError> {
        parse_sip_message(self)
    }
}

pub struct ParsedMessageIterator<R> {
    inner: MessageIterator<R>,
}

impl<R: std::io::Read> ParsedMessageIterator<R> {
    pub fn new(reader: R) -> Self {
        ParsedMessageIterator {
            inner: MessageIterator::new(reader),
        }
    }
}

impl<R: std::io::Read> Iterator for ParsedMessageIterator<R> {
    type Item = Result<ParsedSipMessage, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let msg = match self.inner.next()? {
            Ok(m) => m,
            Err(e) => return Some(Err(e)),
        };
        Some(msg.parse())
    }
}

fn parse_sip_message(msg: &SipMessage) -> Result<ParsedSipMessage, ParseError> {
    let content = &msg.content;

    // Find end of first line
    let first_line_end = CRLF
        .find(content)
        .ok_or_else(|| ParseError::InvalidHeader("no CRLF in SIP message".into()))?;
    let first_line = &content[..first_line_end];

    let message_type = parse_first_line(first_line)?;

    // Find end of headers
    let header_end = CRLFCRLF.find(content);
    let (headers, body) = match header_end {
        Some(pos) if pos > first_line_end + 1 => {
            let header_bytes = &content[first_line_end + 2..pos];
            let body = &content[pos + 4..];
            (header_bytes, body)
        }
        Some(pos) => {
            let body = &content[pos + 4..];
            (&[][..], body)
        }
        None => {
            // No blank line — entire content after first line is headers, no body
            let header_bytes = &content[first_line_end + 2..];
            (header_bytes, &[][..])
        }
    };

    let headers = parse_headers(headers);

    Ok(ParsedSipMessage {
        direction: msg.direction,
        transport: msg.transport,
        address: msg.address.clone(),
        timestamp: msg.timestamp,
        message_type,
        headers,
        body: body.to_vec(),
        frame_count: msg.frame_count,
    })
}

fn parse_first_line(line: &[u8]) -> Result<SipMessageType, ParseError> {
    if line.starts_with(b"SIP/2.0 ") {
        return parse_status_line(line);
    }
    parse_request_line(line)
}

fn parse_status_line(line: &[u8]) -> Result<SipMessageType, ParseError> {
    // SIP/2.0 <code> <reason>
    let after_version = &line[8..]; // skip "SIP/2.0 "

    let space = memchr::memchr(b' ', after_version)
        .ok_or_else(|| ParseError::InvalidHeader("no space after status code".into()))?;
    let code_bytes = &after_version[..space];
    let code: u16 = std::str::from_utf8(code_bytes)
        .map_err(|_| ParseError::InvalidHeader("non-UTF-8 status code".into()))?
        .parse()
        .map_err(|_| ParseError::InvalidHeader("invalid status code".into()))?;

    let reason = &after_version[space + 1..];
    let reason = bytes_to_string(reason);

    Ok(SipMessageType::Response { code, reason })
}

fn parse_request_line(line: &[u8]) -> Result<SipMessageType, ParseError> {
    // <METHOD> <URI> SIP/2.0
    let first_space = memchr::memchr(b' ', line)
        .ok_or_else(|| ParseError::InvalidHeader("no space in request line".into()))?;
    let method = &line[..first_space];
    let rest = &line[first_space + 1..];

    let last_space = memchr::memrchr(b' ', rest)
        .ok_or_else(|| ParseError::InvalidHeader("no SIP version in request line".into()))?;
    let version = &rest[last_space + 1..];
    if version != b"SIP/2.0" {
        return Err(ParseError::InvalidHeader(format!(
            "expected SIP/2.0, got {:?}",
            String::from_utf8_lossy(version)
        )));
    }
    let uri = &rest[..last_space];

    let method = bytes_to_string(method);
    let uri = bytes_to_string(uri);

    Ok(SipMessageType::Request { method, uri })
}

fn bytes_to_string(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_owned(),
        Err(_) => String::from_utf8_lossy(b).into_owned(),
    }
}

fn parse_headers(data: &[u8]) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if data.is_empty() {
        return headers;
    }

    let mut pos = 0;
    while pos < data.len() {
        let line_end = CRLF.find(&data[pos..]).unwrap_or(data.len() - pos);
        let mut line = &data[pos..pos + line_end];
        pos += line_end + 2; // skip \r\n

        // Handle header folding (continuation lines start with SP or HT)
        while pos < data.len() && (data[pos] == b' ' || data[pos] == b'\t') {
            let next_end = CRLF.find(&data[pos..]).unwrap_or(data.len() - pos);
            // Extend line to include continuation
            line = &data[line.as_ptr() as usize - data.as_ptr() as usize..pos + next_end];
            pos += next_end + 2;
        }

        if line.is_empty() {
            continue;
        }

        if let Some(colon) = memchr::memchr(b':', line) {
            let name = &line[..colon];
            let value = if colon + 1 < line.len() {
                trim_header_value(&line[colon + 1..])
            } else {
                &[]
            };
            headers.push((bytes_to_string(name), bytes_to_string(value)));
        }
    }

    headers
}

fn trim_header_value(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(b.len());
    &b[start..]
}

impl ParsedSipMessage {
    pub fn is_multipart(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_ascii_lowercase().starts_with("multipart/"))
            .unwrap_or(false)
    }

    pub fn multipart_boundary(&self) -> Option<&str> {
        let ct = self.content_type()?;
        extract_boundary(ct)
    }

    pub fn body_parts(&self) -> Option<Vec<MimePart>> {
        let boundary = self.multipart_boundary()?;
        Some(parse_multipart_body(&self.body, boundary))
    }
}

fn extract_boundary(content_type: &str) -> Option<&str> {
    let lower = content_type.to_ascii_lowercase();
    let idx = lower.find("boundary=")?;
    let after = &content_type[idx + 9..];

    if let Some(after_quote) = after.strip_prefix('"') {
        let end_quote = after_quote.find('"')?;
        Some(&after_quote[..end_quote])
    } else {
        let end = after.find(';').unwrap_or(after.len());
        let boundary = after[..end].trim();
        if boundary.is_empty() {
            None
        } else {
            Some(boundary)
        }
    }
}

fn parse_multipart_body(body: &[u8], boundary: &str) -> Vec<MimePart> {
    let open_delim = format!("--{boundary}");
    let open_bytes = open_delim.as_bytes();

    let mut parts = Vec::new();

    // Find the first opening delimiter
    let mut pos = match memmem::find(body, open_bytes) {
        Some(p) => p + open_bytes.len(),
        None => return parts,
    };

    // Check for close delimiter immediately
    if body[pos..].starts_with(b"--") {
        return parts;
    }

    // Skip CRLF after delimiter
    if body[pos..].starts_with(b"\r\n") {
        pos += 2;
    }

    while let Some(next) = memmem::find(&body[pos..], open_bytes) {
        // Part content: strip trailing CRLF before delimiter
        let mut end = pos + next;
        if end >= 2 && body[end - 2] == b'\r' && body[end - 1] == b'\n' {
            end -= 2;
        }

        parts.push(parse_mime_part(&body[pos..end]));

        // Move past delimiter
        pos = pos + next + open_bytes.len();

        // Check for close delimiter
        if body[pos..].starts_with(b"--") {
            break;
        }

        // Skip CRLF after delimiter
        if body[pos..].starts_with(b"\r\n") {
            pos += 2;
        }
    }

    parts
}

fn parse_mime_part(data: &[u8]) -> MimePart {
    match memmem::find(data, b"\r\n\r\n") {
        Some(pos) => {
            let header_bytes = &data[..pos];
            let body = &data[pos + 4..];
            let headers = parse_headers(header_bytes);
            MimePart {
                headers,
                body: body.to_vec(),
            }
        }
        None => {
            // Could be headers-only or body-only.
            // If first line has a colon, treat as headers with no body.
            let first_line_end = memmem::find(data, b"\r\n").unwrap_or(data.len());
            if memchr::memchr(b':', &data[..first_line_end]).is_some() {
                let headers = parse_headers(data);
                MimePart {
                    headers,
                    body: Vec::new(),
                }
            } else {
                MimePart {
                    headers: Vec::new(),
                    body: data.to_vec(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Direction, SipMessage, Timestamp, Transport};

    fn make_sip_message(content: &[u8]) -> SipMessage {
        SipMessage {
            direction: Direction::Recv,
            transport: Transport::Udp,
            address: "10.0.0.1:5060".into(),
            timestamp: Timestamp::TimeOnly {
                hour: 12,
                min: 0,
                sec: 0,
                usec: 0,
            },
            content: content.to_vec(),
            frame_count: 1,
        }
    }

    #[test]
    fn parse_options_request() {
        let content = b"OPTIONS sip:user@host SIP/2.0\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1\r\n\
            From: <sip:user@host>;tag=abc\r\n\
            To: <sip:user@host>\r\n\
            Call-ID: test-call-id@host\r\n\
            CSeq: 1 OPTIONS\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Request {
                method: "OPTIONS".into(),
                uri: "sip:user@host".into()
            }
        );
        assert_eq!(parsed.call_id(), Some("test-call-id@host"));
        assert_eq!(parsed.cseq(), Some("1 OPTIONS"));
        assert_eq!(parsed.content_length(), Some(0));
        assert_eq!(parsed.method(), Some("OPTIONS"));
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn parse_200_ok_response() {
        let content = b"SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060\r\n\
            Call-ID: resp-id@host\r\n\
            CSeq: 1 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Response {
                code: 200,
                reason: "OK".into()
            }
        );
        assert_eq!(parsed.method(), Some("INVITE"));
    }

    #[test]
    fn parse_100_trying() {
        let content = b"SIP/2.0 100 Trying\r\n\
            Via: SIP/2.0/TCP 10.0.0.1:5060\r\n\
            Call-ID: trying-id\r\n\
            CSeq: 42 INVITE\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Response {
                code: 100,
                reason: "Trying".into()
            }
        );
        assert_eq!(parsed.method(), Some("INVITE"));
    }

    #[test]
    fn parse_invite_with_sdp_body() {
        let body = b"v=0\r\no=- 123 456 IN IP4 10.0.0.1\r\ns=-\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:user@host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: invite-body@host\r\n");
        content.extend_from_slice(b"CSeq: 1 INVITE\r\n");
        content.extend_from_slice(b"Content-Type: application/sdp\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.method(), Some("INVITE"));
        assert_eq!(parsed.content_type(), Some("application/sdp"));
        assert_eq!(parsed.content_length(), Some(body.len()));
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn parse_notify_with_json_body() {
        let body = br#"{"event":"AbandonedCall","id":"123"}"#;
        let mut content = Vec::new();
        content.extend_from_slice(b"NOTIFY sip:user@host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: notify-json@host\r\n");
        content.extend_from_slice(b"CSeq: 1 NOTIFY\r\n");
        content.extend_from_slice(b"Content-Type: application/json\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.method(), Some("NOTIFY"));
        assert_eq!(parsed.content_type(), Some("application/json"));
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn compact_headers() {
        let content = b"NOTIFY sip:user@host SIP/2.0\r\n\
            i: compact-call-id\r\n\
            l: 0\r\n\
            c: text/plain\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.call_id(), Some("compact-call-id"));
        assert_eq!(parsed.content_length(), Some(0));
        assert_eq!(parsed.content_type(), Some("text/plain"));
    }

    #[test]
    fn header_folding() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Via: SIP/2.0/UDP 10.0.0.1:5060\r\n\
            Subject: this is a long\r\n \
            folded header value\r\n\
            Call-ID: fold-test\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        let subject = parsed
            .headers
            .iter()
            .find(|(k, _)| k == "Subject")
            .map(|(_, v)| v.as_str());
        assert!(
            subject.unwrap().contains("folded header value"),
            "folded header should be reconstructed: {:?}",
            subject
        );
        assert_eq!(parsed.call_id(), Some("fold-test"));
    }

    #[test]
    fn no_body() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Call-ID: nobody\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn no_blank_line_no_body() {
        // Malformed: no \r\n\r\n separator
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Call-ID: no-blank\r\n\
            Content-Length: 0";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();
        assert!(parsed.body.is_empty());
        assert_eq!(parsed.call_id(), Some("no-blank"));
    }

    #[test]
    fn preserves_metadata() {
        let content = b"REGISTER sip:host SIP/2.0\r\n\
            Call-ID: meta-test\r\n\
            \r\n";
        let msg = SipMessage {
            direction: Direction::Sent,
            transport: Transport::Tls,
            address: "[2001:db8::1]:5061".into(),
            timestamp: Timestamp::DateTime {
                year: 2026,
                month: 2,
                day: 12,
                hour: 10,
                min: 30,
                sec: 0,
                usec: 123456,
            },
            content: content.to_vec(),
            frame_count: 3,
        };
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.direction, Direction::Sent);
        assert_eq!(parsed.transport, Transport::Tls);
        assert_eq!(parsed.address, "[2001:db8::1]:5061");
        assert_eq!(parsed.frame_count, 3);
        assert_eq!(
            parsed.timestamp,
            Timestamp::DateTime {
                year: 2026,
                month: 2,
                day: 12,
                hour: 10,
                min: 30,
                sec: 0,
                usec: 123456,
            }
        );
    }

    #[test]
    fn multiple_same_name_headers() {
        let content = b"INVITE sip:host SIP/2.0\r\n\
            Via: SIP/2.0/UDP proxy1:5060\r\n\
            Via: SIP/2.0/UDP proxy2:5060\r\n\
            Record-Route: <sip:proxy1>\r\n\
            Record-Route: <sip:proxy2>\r\n\
            Call-ID: multi-hdr\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        let via_count = parsed.headers.iter().filter(|(k, _)| k == "Via").count();
        assert_eq!(via_count, 2);

        let rr_count = parsed
            .headers
            .iter()
            .filter(|(k, _)| k == "Record-Route")
            .count();
        assert_eq!(rr_count, 2);
    }

    #[test]
    fn header_ordering_preserved() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Via: v1\r\n\
            From: f1\r\n\
            To: t1\r\n\
            Call-ID: order-test\r\n\
            CSeq: 1 OPTIONS\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        let names: Vec<&str> = parsed.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["Via", "From", "To", "Call-ID", "CSeq"]);
    }

    #[test]
    fn status_line_with_long_reason() {
        let content = b"SIP/2.0 486 Busy Here\r\n\
            Call-ID: busy\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Response {
                code: 486,
                reason: "Busy Here".into()
            }
        );
    }

    #[test]
    fn request_with_complex_uri() {
        let content = b"INVITE sip:+15551234567@gateway.example.com;transport=tcp SIP/2.0\r\n\
            Call-ID: complex-uri\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.message_type,
            SipMessageType::Request {
                method: "INVITE".into(),
                uri: "sip:+15551234567@gateway.example.com;transport=tcp".into()
            }
        );
    }

    #[test]
    fn binary_body() {
        let body: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let mut content = Vec::new();
        content.extend_from_slice(b"MESSAGE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: binary-body\r\n");
        content.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(&body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.body, body);
    }

    #[test]
    fn error_no_crlf() {
        let content = b"garbage without any crlf";
        let msg = make_sip_message(content);
        let result = msg.parse();
        assert!(result.is_err());
    }

    #[test]
    fn error_no_space_in_request_line() {
        let content = b"INVALID\r\n\r\n";
        let msg = make_sip_message(content);
        let result = msg.parse();
        assert!(result.is_err());
    }

    #[test]
    fn header_value_with_colon() {
        // SIP URIs in header values contain colons
        let content = b"INVITE sip:host SIP/2.0\r\n\
            Contact: <sip:user@10.0.0.1:5060;transport=tcp>\r\n\
            Call-ID: colon-val\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        let contact = parsed
            .headers
            .iter()
            .find(|(k, _)| k == "Contact")
            .map(|(_, v)| v.as_str());
        assert_eq!(contact, Some("<sip:user@10.0.0.1:5060;transport=tcp>"));
    }

    #[test]
    fn whitespace_around_header_value() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Call-ID:   spaces-around   \r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        // Leading whitespace should be trimmed, trailing kept (we only trim leading)
        assert_eq!(parsed.call_id(), Some("spaces-around   "));
    }

    #[test]
    fn parsed_message_iterator() {
        let content =
            b"OPTIONS sip:host SIP/2.0\r\nCall-ID: iter-test\r\nContent-Length: 0\r\n\r\n";
        let header = format!(
            "recv {} bytes from udp/10.0.0.1:5060 at 00:00:00.000000:\n",
            content.len()
        );
        let mut data = header.into_bytes();
        data.extend_from_slice(content);
        data.extend_from_slice(b"\x0B\n");

        let parsed: Vec<ParsedSipMessage> = ParsedMessageIterator::new(&data[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].call_id(), Some("iter-test"));
        assert_eq!(parsed[0].method(), Some("OPTIONS"));
    }

    // --- Multipart tests ---

    fn make_multipart_invite(boundary: &str, parts: &[(&str, &[u8])]) -> SipMessage {
        let mut body = Vec::new();
        for (ct, content) in parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--").as_bytes());

        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:urn:service:sos@esrp.example.com SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: multipart-test@host\r\n");
        content.extend_from_slice(b"CSeq: 1 INVITE\r\n");
        content.extend_from_slice(
            format!("Content-Type: multipart/mixed;boundary={boundary}\r\n").as_bytes(),
        );
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(&body);

        make_sip_message(&content)
    }

    #[test]
    fn multipart_sdp_and_pidf() {
        let sdp = b"v=0\r\no=- 123 456 IN IP4 10.0.0.1\r\ns=-\r\n";
        let pidf = b"<?xml version=\"1.0\"?>\r\n<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"/>";
        let msg = make_multipart_invite(
            "unique-boundary-1",
            &[("application/sdp", sdp), ("application/pidf+xml", pidf)],
        );
        let parsed = msg.parse().unwrap();

        assert!(parsed.is_multipart());
        assert_eq!(parsed.multipart_boundary(), Some("unique-boundary-1"));

        let parts = parsed.body_parts().unwrap();
        assert_eq!(parts.len(), 2);

        assert_eq!(parts[0].content_type(), Some("application/sdp"));
        assert_eq!(parts[0].body, sdp);

        assert_eq!(parts[1].content_type(), Some("application/pidf+xml"));
        assert_eq!(parts[1].body, pidf);
    }

    #[test]
    fn multipart_sdp_and_eido() {
        let sdp = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\n\
            c=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
        let eido = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
            <eido:EmergencyCallData xmlns:eido=\"urn:nena:xml:ns:EmergencyCallData\">\r\n\
            <eido:IncidentId>INC-2026-001</eido:IncidentId>\r\n\
            </eido:EmergencyCallData>";
        let msg = make_multipart_invite(
            "ng911-boundary",
            &[
                ("application/sdp", sdp),
                ("application/emergencyCallData.eido+xml", eido),
            ],
        );
        let parsed = msg.parse().unwrap();
        let parts = parsed.body_parts().unwrap();
        assert_eq!(parts.len(), 2);

        let sdp_part = parts
            .iter()
            .find(|p| p.content_type() == Some("application/sdp"));
        assert!(sdp_part.is_some());
        assert_eq!(sdp_part.unwrap().body, sdp);

        let eido_part = parts
            .iter()
            .find(|p| p.content_type().is_some_and(|ct| ct.contains("eido")));
        assert!(eido_part.is_some());
        assert_eq!(eido_part.unwrap().body, eido);
    }

    #[test]
    fn multipart_three_parts_sdp_pidf_eido() {
        let sdp = b"v=0\r\ns=-\r\n";
        let pidf = b"<presence/>";
        let eido = b"<EmergencyCallData/>";
        let msg = make_multipart_invite(
            "tri-part",
            &[
                ("application/sdp", sdp),
                ("application/pidf+xml", pidf),
                ("application/emergencyCallData.eido+xml", eido),
            ],
        );
        let parsed = msg.parse().unwrap();
        let parts = parsed.body_parts().unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].content_type(), Some("application/sdp"));
        assert_eq!(parts[1].content_type(), Some("application/pidf+xml"));
        assert_eq!(
            parts[2].content_type(),
            Some("application/emergencyCallData.eido+xml")
        );
    }

    #[test]
    fn multipart_quoted_boundary() {
        let sdp = b"v=0\r\n";
        let pidf = b"<presence/>";

        let mut body = Vec::new();
        body.extend_from_slice(b"--quoted-boundary\r\n");
        body.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
        body.extend_from_slice(sdp);
        body.extend_from_slice(b"\r\n--quoted-boundary\r\n");
        body.extend_from_slice(b"Content-Type: application/pidf+xml\r\n\r\n");
        body.extend_from_slice(pidf);
        body.extend_from_slice(b"\r\n--quoted-boundary--");

        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: quoted-bnd@host\r\n");
        content
            .extend_from_slice(b"Content-Type: multipart/mixed; boundary=\"quoted-boundary\"\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(&body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.multipart_boundary(), Some("quoted-boundary"));
        let parts = parsed.body_parts().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].body, sdp);
        assert_eq!(parts[1].body, pidf);
    }

    #[test]
    fn multipart_with_preamble() {
        let sdp = b"v=0\r\n";

        let mut body = Vec::new();
        body.extend_from_slice(b"This is the preamble. It should be ignored.\r\n");
        body.extend_from_slice(b"--boundary-pre\r\n");
        body.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
        body.extend_from_slice(sdp);
        body.extend_from_slice(b"\r\n--boundary-pre--");

        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: preamble@host\r\n");
        content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=boundary-pre\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(&body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();
        let parts = parsed.body_parts().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].body, sdp);
    }

    #[test]
    fn multipart_part_with_multiple_headers() {
        let eido = b"<EmergencyCallData/>";

        let mut body = Vec::new();
        body.extend_from_slice(b"--hdr-boundary\r\n");
        body.extend_from_slice(b"Content-Type: application/emergencyCallData.eido+xml\r\n");
        body.extend_from_slice(b"Content-ID: <eido@example.com>\r\n");
        body.extend_from_slice(b"Content-Disposition: by-reference\r\n");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(eido);
        body.extend_from_slice(b"\r\n--hdr-boundary--");

        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: multi-hdr-part@host\r\n");
        content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=hdr-boundary\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(&body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();
        let parts = parsed.body_parts().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].content_type(),
            Some("application/emergencyCallData.eido+xml")
        );
        assert_eq!(parts[0].content_id(), Some("<eido@example.com>"));
        assert_eq!(parts[0].content_disposition(), Some("by-reference"));
        assert_eq!(parts[0].body, eido);
    }

    #[test]
    fn not_multipart_returns_none() {
        let content = b"INVITE sip:host SIP/2.0\r\n\
            Call-ID: not-multi@host\r\n\
            Content-Type: application/sdp\r\n\
            Content-Length: 4\r\n\
            \r\n\
            v=0\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();

        assert!(!parsed.is_multipart());
        assert!(parsed.multipart_boundary().is_none());
        assert!(parsed.body_parts().is_none());
    }

    #[test]
    fn multipart_empty_body() {
        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: empty-multi@host\r\n");
        content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=empty\r\n");
        content.extend_from_slice(b"Content-Length: 9\r\n");
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(b"--empty--");

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();
        let parts = parsed.body_parts().unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn extract_boundary_unquoted() {
        assert_eq!(
            extract_boundary("multipart/mixed;boundary=foo-bar"),
            Some("foo-bar")
        );
    }

    #[test]
    fn extract_boundary_quoted() {
        assert_eq!(
            extract_boundary("multipart/mixed; boundary=\"foo-bar\""),
            Some("foo-bar")
        );
    }

    #[test]
    fn extract_boundary_with_extra_params() {
        assert_eq!(
            extract_boundary("multipart/mixed; boundary=foo;charset=utf-8"),
            Some("foo")
        );
    }

    #[test]
    fn extract_boundary_case_insensitive() {
        assert_eq!(
            extract_boundary("multipart/mixed;BOUNDARY=abc"),
            Some("abc")
        );
    }

    #[test]
    fn extract_boundary_missing() {
        assert_eq!(extract_boundary("multipart/mixed"), None);
    }

    #[test]
    fn multipart_part_no_headers() {
        let raw_body = b"just raw content";

        let mut body = Vec::new();
        body.extend_from_slice(b"--no-hdr\r\n");
        body.extend_from_slice(raw_body);
        body.extend_from_slice(b"\r\n--no-hdr--");

        let mut content = Vec::new();
        content.extend_from_slice(b"MESSAGE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: no-hdr-part@host\r\n");
        content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=no-hdr\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(&body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();
        let parts = parsed.body_parts().unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].content_type().is_none());
        assert!(parts[0].headers.is_empty());
        assert_eq!(parts[0].body, raw_body);
    }
}
