use std::borrow::Cow;
use std::sync::LazyLock;

use memchr::memmem;
use sip_header::extract_all_headers;

use crate::frame::ParseError;
use crate::message::MessageIterator;
use crate::types::{
    Headers, MimePart, ParseStats, ParsedSipMessage, SipFragment, SipMessage, SipMessageType,
    SkipTracking, UnparsedRegion,
};

static CRLF: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new(b"\r\n"));
static CRLFCRLF: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(b"\r\n\r\n"));

impl SipMessage {
    /// Parse this reassembled message into a [`ParsedSipMessage`] with typed
    /// access to the request/status line, headers, and body.
    pub fn parse(&self) -> Result<ParsedSipMessage, ParseError> {
        parse_sip_message(self)
    }
}

/// Level 3 streaming parser: wraps [`MessageIterator`] and parses each
/// reassembled message into a [`ParsedSipMessage`].
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use freeswitch_sofia_trace_parser::ParsedMessageIterator;
///
/// let file = File::open("profile.dump").unwrap();
/// for result in ParsedMessageIterator::new(file) {
///     let msg = result.unwrap();
///     if let Some(parts) = msg.body_parts() {
///         for part in &parts {
///             println!("  {} ({} bytes)",
///                 part.content_type().unwrap_or("unknown"), part.body.len());
///         }
///     }
/// }
/// ```
pub struct ParsedMessageIterator<R> {
    inner: MessageIterator<R>,
}

impl<R: std::io::Read> ParsedMessageIterator<R> {
    /// Create a new parsed message iterator reading from the given source.
    pub fn new(reader: R) -> Self {
        ParsedMessageIterator {
            inner: MessageIterator::new(reader),
        }
    }

    /// Enable capturing of skipped bytes in the underlying frame parser.
    pub fn capture_skipped(mut self, enable: bool) -> Self {
        self.inner = self.inner.capture_skipped(enable);
        self
    }

    /// Set the level of detail for unparsed region tracking.
    pub fn skip_tracking(mut self, tracking: SkipTracking) -> Self {
        self.inner = self.inner.skip_tracking(tracking);
        self
    }

    /// Borrow the accumulated parse statistics.
    pub fn parse_stats(&self) -> &ParseStats {
        self.inner.parse_stats()
    }

    /// Mutably borrow the parse statistics.
    pub fn parse_stats_mut(&mut self) -> &mut ParseStats {
        self.inner.parse_stats_mut()
    }

    /// Take all accumulated unparsed regions, leaving the list empty.
    pub fn drain_unparsed(&mut self) -> Vec<UnparsedRegion> {
        self.inner.drain_unparsed()
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

fn content_preview(content: &[u8], max_len: usize) -> String {
    use std::fmt::Write;
    let len = content.len().min(max_len);
    let s = String::from_utf8_lossy(&content[..len]);
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    if content.len() > max_len {
        out.push_str("...");
    }
    out
}

fn parse_sip_message(msg: &SipMessage) -> Result<ParsedSipMessage, ParseError> {
    let content = &msg.content;

    if content
        .iter()
        .all(|&b| matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
    {
        return Err(ParseError::TransportNoise {
            bytes: content.len(),
            transport: msg.transport,
            address: msg.address.clone(),
        });
    }

    parse_sip_content(msg, content).map_err(|e| {
        let reason = match e {
            ParseError::InvalidMessage(reason) => reason,
            other => return other,
        };
        let preview = content_preview(content, 200);
        ParseError::InvalidMessage(format!(
            "{} {}/{} at {} ({} frames, {} bytes): {reason}\n  {preview}",
            msg.direction,
            msg.transport,
            msg.address,
            msg.timestamp,
            msg.frame_count,
            content.len(),
        ))
    })
}

fn parse_sip_content(msg: &SipMessage, content: &[u8]) -> Result<ParsedSipMessage, ParseError> {
    // Find end of first line
    let first_line_end = CRLF
        .find(content)
        .ok_or_else(|| ParseError::InvalidMessage("no CRLF found".into()))?;
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
        .ok_or_else(|| ParseError::InvalidMessage("no space after status code".into()))?;
    let code_bytes = &after_version[..space];
    let code: u16 = std::str::from_utf8(code_bytes)
        .map_err(|_| ParseError::InvalidMessage("non-UTF-8 status code".into()))?
        .parse()
        .map_err(|_| ParseError::InvalidMessage("invalid status code".into()))?;

    let reason = &after_version[space + 1..];
    let reason = bytes_to_string(reason);

    Ok(SipMessageType::Response { code, reason })
}

fn is_sip_token(b: &[u8]) -> bool {
    !b.is_empty()
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || b"-._!%*+'~".contains(&c))
}

/// A syntactically valid header first line: a nonempty SIP token, optionally
/// followed by HCOLON whitespace (SP / HTAB), then a colon.
fn is_header_line(line: &[u8]) -> bool {
    let Some(colon) = memchr::memchr(b':', line) else {
        return false;
    };
    let mut name = &line[..colon];
    while let [rest @ .., b' ' | b'\t'] = name {
        name = rest;
    }
    is_sip_token(name)
}

fn parse_request_line(line: &[u8]) -> Result<SipMessageType, ParseError> {
    // <METHOD> <URI> SIP/2.0
    let first_space = memchr::memchr(b' ', line)
        .ok_or_else(|| ParseError::InvalidMessage("no space in request line".into()))?;
    let method = &line[..first_space];

    if !is_sip_token(method) {
        return Err(ParseError::InvalidMessage(format!(
            "invalid SIP method: {:?}",
            String::from_utf8_lossy(method)
        )));
    }
    let rest = &line[first_space + 1..];

    let last_space = memchr::memrchr(b' ', rest)
        .ok_or_else(|| ParseError::InvalidMessage("no SIP version in request line".into()))?;
    let version = &rest[last_space + 1..];
    if version != b"SIP/2.0" {
        return Err(ParseError::InvalidMessage(format!(
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
    if b.is_ascii() {
        // SAFETY: ASCII is a subset of UTF-8; is_ascii() guarantees all bytes < 128
        unsafe { String::from_utf8_unchecked(b.to_vec()) }
    } else {
        String::from_utf8_lossy(b).into_owned()
    }
}

fn parse_headers(data: &[u8]) -> Headers {
    let text = String::from_utf8_lossy(data);
    Headers(extract_all_headers(&text))
}

/// Parse a `message/sipfrag` body (RFC 3420) — any prefix of a SIP message.
///
/// The start line is optional: a fragment that begins with a header is parsed
/// from the headers down. The trailing CRLF is optional too, so a bare status
/// line parses. Fails only when the first line is neither a start line nor a
/// header, or the input is empty.
pub fn parse_sipfrag(data: &[u8]) -> Result<SipFragment, ParseError> {
    if data.is_empty() {
        return Err(ParseError::InvalidMessage("empty sipfrag".into()));
    }

    let first_line_end = CRLF.find(data).unwrap_or(data.len());
    let mut first_line = &data[..first_line_end];
    // A bare trailing terminator from an LF-only writer is not part of the
    // start line; a full CRLF is already excluded by the find above.
    if let [rest @ .., b'\n'] = first_line {
        first_line = rest;
    }
    if let [rest @ .., b'\r'] = first_line {
        first_line = rest;
    }

    let (message_type, headers_start) = match parse_first_line(first_line) {
        Ok(mt) => (Some(mt), (first_line_end + 2).min(data.len())),
        Err(e) => {
            if !is_header_line(first_line) {
                return Err(e);
            }
            (None, 0)
        }
    };

    let (header_bytes, body) = match CRLFCRLF.find(data) {
        Some(pos) if pos >= headers_start => (&data[headers_start..pos], &data[pos + 4..]),
        // The blank line terminates the start line: no headers, body follows.
        Some(pos) => (&[][..], &data[pos + 4..]),
        None => (&data[headers_start..], &[][..]),
    };

    Ok(SipFragment {
        message_type,
        headers: parse_headers(header_bytes),
        body: body.to_vec(),
    })
}

fn is_multipart_type(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| normalize_media_type(ct).starts_with("multipart/"))
        .unwrap_or(false)
}

/// A declared boundary that yields no parts — absent from the body, or present
/// only as the close delimiter — is not a split: reporting it as one empty
/// makes a body vanish from a per-part loop.
fn split_multipart(content_type: Option<&str>, body: &[u8]) -> Option<Vec<MimePart>> {
    let boundary = extract_boundary(content_type?)?;
    let parts = parse_multipart_body(body, boundary);
    (!parts.is_empty()).then_some(parts)
}

impl MimePart {
    /// Content-Type with parameters stripped and lowercased, e.g.
    /// `application/sdp` from `Application/SDP; charset=utf-8`. Use this to
    /// dispatch on the type rather than matching the raw header value.
    pub fn media_type(&self) -> Option<Cow<'_, str>> {
        self.content_type().map(normalize_media_type)
    }

    /// Returns `true` if this part's Content-Type starts with `multipart/`.
    pub fn is_multipart(&self) -> bool {
        is_multipart_type(self.content_type())
    }

    /// Extract the MIME boundary string from this part's Content-Type header.
    pub fn multipart_boundary(&self) -> Option<&str> {
        extract_boundary(self.content_type()?)
    }

    /// Parse this part's body as a `message/sipfrag` (RFC 3420).
    ///
    /// Does not check the Content-Type: dispatch on [`media_type`](Self::media_type)
    /// first, then call this for the parts that claim to be fragments.
    pub fn parse_sipfrag(&self) -> Result<SipFragment, ParseError> {
        parse_sipfrag(&self.body)
    }

    /// Split a nested multipart part into its own [`MimePart`]s.
    /// Returns `None` when this part carries no boundary or that boundary
    /// yields no parts — either way, keep the part's own bytes.
    ///
    /// Descends exactly one level: a grandchild multipart comes back as a part
    /// with its `multipart/*` type intact, to be split by another explicit
    /// call. Depth is the caller's decision.
    pub fn body_parts(&self) -> Option<Vec<MimePart>> {
        split_multipart(self.content_type(), &self.body)
    }
}

impl ParsedSipMessage {
    /// Content-Type with parameters stripped and lowercased, e.g.
    /// `multipart/mixed` from `multipart/mixed;boundary=abc`. Use this to
    /// dispatch on the type rather than matching the raw header value.
    pub fn media_type(&self) -> Option<Cow<'_, str>> {
        self.content_type().map(normalize_media_type)
    }

    /// Returns `true` if the Content-Type starts with `multipart/`.
    pub fn is_multipart(&self) -> bool {
        is_multipart_type(self.content_type())
    }

    /// Extract the MIME boundary string from the Content-Type header.
    pub fn multipart_boundary(&self) -> Option<&str> {
        let ct = self.content_type()?;
        extract_boundary(ct)
    }

    /// Split a multipart body into individual [`MimePart`]s.
    /// Returns `None` when the Content-Type carries no `boundary` parameter or
    /// that boundary yields no parts.
    pub fn body_parts(&self) -> Option<Vec<MimePart>> {
        split_multipart(self.content_type(), &self.body)
    }

    /// The body as parts, whatever its Content-Type: the multipart children
    /// when it splits, otherwise a single part carrying the message's own
    /// `Content-*` headers. Empty when there is no body.
    ///
    /// That single part is fabricated — a non-multipart body has no per-part
    /// header block on the wire — so its headers are copied down from the
    /// message under their canonical names, `Content-Length` excluded. A part
    /// split from a real multipart body carries only what the sender wrote
    /// there, and nothing is copied into it.
    ///
    /// A body that claims `multipart/*` but does not split — no boundary
    /// parameter, or one that never appears in the body — comes back as that
    /// one part, still typed `multipart/*`. A caller that only handles types it
    /// recognizes then sees an unknown type rather than nothing at all.
    ///
    /// Descends one level only; nested multipart parts are split by calling
    /// [`MimePart::body_parts`] on them.
    pub fn all_body_parts(&self) -> Vec<MimePart> {
        if self.body.is_empty() {
            return Vec::new();
        }
        if let Some(parts) = self.body_parts() {
            return parts;
        }

        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(ct) = self.content_type() {
            headers.push(("Content-Type".to_string(), ct.to_string()));
        }
        for (name, value) in &self.headers {
            let Some(canonical) = canonical_body_header(name) else {
                continue;
            };
            if headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(&canonical))
            {
                continue;
            }
            headers.push((canonical.into_owned(), value.clone()));
        }
        vec![MimePart {
            headers: Headers(headers),
            body: self.body.clone(),
        }]
    }

    /// Content-type-aware body text. For JSON content types (`application/json`
    /// and `application/*+json`), unescapes RFC 8259 string sequences
    /// (`\r\n` to CRLF, `\t` to tab, `\uXXXX` to Unicode). Passthrough for
    /// all other content types.
    pub fn body_text(&self) -> Cow<'_, str> {
        if let Some(ct) = self.content_type() {
            if is_json_content_type(ct) {
                return Cow::Owned(unescape_json_body(&self.body));
            }
        }
        self.body_data()
    }

    /// Parse the body as JSON and return the unescaped string value of a
    /// top-level key. Returns `None` if the content type is not JSON, the
    /// body is invalid JSON, the key is missing, or the value is not a string.
    pub fn json_field(&self, key: &str) -> Option<String> {
        let ct = self.content_type()?;
        if !is_json_content_type(ct) {
            return None;
        }
        let value: serde_json::Value = serde_json::from_slice(&self.body).ok()?;
        let obj = value.as_object()?;
        obj.get(key)?.as_str().map(|s| s.to_string())
    }
}

/// Strip parameters from a Content-Type value and normalize to lowercase.
/// Borrows when the type/subtype is already lowercase and unpadded.
fn normalize_media_type(ct: &str) -> Cow<'_, str> {
    let base = ct.split(';').next().unwrap_or("").trim();
    if base.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(base.to_ascii_lowercase())
    } else {
        Cow::Borrowed(base)
    }
}

/// Canonical name of a header describing the body, or `None` for one that does
/// not. `Content-Length` is not one: it counts the message body, so it goes
/// stale as soon as a consumer rewrites the part it would be copied onto.
fn canonical_body_header(name: &str) -> Option<Cow<'_, str>> {
    if name.eq_ignore_ascii_case("c") {
        return Some(Cow::Borrowed("Content-Type"));
    }
    if name.eq_ignore_ascii_case("e") {
        return Some(Cow::Borrowed("Content-Encoding"));
    }
    if name.eq_ignore_ascii_case("l") || name.eq_ignore_ascii_case("Content-Length") {
        return None;
    }
    name.as_bytes()
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"content-"))
        .then_some(Cow::Borrowed(name))
}

/// Returns `true` for `application/json` and any `application/*+json` subtype.
/// Case-insensitive; media type parameters are ignored.
pub fn is_json_content_type(ct: &str) -> bool {
    let media_type = normalize_media_type(ct);
    media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
}

fn unescape_json_body(input: &[u8]) -> String {
    let s = String::from_utf8_lossy(input);
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('b') => out.push('\x08'),
            Some('f') => out.push('\x0C'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => unescape_unicode(&mut chars, &mut out),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn unescape_unicode(chars: &mut std::str::Chars<'_>, out: &mut String) {
    let hex: String = chars.by_ref().take(4).collect();
    let Some(code_point) = parse_hex4(&hex) else {
        out.push_str("\\u");
        out.push_str(&hex);
        return;
    };

    if (0xD800..=0xDBFF).contains(&code_point) {
        let mut peek = chars.clone();
        if peek.next() == Some('\\') && peek.next() == Some('u') {
            let hex2: String = peek.by_ref().take(4).collect();
            if let Some(low) = parse_hex4(&hex2) {
                if (0xDC00..=0xDFFF).contains(&low) {
                    let combined =
                        0x10000 + ((code_point as u32 - 0xD800) << 10) + (low as u32 - 0xDC00);
                    if let Some(ch) = char::from_u32(combined) {
                        out.push(ch);
                        *chars = peek;
                        return;
                    }
                }
            }
        }
        out.push_str("\\u");
        out.push_str(&hex);
    } else if let Some(ch) = char::from_u32(code_point as u32) {
        out.push(ch);
    } else {
        out.push_str("\\u");
        out.push_str(&hex);
    }
}

fn parse_hex4(hex: &str) -> Option<u16> {
    if hex.len() == 4 {
        u16::from_str_radix(hex, 16).ok()
    } else {
        None
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

/// What follows a matched `--boundary` token, deciding whether the match is a
/// real RFC 2046 delimiter line and where the next part's content starts.
enum BoundaryTail {
    /// Open delimiter; the value is the byte count from the end of the token
    /// (transport padding plus CRLF) to the start of the part content.
    Open(usize),
    Close,
    /// Input ends inside the delimiter line itself (truncated dump).
    End,
}

/// Classify the bytes after a `--boundary` token. `None` means the match is
/// not a delimiter line at all — e.g. boundary `b` matched inside `--b2`.
fn boundary_tail(rest: &[u8]) -> Option<BoundaryTail> {
    if rest.starts_with(b"--") {
        return Some(BoundaryTail::Close);
    }
    let pad = rest
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(rest.len());
    match &rest[pad..] {
        [] => Some(BoundaryTail::End),
        [b'\r', b'\n', ..] => Some(BoundaryTail::Open(pad + 2)),
        _ => None,
    }
}

/// Next RFC 2046 delimiter line at or after `from`: `--boundary` at body
/// offset 0 (no preamble) or immediately after a CRLF. `part_end` is where the
/// preceding part's content stops — the CRLF belongs to the delimiter line.
fn next_delimiter(
    body: &[u8],
    from: usize,
    dash_boundary: &[u8],
    anchored: &memmem::Finder<'_>,
) -> Option<(usize, usize, BoundaryTail)> {
    if from == 0 && body.starts_with(dash_boundary) {
        if let Some(tail) = boundary_tail(&body[dash_boundary.len()..]) {
            return Some((0, dash_boundary.len(), tail));
        }
    }
    let mut search = from;
    while let Some(rel) = anchored.find(&body[search..]) {
        let crlf = search + rel;
        let token_end = crlf + 2 + dash_boundary.len();
        if let Some(tail) = boundary_tail(&body[token_end..]) {
            return Some((crlf, token_end, tail));
        }
        search = crlf + 1;
    }
    None
}

fn parse_multipart_body(body: &[u8], boundary: &str) -> Vec<MimePart> {
    let mut pattern = Vec::with_capacity(boundary.len() + 4);
    pattern.extend_from_slice(b"\r\n--");
    pattern.extend_from_slice(boundary.as_bytes());
    let anchored = memmem::Finder::new(&pattern);
    let dash_boundary = &pattern[2..];

    let mut parts = Vec::new();

    let Some((_, token_end, tail)) = next_delimiter(body, 0, dash_boundary, &anchored) else {
        return parts;
    };
    let mut cursor = match tail {
        BoundaryTail::Open(skip) => token_end + skip,
        // The body opens with the close delimiter, or truncates inside the
        // first delimiter line: no parts.
        BoundaryTail::Close | BoundaryTail::End => return parts,
    };

    loop {
        match next_delimiter(body, cursor, dash_boundary, &anchored) {
            Some((part_end, token_end, BoundaryTail::Open(skip))) => {
                parts.push(parse_mime_part(&body[cursor..part_end]));
                cursor = token_end + skip;
            }
            Some((part_end, _, BoundaryTail::Close | BoundaryTail::End)) => {
                parts.push(parse_mime_part(&body[cursor..part_end]));
                break;
            }
            // Truncated before the close delimiter: the trailing bytes are
            // the final part, never silently dropped.
            None => {
                parts.push(parse_mime_part(&body[cursor..]));
                break;
            }
        }
    }
    parts
}

fn parse_mime_part(data: &[u8]) -> MimePart {
    match CRLFCRLF.find(data) {
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
            let first_line_end = CRLF.find(data).unwrap_or(data.len());
            if memchr::memchr(b':', &data[..first_line_end]).is_some() {
                let headers = parse_headers(data);
                MimePart {
                    headers,
                    body: Vec::new(),
                }
            } else {
                MimePart {
                    headers: Headers::default(),
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
    fn parse_stats_delegates() {
        let content =
            b"OPTIONS sip:host SIP/2.0\r\nCall-ID: stats-test\r\nContent-Length: 0\r\n\r\n";
        let header = format!(
            "recv {} bytes from udp/10.0.0.1:5060 at 00:00:00.000000:\n",
            content.len()
        );
        let mut data = header.into_bytes();
        data.extend_from_slice(content);
        data.extend_from_slice(b"\x0B\n");

        let mut iter = ParsedMessageIterator::new(&data[..]);
        let parsed: Vec<_> = iter.by_ref().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(parsed.len(), 1);
        let stats = iter.parse_stats();
        assert_eq!(stats.bytes_read, data.len() as u64);
        assert_eq!(stats.bytes_skipped, 0);
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
        assert_eq!(subject, Some("this is a long folded header value"));
        assert_eq!(parsed.call_id(), Some("fold-test"));
    }

    #[test]
    fn folded_header_no_crlf_leak() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Subject: line1\r\n \
            line2\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();
        let subject = parsed.headers.iter().find(|(k, _)| k == "Subject").unwrap();
        assert!(!subject.1.contains('\r'), "CRLF leaked: {:?}", subject.1);
        assert!(!subject.1.contains('\n'), "LF leaked: {:?}", subject.1);
        assert_eq!(subject.1, "line1 line2");
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
    fn parse_request_rejects_xml_method() {
        let content =
            b"</confInfo:conference-info>NOTIFY sip:user@host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg = make_sip_message(content);
        assert!(msg.parse().is_err(), "should reject XML-prefixed method");
    }

    #[test]
    fn parse_request_rejects_method_with_angle_brackets() {
        let content = b"<xml>BYE sip:host SIP/2.0\r\n\r\n";
        let msg = make_sip_message(content);
        assert!(msg.parse().is_err());
    }

    #[test]
    fn parse_request_accepts_extension_method() {
        let content = b"CUSTOM-METHOD sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let msg = make_sip_message(content);
        let parsed = msg.parse().unwrap();
        assert_eq!(
            parsed.message_type,
            SipMessageType::Request {
                method: "CUSTOM-METHOD".into(),
                uri: "sip:host".into()
            }
        );
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
        assert!(parsed.body_parts().is_none());

        let parts = parsed.all_body_parts();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].body, b"--empty--");
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

    // --- media_type tests ---

    fn make_with_content_type(header: &str) -> ParsedSipMessage {
        let content = format!("INVITE sip:host SIP/2.0\r\n{header}\r\nCall-ID: mt@host\r\n\r\n");
        make_sip_message(content.as_bytes()).parse().unwrap()
    }

    #[test]
    fn media_type_strips_parameters() {
        let parsed = make_with_content_type("Content-Type: multipart/mixed;boundary=abc");
        assert_eq!(parsed.media_type().as_deref(), Some("multipart/mixed"));
    }

    #[test]
    fn media_type_lowercases() {
        let parsed = make_with_content_type("Content-Type: Application/SDP");
        assert_eq!(parsed.media_type().as_deref(), Some("application/sdp"));
    }

    #[test]
    fn media_type_trims_whitespace() {
        let parsed = make_with_content_type("Content-Type: application/sdp ; charset=utf-8");
        assert_eq!(parsed.media_type().as_deref(), Some("application/sdp"));
    }

    #[test]
    fn media_type_compact_form() {
        let parsed = make_with_content_type("c: application/pidf+xml");
        assert_eq!(parsed.media_type().as_deref(), Some("application/pidf+xml"));
    }

    #[test]
    fn media_type_absent() {
        let parsed = make_with_content_type("Subject: none");
        assert_eq!(parsed.media_type(), None);
    }

    #[test]
    fn media_type_on_mime_part() {
        let msg = make_multipart_invite(
            "mt-boundary",
            &[("Application/SDP; charset=utf-8", b"v=0\r\n")],
        );
        let parsed = msg.parse().unwrap();
        let parts = parsed.body_parts().unwrap();
        assert_eq!(parts[0].media_type().as_deref(), Some("application/sdp"));
    }

    // --- all_body_parts tests ---

    #[test]
    fn all_body_parts_wraps_non_multipart() {
        let body = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: abp-plain@host\r\n");
        content.extend_from_slice(b"Content-Type: application/sdp\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let parsed = make_sip_message(&content).parse().unwrap();
        let parts = parsed.all_body_parts();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].media_type().as_deref(), Some("application/sdp"));
        assert_eq!(parts[0].body, body);
    }

    #[test]
    fn all_body_parts_matches_body_parts_for_multipart() {
        let msg = make_multipart_invite(
            "abp-multi",
            &[
                ("application/sdp", b"v=0\r\n"),
                ("application/pidf+xml", b"<presence/>"),
            ],
        );
        let parsed = msg.parse().unwrap();
        let all = parsed.all_body_parts();
        let split = parsed.body_parts().unwrap();
        assert_eq!(all.len(), split.len());
        for (a, b) in all.iter().zip(split.iter()) {
            assert_eq!(a.headers, b.headers);
            assert_eq!(a.body, b.body);
        }
    }

    #[test]
    fn all_body_parts_empty_body() {
        let content = b"OPTIONS sip:host SIP/2.0\r\n\
            Call-ID: abp-empty@host\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let parsed = make_sip_message(content).parse().unwrap();
        assert!(parsed.all_body_parts().is_empty());
    }

    #[test]
    fn all_body_parts_multipart_without_boundary() {
        let body = b"--something\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n";
        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: abp-nobnd@host\r\n");
        content.extend_from_slice(b"Content-Type: multipart/mixed\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let parsed = make_sip_message(&content).parse().unwrap();
        let parts = parsed.all_body_parts();
        assert_eq!(
            parts.len(),
            1,
            "unsplittable multipart must surface as one part"
        );
        assert_eq!(parts[0].media_type().as_deref(), Some("multipart/mixed"));
        assert_eq!(parts[0].body, body);
    }

    #[test]
    fn all_body_parts_boundary_not_in_body() {
        let body = b"--other\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--other--";
        let parsed = parsed_with_headers(
            "abp-mismatch",
            &["Content-Type: multipart/mixed;boundary=declared"],
            body,
        );
        let parts = parsed.all_body_parts();
        assert_eq!(
            parts.len(),
            1,
            "a boundary absent from the body is not a split"
        );
        assert_eq!(parts[0].media_type().as_deref(), Some("multipart/mixed"));
        assert_eq!(parts[0].body, body);
        assert!(parsed.body_parts().is_none());
    }

    #[test]
    fn all_body_parts_truncated_multipart() {
        let body = b"--trunc\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n";
        let parsed = parsed_with_headers(
            "abp-trunc",
            &["Content-Type: multipart/mixed;boundary=trunc"],
            body,
        );
        let parts = parsed.all_body_parts();
        assert_eq!(
            parts.len(),
            1,
            "a body cut off before the closing delimiter must not vanish"
        );
        assert_eq!(parts[0].content_type(), Some("application/sdp"));
        assert_eq!(parts[0].body, b"v=0\r\n");
        assert!(parsed.body_parts().is_some());
    }

    #[test]
    fn multipart_truncated_trailing_part() {
        let body = b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n\
            --b\r\nContent-Type: application/pidf+xml\r\n\r\n<presence";
        let parts = parse_multipart_body(body, "b");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].body, b"v=0");
        assert_eq!(parts[1].content_type(), Some("application/pidf+xml"));
        assert_eq!(parts[1].body, b"<presence");
    }

    #[test]
    fn multipart_truncated_inside_close_delimiter() {
        let body = b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b";
        let parts = parse_multipart_body(body, "b");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].body, b"v=0");
    }

    #[test]
    fn multipart_preamble_substring_no_false_part() {
        let body = b"preamble mentions --b in passing\r\n\
            --b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b--";
        let parts = parse_multipart_body(body, "b");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].content_type(), Some("application/sdp"));
        assert_eq!(parts[0].body, b"v=0");
    }

    #[test]
    fn multipart_boundary_prefix_collision() {
        let body =
            b"--b\r\nContent-Type: text/plain\r\n\r\nouter\r\n--b2\r\ninner text\r\n--b2--\r\n--b--";
        let parts = parse_multipart_body(body, "b");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].body, b"outer\r\n--b2\r\ninner text\r\n--b2--");
    }

    #[test]
    fn multipart_delimiter_transport_padding() {
        let body = b"--b \t\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n\
            --b  \r\nContent-Type: application/pidf+xml\r\n\r\n<presence/>\r\n--b--";
        let parts = parse_multipart_body(body, "b");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].body, b"v=0");
        assert_eq!(parts[1].body, b"<presence/>");
    }

    #[test]
    fn multipart_no_preamble_delimiter_at_offset_zero() {
        let body = b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b--";
        let parts = parse_multipart_body(body, "b");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].body, b"v=0");
    }

    // --- content headers copied onto the synthetic part ---

    fn parsed_with_headers(call_id: &str, headers: &[&str], body: &[u8]) -> ParsedSipMessage {
        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
        content.extend_from_slice(format!("Call-ID: {call_id}@host\r\n").as_bytes());
        for header in headers {
            content.extend_from_slice(header.as_bytes());
            content.extend_from_slice(b"\r\n");
        }
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);
        make_sip_message(&content).parse().unwrap()
    }

    fn part_header<'a>(part: &'a MimePart, name: &str) -> Option<&'a str> {
        part.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn synthetic_part_carries_transfer_encoding() {
        let parsed = parsed_with_headers(
            "abp-cte",
            &[
                "Content-Type: application/pidf+xml",
                "Content-Transfer-Encoding: base64",
            ],
            b"PD94bWwgdmVyc2lvbj0iMS4wIj8+",
        );
        let parts = parsed.all_body_parts();
        assert_eq!(
            parts[0].content_transfer_encoding(),
            Some("base64"),
            "a per-part consumer must see the encoding the message declared"
        );
    }

    #[test]
    fn synthetic_part_carries_disposition_and_id() {
        let parsed = parsed_with_headers(
            "abp-cd",
            &[
                "Content-Type: application/sdp",
                "Content-Disposition: session",
                "Content-ID: <sdp@host>",
            ],
            b"v=0\r\n",
        );
        let parts = parsed.all_body_parts();
        assert_eq!(parts[0].content_disposition(), Some("session"));
        assert_eq!(parts[0].content_id(), Some("<sdp@host>"));
    }

    #[test]
    fn synthetic_part_canonicalizes_compact_content_encoding() {
        let parsed = parsed_with_headers(
            "abp-compact-e",
            &["Content-Type: application/sdp", "e: gzip"],
            b"v=0\r\n",
        );
        let parts = parsed.all_body_parts();
        assert_eq!(
            part_header(&parts[0], "Content-Encoding"),
            Some("gzip"),
            "compact form must arrive under the canonical name"
        );
    }

    #[test]
    fn synthetic_part_canonicalizes_compact_content_type() {
        let parsed = parsed_with_headers("abp-compact-c", &["c: application/sdp"], b"v=0\r\n");
        let parts = parsed.all_body_parts();
        assert_eq!(parts[0].media_type().as_deref(), Some("application/sdp"));
        assert_eq!(
            parts[0]
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
                .count(),
            1
        );
    }

    #[test]
    fn synthetic_part_content_type_matches_the_message() {
        let parsed = parsed_with_headers(
            "abp-both-ct",
            &["c: text/plain", "Content-Type: application/sdp"],
            b"v=0\r\n",
        );
        let parts = parsed.all_body_parts();
        assert_eq!(parts[0].content_type(), parsed.content_type());
        assert_eq!(
            parts[0]
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
                .count(),
            1
        );
    }

    #[test]
    fn synthetic_part_omits_content_length() {
        let parsed = parsed_with_headers("abp-len", &["Content-Type: application/sdp"], b"v=0\r\n");
        let parts = parsed.all_body_parts();
        assert_eq!(part_header(&parts[0], "Content-Length"), None);
        assert_eq!(part_header(&parts[0], "l"), None);
    }

    #[test]
    fn synthetic_part_copies_only_content_headers() {
        let parsed = parsed_with_headers(
            "abp-other",
            &[
                "Content-Type: application/sdp",
                "Subject: not a body header",
            ],
            b"v=0\r\n",
        );
        let parts = parsed.all_body_parts();
        assert_eq!(part_header(&parts[0], "Subject"), None);
        assert_eq!(part_header(&parts[0], "Call-ID"), None);
    }

    #[test]
    fn wire_parts_get_no_fabricated_headers() {
        let msg = make_multipart_invite("wire-hdrs", &[("application/sdp", b"v=0\r\n")]);
        let mut content = msg.content.clone();
        let insert_at = CRLF.find(&content).unwrap() + 2;
        content.splice(
            insert_at..insert_at,
            b"Content-Transfer-Encoding: base64\r\n".iter().copied(),
        );
        let parsed = make_sip_message(&content).parse().unwrap();
        let parts = parsed.all_body_parts();
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].content_transfer_encoding(),
            None,
            "a wire part carries what the sender wrote, nothing copied down"
        );
    }

    // --- nested multipart (caller-driven descent) ---

    /// INVITE whose body is a multipart carrying SDP beside a nested
    /// multipart/mixed that holds the PIDF-LO.
    fn make_nested_multipart_invite() -> SipMessage {
        let mut inner = Vec::new();
        inner.extend_from_slice(b"--inner\r\n");
        inner.extend_from_slice(b"Content-Type: application/pidf+xml\r\n\r\n");
        inner.extend_from_slice(b"<presence/>");
        inner.extend_from_slice(b"\r\n--inner--");

        let mut body = Vec::new();
        body.extend_from_slice(b"--outer\r\n");
        body.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
        body.extend_from_slice(b"v=0\r\n");
        body.extend_from_slice(b"\r\n--outer\r\n");
        body.extend_from_slice(b"Content-Type: multipart/mixed;boundary=inner\r\n\r\n");
        body.extend_from_slice(&inner);
        body.extend_from_slice(b"\r\n--outer--");

        let mut content = Vec::new();
        content.extend_from_slice(b"INVITE sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: nested@host\r\n");
        content.extend_from_slice(b"Content-Type: multipart/mixed;boundary=outer\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(&body);

        make_sip_message(&content)
    }

    #[test]
    fn nested_multipart_not_flattened() {
        let parsed = make_nested_multipart_invite().parse().unwrap();
        let parts = parsed.all_body_parts();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].media_type().as_deref(), Some("application/sdp"));
        assert_eq!(parts[1].media_type().as_deref(), Some("multipart/mixed"));
    }

    #[test]
    fn nested_multipart_explicit_descent() {
        let parsed = make_nested_multipart_invite().parse().unwrap();
        let outer = parsed.all_body_parts();
        let nested = &outer[1];

        assert!(nested.is_multipart());
        assert_eq!(nested.multipart_boundary(), Some("inner"));

        let inner = nested.body_parts().unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(
            inner[0].media_type().as_deref(),
            Some("application/pidf+xml")
        );
        assert_eq!(inner[0].body, b"<presence/>");
    }

    #[test]
    fn non_multipart_part_has_no_children() {
        let parsed = make_nested_multipart_invite().parse().unwrap();
        let sdp_part = &parsed.all_body_parts()[0];
        assert!(!sdp_part.is_multipart());
        assert!(sdp_part.multipart_boundary().is_none());
        assert!(sdp_part.body_parts().is_none());
    }

    // --- sipfrag tests ---

    #[test]
    fn sipfrag_status_line_with_crlf() {
        let frag = parse_sipfrag(b"SIP/2.0 200 OK\r\n").unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Response {
                code: 200,
                reason: "OK".into()
            })
        );
        assert!(frag.headers.is_empty());
        assert!(frag.body.is_empty());
    }

    #[test]
    fn sipfrag_status_line_without_trailing_crlf() {
        let frag = parse_sipfrag(b"SIP/2.0 183 Session Progress").unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Response {
                code: 183,
                reason: "Session Progress".into()
            })
        );
    }

    #[test]
    fn sipfrag_headers_only() {
        let frag = parse_sipfrag(b"To: <sip:user@host>\r\nCSeq: 1 INVITE\r\n").unwrap();
        assert_eq!(frag.message_type, None);
        assert_eq!(frag.headers.len(), 2);
        assert_eq!(frag.headers[0].0, "To");
        assert_eq!(frag.headers[0].1, "<sip:user@host>");
        assert_eq!(frag.headers[1].1, "1 INVITE");
    }

    #[test]
    fn sipfrag_header_value_is_case_insensitive() {
        let frag = parse_sipfrag(b"To: <sip:user@host>\r\nCSeq: 1 INVITE\r\n").unwrap();
        assert_eq!(frag.header_value("cseq"), Some("1 INVITE"));
        assert_eq!(frag.header_value("To"), Some("<sip:user@host>"));
        assert_eq!(frag.header_value("Call-ID"), None);
    }

    #[test]
    fn sipfrag_headers_only_without_trailing_crlf() {
        let frag = parse_sipfrag(b"To: <sip:user@host>").unwrap();
        assert_eq!(frag.message_type, None);
        assert_eq!(frag.headers.len(), 1);
        assert_eq!(frag.headers[0].1, "<sip:user@host>");
    }

    #[test]
    fn sipfrag_start_line_headers_and_body() {
        let data = b"SIP/2.0 200 OK\r\n\
            Content-Type: application/sdp\r\n\
            \r\n\
            v=0\r\n";
        let frag = parse_sipfrag(data).unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Response {
                code: 200,
                reason: "OK".into()
            })
        );
        assert_eq!(frag.headers.len(), 1);
        assert_eq!(frag.body, b"v=0\r\n");
    }

    #[test]
    fn sipfrag_request_start_line() {
        let frag = parse_sipfrag(b"INVITE sip:user@host SIP/2.0\r\nCSeq: 2 INVITE\r\n").unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Request {
                method: "INVITE".into(),
                uri: "sip:user@host".into()
            })
        );
        assert_eq!(frag.headers.len(), 1);
    }

    #[test]
    fn sipfrag_garbage_is_error() {
        assert!(parse_sipfrag(b"just some text without a colon").is_err());
        assert!(parse_sipfrag(b"").is_err());
    }

    #[test]
    fn sipfrag_malformed_start_line_with_colon_is_error() {
        assert!(parse_sipfrag(b"INVITE sip:host SIP/1.0\r\n").is_err());
    }

    #[test]
    fn sipfrag_lf_only_status_line() {
        let frag = parse_sipfrag(b"SIP/2.0 200 OK\n").unwrap();
        assert!(matches!(
            frag.message_type,
            Some(SipMessageType::Response { code: 200, ref reason }) if reason == "OK"
        ));
        assert!(frag.headers.is_empty());
        assert!(frag.body.is_empty());
    }

    #[test]
    fn sipfrag_from_mime_part() {
        let body = b"SIP/2.0 100 Trying\r\n";
        let msg = make_multipart_invite("frag-boundary", &[("message/sipfrag", body)]);
        let parsed = msg.parse().unwrap();
        let parts = parsed.all_body_parts();
        assert_eq!(parts[0].media_type().as_deref(), Some("message/sipfrag"));

        let frag = parts[0].parse_sipfrag().unwrap();
        assert_eq!(
            frag.message_type,
            Some(SipMessageType::Response {
                code: 100,
                reason: "Trying".into()
            })
        );
    }

    // --- is_json_content_type tests ---

    #[test]
    fn is_json_content_type_application_json() {
        assert!(is_json_content_type("application/json"));
    }

    #[test]
    fn is_json_content_type_plus_json() {
        assert!(is_json_content_type(
            "application/emergencyCallData.AbandonedCall+json"
        ));
    }

    #[test]
    fn is_json_content_type_with_params() {
        assert!(is_json_content_type("application/json; charset=utf-8"));
    }

    #[test]
    fn is_json_content_type_case_insensitive() {
        assert!(is_json_content_type("Application/JSON"));
    }

    #[test]
    fn is_json_content_type_not_text_plain() {
        assert!(!is_json_content_type("text/plain"));
    }

    #[test]
    fn is_json_content_type_not_multipart() {
        assert!(!is_json_content_type("multipart/mixed;boundary=foo"));
    }

    #[test]
    fn is_json_content_type_not_sdp() {
        assert!(!is_json_content_type("application/sdp"));
    }

    // --- unescape_json_body tests ---

    #[test]
    fn unescape_json_basic_escapes() {
        let input = br#"{"key":"line1\r\nline2\ttab\"\\"}"#;
        let result = unescape_json_body(input);
        assert!(
            result.contains("line1\r\nline2\ttab\"\\"),
            "basic escapes not unescaped: {result:?}"
        );
    }

    #[test]
    fn unescape_json_slash_and_control() {
        let input = br#"{"a":"\/path","b":"\b\f"}"#;
        let result = unescape_json_body(input);
        assert!(result.contains("/path"), "\\/ should become /");
        assert!(result.contains('\x08'), "\\b should become backspace");
        assert!(result.contains('\x0C'), "\\f should become form feed");
    }

    #[test]
    fn unescape_json_unicode_basic() {
        // \u0041 = 'A'
        let input = br#"{"x":"\u0041"}"#;
        let result = unescape_json_body(input);
        assert!(
            result.contains('A'),
            "\\u0041 should become 'A': {result:?}"
        );
    }

    #[test]
    fn unescape_json_unicode_surrogate_pair() {
        // U+1F600 (grinning face) = \uD83D\uDE00
        let input = br#"{"emoji":"\uD83D\uDE00"}"#;
        let result = unescape_json_body(input);
        assert!(
            result.contains('\u{1F600}'),
            "surrogate pair should produce U+1F600: {result:?}"
        );
    }

    #[test]
    fn unescape_json_passthrough_non_escape() {
        let input = b"no escapes here";
        let result = unescape_json_body(input);
        assert_eq!(result, "no escapes here");
    }

    // --- json_field tests ---

    #[test]
    fn json_field_extract_string() {
        let body = br#"{"event":"AbandonedCall","id":"123"}"#;
        let mut content = Vec::new();
        content.extend_from_slice(b"NOTIFY sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: jf-test@host\r\n");
        content.extend_from_slice(b"Content-Type: application/json\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.json_field("event"),
            Some("AbandonedCall".to_string())
        );
        assert_eq!(parsed.json_field("id"), Some("123".to_string()));
    }

    #[test]
    fn json_field_missing_key() {
        let body = br#"{"event":"AbandonedCall"}"#;
        let mut content = Vec::new();
        content.extend_from_slice(b"NOTIFY sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: jf-miss@host\r\n");
        content.extend_from_slice(b"Content-Type: application/json\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.json_field("nonexistent"), None);
    }

    #[test]
    fn json_field_non_string_value() {
        let body = br#"{"count":42,"active":true}"#;
        let mut content = Vec::new();
        content.extend_from_slice(b"NOTIFY sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: jf-nonstr@host\r\n");
        content.extend_from_slice(b"Content-Type: application/json\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.json_field("count"), None);
        assert_eq!(parsed.json_field("active"), None);
    }

    #[test]
    fn json_field_non_json_content_type() {
        let body = br#"{"event":"AbandonedCall"}"#;
        let mut content = Vec::new();
        content.extend_from_slice(b"NOTIFY sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: jf-nonjson@host\r\n");
        content.extend_from_slice(b"Content-Type: text/plain\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(parsed.json_field("event"), None);
    }

    #[test]
    fn json_field_unescapes_value() {
        let body = br#"{"invite":"INVITE sip:host\r\nTo: <sip:host>\r\n"}"#;
        let mut content = Vec::new();
        content.extend_from_slice(b"NOTIFY sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: jf-unescape@host\r\n");
        content.extend_from_slice(b"Content-Type: application/json\r\n");
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        let invite = parsed.json_field("invite").unwrap();
        assert!(
            invite.contains("INVITE sip:host\r\nTo: <sip:host>\r\n"),
            "json_field should return unescaped string: {invite:?}"
        );
    }

    #[test]
    fn json_field_plus_json_content_type() {
        let body = br#"{"cancelTimestamp":"2025-12-14T05:35:03.269Z"}"#;
        let mut content = Vec::new();
        content.extend_from_slice(b"NOTIFY sip:host SIP/2.0\r\n");
        content.extend_from_slice(b"Call-ID: jf-plus@host\r\n");
        content.extend_from_slice(
            b"Content-Type: application/emergencyCallData.AbandonedCall+json\r\n",
        );
        content.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        content.extend_from_slice(b"\r\n");
        content.extend_from_slice(body);

        let msg = make_sip_message(&content);
        let parsed = msg.parse().unwrap();

        assert_eq!(
            parsed.json_field("cancelTimestamp"),
            Some("2025-12-14T05:35:03.269Z".to_string())
        );
    }

    #[test]
    fn whitespace_only_returns_transport_noise() {
        use crate::frame::ParseError;

        for content in [b"\n".as_slice(), b"\r\n", b"\n\n\n", b" \t\r\n"] {
            let msg = SipMessage {
                direction: Direction::Recv,
                transport: Transport::Tls,
                address: "[10.0.0.1]:5061".into(),
                timestamp: Timestamp::TimeOnly {
                    hour: 0,
                    min: 0,
                    sec: 0,
                    usec: 0,
                },
                content: content.to_vec(),
                frame_count: 1,
            };
            let err = msg.parse().unwrap_err();
            assert!(
                matches!(err, ParseError::TransportNoise { .. }),
                "whitespace-only content {:?} should produce TransportNoise, got: {err}",
                content,
            );
        }
    }
}
