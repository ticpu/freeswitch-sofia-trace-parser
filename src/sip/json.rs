use std::borrow::Cow;

use crate::sip::content_type::is_json_content_type;
use crate::types::ParsedSipMessage;

impl ParsedSipMessage {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::test_support::make_sip_message;

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
}
