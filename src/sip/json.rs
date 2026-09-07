use std::borrow::Cow;

use crate::sip::HasHeaders;
use crate::types::{MimePart, ParsedSipMessage};

impl ParsedSipMessage {
    /// Content-type-aware body text. For JSON content types (`application/json`
    /// and `application/*+json`), unescapes RFC 8259 string sequences
    /// (`\r\n` to CRLF, `\t` to tab, `\uXXXX` to Unicode). Passthrough for
    /// all other content types.
    pub fn body_text(&self) -> Cow<'_, str> {
        HasHeaders::body_text(self)
    }

    /// Parse the body as JSON and return the unescaped string value of a
    /// top-level key. Returns `None` if the content type is not JSON, the
    /// body is invalid JSON, the key is missing, or the value is not a string.
    pub fn json_field(&self, key: &str) -> Option<String> {
        HasHeaders::json_field(self, key)
    }
}

impl MimePart {
    /// Content-type-aware body text, as for
    /// [`ParsedSipMessage::body_text`]: JSON parts come back unescaped,
    /// everything else passes through as lossy UTF-8.
    pub fn body_text(&self) -> Cow<'_, str> {
        HasHeaders::body_text(self)
    }

    /// Parse this part's body as JSON and return the unescaped string value of
    /// a top-level key, as for [`ParsedSipMessage::json_field`].
    pub fn json_field(&self, key: &str) -> Option<String> {
        HasHeaders::json_field(self, key)
    }
}

pub(crate) fn unescape_json_body(input: &[u8]) -> String {
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
    use crate::sip::test_support::parsed_with_headers;

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
    fn body_text_non_json_passthrough() {
        let msg = parsed_with_headers(
            "bt-sdp",
            &["Content-Type: application/sdp"],
            b"v=0\r\ns=-\r\n",
        );
        assert_eq!(msg.body_text().as_ref(), msg.body_data().as_ref());
    }

    #[test]
    fn body_text_json_unescapes_newlines() {
        let msg = parsed_with_headers(
            "bt-json",
            &["Content-Type: application/json"],
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
        let msg = parsed_with_headers(
            "bt-plus-json",
            &["Content-Type: application/emergencyCallData.AbandonedCall+json"],
            br#"{"invite":"line1\nline2"}"#,
        );
        let text = msg.body_text();
        assert!(
            text.contains("line1\nline2"),
            "application/*+json should trigger unescaping, got: {text:?}"
        );
    }

    #[test]
    fn json_field_extract_string() {
        let parsed = parsed_with_headers(
            "jf-test",
            &["Content-Type: application/json"],
            br#"{"event":"AbandonedCall","id":"123"}"#,
        );
        assert_eq!(
            parsed.json_field("event"),
            Some("AbandonedCall".to_string())
        );
        assert_eq!(parsed.json_field("id"), Some("123".to_string()));
    }

    #[test]
    fn json_field_missing_key() {
        let parsed = parsed_with_headers(
            "jf-miss",
            &["Content-Type: application/json"],
            br#"{"event":"AbandonedCall"}"#,
        );
        assert_eq!(parsed.json_field("nonexistent"), None);
    }

    #[test]
    fn json_field_non_string_value() {
        let parsed = parsed_with_headers(
            "jf-nonstr",
            &["Content-Type: application/json"],
            br#"{"count":42,"active":true}"#,
        );
        assert_eq!(parsed.json_field("count"), None);
        assert_eq!(parsed.json_field("active"), None);
    }

    #[test]
    fn json_field_non_json_content_type() {
        let parsed = parsed_with_headers(
            "jf-nonjson",
            &["Content-Type: text/plain"],
            br#"{"event":"AbandonedCall"}"#,
        );
        assert_eq!(parsed.json_field("event"), None);
    }

    #[test]
    fn json_field_unescapes_value() {
        let parsed = parsed_with_headers(
            "jf-unescape",
            &["Content-Type: application/json"],
            br#"{"invite":"INVITE sip:host\r\nTo: <sip:host>\r\n"}"#,
        );
        let invite = parsed.json_field("invite").unwrap();
        assert!(
            invite.contains("INVITE sip:host\r\nTo: <sip:host>\r\n"),
            "json_field should return unescaped string: {invite:?}"
        );
    }

    #[test]
    fn json_field_plus_json_content_type() {
        let parsed = parsed_with_headers(
            "jf-plus",
            &["Content-Type: application/emergencyCallData.AbandonedCall+json"],
            br#"{"cancelTimestamp":"2025-12-14T05:35:03.269Z"}"#,
        );
        assert_eq!(
            parsed.json_field("cancelTimestamp"),
            Some("2025-12-14T05:35:03.269Z".to_string())
        );
    }
}
