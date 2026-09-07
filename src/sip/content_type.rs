use std::borrow::Cow;

use sip_header::SipHeader;

use crate::types::Headers;

/// Canonical name of an RFC 3261 §7.3.3 compact form, `None` for any other
/// header name.
fn expand_compact(name: &str) -> Option<&'static str> {
    let [ch] = name.as_bytes() else {
        return None;
    };
    SipHeader::from_compact(*ch).map(|header| header.as_str())
}

/// Value recorded under `name` or under the compact form that expands to it,
/// preferring the full name wherever the message carries both.
pub(crate) fn value_or_compact<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    let mut compact = None;
    for (key, value) in headers.iter() {
        if key.eq_ignore_ascii_case(name) {
            return Some(value);
        }
        if compact.is_none()
            && key.len() == 1
            && expand_compact(key).is_some_and(|full| full.eq_ignore_ascii_case(name))
        {
            compact = Some(value.as_str());
        }
    }
    compact
}

/// Strip parameters from a Content-Type value and normalize to lowercase.
/// Borrows when the type/subtype is already lowercase and unpadded.
pub(crate) fn normalize_media_type(ct: &str) -> Cow<'_, str> {
    let base = ct.split(';').next().unwrap_or("").trim();
    if base.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(base.to_ascii_lowercase())
    } else {
        Cow::Borrowed(base)
    }
}

/// Canonical name of a body-describing header, `None` otherwise. Excludes
/// `Content-Length`: it goes stale once a consumer rewrites the part.
pub(crate) fn canonical_body_header(name: &str) -> Option<&str> {
    let name = expand_compact(name).unwrap_or(name);
    if name.eq_ignore_ascii_case("Content-Length") {
        return None;
    }
    name.as_bytes()
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"content-"))
        .then_some(name)
}

/// Returns `true` for `application/json` and any `application/*+json` subtype.
/// Case-insensitive; media type parameters are ignored.
pub fn is_json_content_type(ct: &str) -> bool {
    let media_type = normalize_media_type(ct);
    media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
}

pub(crate) fn extract_boundary(content_type: &str) -> Option<&str> {
    content_type.split(';').skip(1).find_map(|param| {
        let (key, value) = param.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim();
        let value = match value.strip_prefix('"') {
            Some(quoted) => quoted.split('"').next().unwrap_or(quoted),
            None => value,
        };
        (!value.is_empty()).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::test_support::{make_multipart_invite, make_sip_message};
    use crate::types::ParsedSipMessage;

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
    fn extract_boundary_only_from_its_own_parameter() {
        assert_eq!(
            extract_boundary("multipart/mixed; x-boundary=decoy; boundary=real"),
            Some("real")
        );
        assert_eq!(
            extract_boundary("multipart/mixed; name=\"boundary=decoy\"; boundary=real"),
            Some("real")
        );
    }

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
}
