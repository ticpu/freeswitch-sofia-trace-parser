use std::borrow::Cow;

use crate::types::expand_compact;

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

    fn boundary_of(content_type: &str) -> Option<String> {
        make_with_content_type(&format!("Content-Type: {content_type}"))
            .multipart_boundary()
            .map(str::to_string)
    }

    #[test]
    fn extract_boundary_unquoted() {
        assert_eq!(
            boundary_of("multipart/mixed;boundary=foo-bar").as_deref(),
            Some("foo-bar")
        );
    }

    #[test]
    fn extract_boundary_quoted() {
        assert_eq!(
            boundary_of("multipart/mixed; boundary=\"foo-bar\"").as_deref(),
            Some("foo-bar")
        );
    }

    #[test]
    fn extract_boundary_with_extra_params() {
        assert_eq!(
            boundary_of("multipart/mixed; boundary=foo;charset=utf-8").as_deref(),
            Some("foo")
        );
    }

    #[test]
    fn extract_boundary_case_insensitive() {
        assert_eq!(
            boundary_of("multipart/mixed;BOUNDARY=abc").as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn extract_boundary_missing() {
        assert_eq!(boundary_of("multipart/mixed"), None);
    }

    #[test]
    fn extract_boundary_only_from_its_own_parameter() {
        assert_eq!(
            boundary_of("multipart/mixed; x-boundary=decoy; boundary=real").as_deref(),
            Some("real")
        );
        assert_eq!(
            boundary_of("multipart/mixed; name=\"boundary=decoy\"; boundary=real").as_deref(),
            Some("real")
        );
    }

    #[test]
    fn is_json_content_type_table() {
        for ct in [
            "application/json",
            "application/emergencyCallData.AbandonedCall+json",
            "application/json; charset=utf-8",
            "Application/JSON",
        ] {
            assert!(is_json_content_type(ct), "should be JSON: {ct}");
        }
        for ct in [
            "text/plain",
            "multipart/mixed;boundary=foo",
            "application/sdp",
        ] {
            assert!(!is_json_content_type(ct), "should not be JSON: {ct}");
        }
    }
}
