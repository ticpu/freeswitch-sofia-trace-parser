use quoted_printable::{encode_with_options, InputMode, Options};

pub fn encode_qp(data: &[u8]) -> String {
    let opts = Options::default()
        .input_mode(InputMode::Binary)
        .line_length_limit(usize::MAX);
    encode_with_options(data, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_passthrough() {
        assert_eq!(encode_qp(b"Content-Length: 0"), "Content-Length: 0");
    }

    #[test]
    fn crlf_encoded() {
        assert_eq!(
            encode_qp(b"\r\n\r\nContent-Length: 0"),
            "=0D=0A=0D=0AContent-Length: 0"
        );
    }

    #[test]
    fn binary_encoded() {
        assert_eq!(encode_qp(&[0x00, 0x01, 0xFF]), "=00=01=FF");
    }

    #[test]
    fn equals_sign_encoded() {
        assert_eq!(encode_qp(b"a=b"), "a=3Db");
    }

    #[test]
    fn no_soft_line_breaks() {
        let long = "A".repeat(200);
        let encoded = encode_qp(long.as_bytes());
        assert!(!encoded.contains('='), "should not insert soft line breaks");
        assert_eq!(encoded, long);
    }
}
