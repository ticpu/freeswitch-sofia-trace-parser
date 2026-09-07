mod common;

use freeswitch_sofia_trace_parser::types::{ParseStats, SipMessageType, SkipTracking, Transport};
use freeswitch_sofia_trace_parser::{MessageIterator, ParsedMessageIterator, ParsedSipMessage};

use common::{
    assert_parse_stats, method_histogram, open_sample, MIN_HEADER_PRESENCE, MIN_PARSE_SUCCESS,
};

struct ParseResult {
    parsed: Vec<ParsedSipMessage>,
    errors: usize,
    total: usize,
    stats: ParseStats,
}

fn parse_file(name: &str) -> ParseResult {
    let Some(file) = open_sample(name) else {
        return ParseResult {
            parsed: vec![],
            errors: 0,
            total: 0,
            stats: ParseStats::default(),
        };
    };
    let mut iter = ParsedMessageIterator::new(file).skip_tracking(SkipTracking::TrackRegions);
    let mut parsed = Vec::new();
    let mut errors = 0;
    let mut total = 0;
    for result in iter.by_ref() {
        total += 1;
        match result {
            Ok(msg) => parsed.push(msg),
            Err(_) => errors += 1,
        }
    }
    if errors > 0 {
        eprintln!(
            "{name}: {errors}/{total} messages failed to parse ({:.3}%)",
            errors as f64 / total as f64 * 100.0
        );
    }
    let stats = iter.parse_stats().clone();
    ParseResult {
        parsed,
        errors,
        total,
        stats,
    }
}

const TCP_LIKE_FILES: &[&str] = &[
    "esinet1-v4-tcp.dump.20",
    "esinet1-v4-tcp.dump.4",
    "esinet1-v6-tcp.dump.205",
];

#[test]
fn tcp_like_messages_parse() {
    for name in TCP_LIKE_FILES {
        let result = parse_file(name);
        if result.total == 0 {
            continue;
        }
        assert_parse_stats(&result.stats, name, 1);
        let msgs = &result.parsed;

        eprintln!(
            "{name}: {} parsed, {} errors out of {} total",
            msgs.len(),
            result.errors,
            result.total
        );

        let requests = msgs
            .iter()
            .filter(|m| matches!(m.message_type, SipMessageType::Request { .. }))
            .count();
        let responses = msgs
            .iter()
            .filter(|m| matches!(m.message_type, SipMessageType::Response { .. }))
            .count();
        eprintln!("  requests: {requests}, responses: {responses}");

        assert!(requests > 0, "{name}: should have requests");
        assert!(responses > 0, "{name}: should have responses");

        let success_rate = msgs.len() as f64 / result.total as f64;
        assert!(
            success_rate > MIN_PARSE_SUCCESS,
            "{name}: parse success rate too low: {:.3}%",
            success_rate * 100.0
        );

        assert!(!msgs.is_empty(), "{name}: no messages parsed");
        let with_callid = msgs.iter().filter(|m| m.call_id().is_some()).count();
        let ratio = with_callid as f64 / msgs.len() as f64;
        eprintln!(
            "  with Call-ID: {with_callid}/{} ({:.1}%)",
            msgs.len(),
            ratio * 100.0
        );
        assert!(
            ratio > MIN_HEADER_PRESENCE,
            "{name}: expected >{:.0}% of messages to have Call-ID, got {:.1}%",
            MIN_HEADER_PRESENCE * 100.0,
            ratio * 100.0
        );
    }
}

const UDP_LIKE_FILES: &[&str] = &["esinet1-v4-udp.dump.20", "esinet1-v6-udp.dump.205"];

#[test]
fn udp_like_messages_parse() {
    for name in UDP_LIKE_FILES {
        let result = parse_file(name);
        if result.total == 0 {
            continue;
        }
        assert_parse_stats(&result.stats, name, 1);
        let msgs = &result.parsed;

        eprintln!("{name}: {} parsed messages", msgs.len());
        assert!(!msgs.is_empty(), "{name}: no messages parsed");
        assert!(
            msgs.iter().all(|m| m.transport == Transport::Udp),
            "{name}: expected all UDP messages"
        );
        assert_eq!(
            result.errors, 0,
            "{name}: UDP should have zero parse errors"
        );

        let with_callid = msgs.iter().filter(|m| m.call_id().is_some()).count();
        let ratio = with_callid as f64 / msgs.len() as f64;
        eprintln!(
            "  with Call-ID: {with_callid}/{} ({:.1}%)",
            msgs.len(),
            ratio * 100.0
        );
        assert!(
            ratio > MIN_HEADER_PRESENCE,
            "{name}: expected >{:.0}% of messages to have Call-ID, got {:.1}%",
            MIN_HEADER_PRESENCE * 100.0,
            ratio * 100.0
        );
    }
}

#[test]
fn tcp_method_distribution() {
    let result = parse_file("esinet1-v4-tcp.dump.20");
    if result.total == 0 {
        return;
    }

    let sorted = method_histogram(&result.parsed);

    eprintln!("esinet1-v4-tcp method distribution:");
    for (method, count) in &sorted {
        eprintln!("  {method}: {count}");
    }

    assert!(
        sorted.iter().any(|(m, _)| m == "INVITE"),
        "expected INVITE in method distribution"
    );
    assert!(
        sorted.iter().any(|(m, _)| m == "200"),
        "expected 200 responses in method distribution"
    );
}

#[test]
fn tls_v6_all_messages_parse() {
    let result = parse_file("esinet1-v6-tls.dump.180");
    if result.total == 0 {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v6-tls.dump.180", 1);
    let msgs = &result.parsed;
    assert!(!msgs.is_empty(), "no messages parsed");

    eprintln!("esinet1-v6-tls.dump.180: {} parsed messages", msgs.len());
    assert!(msgs.iter().all(|m| m.transport == Transport::Tls));

    let sorted = method_histogram(msgs);
    eprintln!("  method distribution:");
    for (method, count) in &sorted {
        eprintln!("    {method}: {count}");
    }

    let non_options = msgs
        .iter()
        .filter(|m| m.method() != Some("OPTIONS"))
        .count();
    eprintln!("  non-OPTIONS: {non_options}");
    assert!(non_options > 0, "expected non-OPTIONS traffic in .dump.180");
}

#[test]
fn tls_v4_all_messages_parse() {
    let result = parse_file("esinet1-v4-tls.dump.180");
    if result.total == 0 {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v4-tls.dump.180", 1);
    let msgs = &result.parsed;
    assert!(!msgs.is_empty(), "no messages parsed");

    eprintln!("esinet1-v4-tls.dump.180: {} parsed messages", msgs.len());
    assert!(msgs.iter().all(|m| m.transport == Transport::Tls));

    let with_callid = msgs.iter().filter(|m| m.call_id().is_some()).count();
    eprintln!("  with Call-ID: {with_callid}/{}", msgs.len());
}

#[test]
fn messages_with_body_have_content_type() {
    let result = parse_file("esinet1-v4-tcp.dump.20");
    if result.total == 0 {
        return;
    }
    let msgs = &result.parsed;

    let with_body: Vec<_> = msgs.iter().filter(|m| !m.body.is_empty()).collect();
    let with_ct = with_body
        .iter()
        .filter(|m| m.content_type().is_some())
        .count();

    eprintln!(
        "messages with body: {}, with Content-Type: {with_ct}",
        with_body.len()
    );
    if !with_body.is_empty() {
        let ratio = with_ct as f64 / with_body.len() as f64;
        assert!(
            ratio > MIN_HEADER_PRESENCE,
            "messages with body should have Content-Type ({:.1}%)",
            ratio * 100.0
        );
    }
}

#[test]
fn cseq_present_on_all_messages() {
    let result = parse_file("esinet1-v4-tcp.dump.20");
    if result.total == 0 {
        return;
    }
    let msgs = &result.parsed;
    assert!(!msgs.is_empty(), "no messages parsed");

    let with_cseq = msgs.iter().filter(|m| m.cseq().is_some()).count();
    let ratio = with_cseq as f64 / msgs.len() as f64;
    eprintln!(
        "with CSeq: {with_cseq}/{} ({:.1}%)",
        msgs.len(),
        ratio * 100.0
    );
    assert!(
        ratio > MIN_HEADER_PRESENCE,
        "expected >{:.0}% with CSeq",
        MIN_HEADER_PRESENCE * 100.0
    );
}

#[test]
fn response_method_extraction() {
    let result = parse_file("esinet1-v4-tcp.dump.20");
    if result.total == 0 {
        return;
    }
    let msgs = &result.parsed;

    let responses: Vec<_> = msgs
        .iter()
        .filter(|m| matches!(m.message_type, SipMessageType::Response { .. }))
        .collect();
    assert!(!responses.is_empty(), "expected response messages");

    let with_method = responses.iter().filter(|m| m.method().is_some()).count();
    let ratio = with_method as f64 / responses.len() as f64;
    eprintln!(
        "responses with method from CSeq: {with_method}/{} ({:.1}%)",
        responses.len(),
        ratio * 100.0
    );
    assert!(
        ratio > MIN_HEADER_PRESENCE,
        "responses should extract method from CSeq"
    );
}

/// `SipMessage::method` reads the method without parsing. Over the whole corpus
/// it must never answer a method the full parse disagrees with; answering
/// nothing is always allowed.
#[test]
fn cheap_method_agrees_with_parsed_method() {
    for name in [
        "esinet1-v4-tcp.dump.20",
        "esinet1-v4-tcp.dump.4",
        "esinet1-v4-udp.dump.20",
        "esinet1-v6-tls.dump.180",
        "internal-v4.dump.20",
        "internal-v6.dump.20",
    ] {
        let Some(file) = open_sample(name) else {
            continue;
        };
        let mut classified = 0usize;
        let mut total = 0usize;
        for msg in MessageIterator::new(file).flatten() {
            total += 1;
            let Some(cheap) = msg.method() else {
                continue;
            };
            let cheap = cheap.to_string();
            classified += 1;
            let parsed = msg.parse().unwrap_or_else(|e| {
                panic!("{name}: classified as {cheap} but failed to parse: {e}")
            });
            assert_eq!(
                parsed.method(),
                Some(cheap.as_str()),
                "{name}: cheap method disagrees with parsed method"
            );
        }
        eprintln!(
            "{name}: {classified}/{total} classified without parsing ({:.1}%)",
            classified as f64 / total as f64 * 100.0
        );
        assert!(
            classified as f64 / total as f64 > MIN_HEADER_PRESENCE,
            "{name}: expected >99% of messages classifiable without a parse"
        );
    }
}

#[test]
fn tcp_multipart_bodies() {
    let result = parse_file("esinet1-v4-tcp.dump.20");
    if result.total == 0 {
        return;
    }
    let msgs = &result.parsed;

    let multipart: Vec<&ParsedSipMessage> = msgs.iter().filter(|m| m.is_multipart()).collect();
    eprintln!("multipart messages: {}", multipart.len());

    if multipart.is_empty() {
        eprintln!("  no multipart messages in TCP dump");
        return;
    }

    let mut ct_distribution: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut total_parts = 0;
    let mut parse_failures = 0;

    for msg in &multipart {
        match msg.body_parts() {
            Some(parts) => {
                total_parts += parts.len();
                for part in &parts {
                    let ct = part.content_type().unwrap_or("(none)").to_string();
                    *ct_distribution.entry(ct).or_default() += 1;
                }
            }
            None => parse_failures += 1,
        }
    }

    eprintln!("  total parts: {total_parts}, parse failures: {parse_failures}");

    let mut sorted: Vec<_> = ct_distribution.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
    eprintln!("  part content-type distribution:");
    for (ct, count) in &sorted {
        eprintln!("    {ct}: {count}");
    }

    assert_eq!(parse_failures, 0, "all multipart messages should split");
    assert!(
        total_parts > multipart.len(),
        "most multipart messages should have multiple parts"
    );
}

#[test]
fn tls_v6_multipart_bodies() {
    let result = parse_file("esinet1-v6-tls.dump.180");
    if result.total == 0 {
        return;
    }
    let msgs = &result.parsed;

    let multipart: Vec<&ParsedSipMessage> = msgs.iter().filter(|m| m.is_multipart()).collect();
    eprintln!("esinet1-v6-tls multipart messages: {}", multipart.len());

    if multipart.is_empty() {
        eprintln!("  no multipart messages in TLS v6 dump");
        return;
    }

    let mut has_sdp = 0;
    let mut has_pidf_or_eido = 0;

    for msg in &multipart {
        if let Some(parts) = msg.body_parts() {
            if parts
                .iter()
                .any(|p| p.content_type() == Some("application/sdp"))
            {
                has_sdp += 1;
            }
            if parts.iter().any(|p| {
                p.content_type().is_some_and(|ct| {
                    ct.contains("pidf") || ct.contains("eido") || ct.contains("xml")
                })
            }) {
                has_pidf_or_eido += 1;
            }
        }
    }

    eprintln!("  with SDP part: {has_sdp}");
    eprintln!("  with PIDF/EIDO/XML part: {has_pidf_or_eido}");

    // Production data pairs multipart bodies as SDP + PIDF/EIDO location XML;
    // a multipart message with neither means the split silently dropped a part.
    assert!(
        has_sdp > 0,
        "expected at least one multipart message with an SDP part"
    );
    assert!(
        has_pidf_or_eido > 0,
        "expected at least one multipart message with a PIDF/EIDO/XML part"
    );
}
