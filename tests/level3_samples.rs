use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use freeswitch_sofia_trace_parser::types::{
    ParseStats, SipMessageType, SkipReason, SkipTracking, Transport,
};
use freeswitch_sofia_trace_parser::{ParsedMessageIterator, ParsedSipMessage};

fn sample_dir() -> &'static Path {
    Path::new("samples")
}

struct ParseResult {
    parsed: Vec<freeswitch_sofia_trace_parser::ParsedSipMessage>,
    errors: usize,
    total: usize,
    stats: ParseStats,
}

fn parse_file(name: &str) -> ParseResult {
    let path = sample_dir().join(name);
    if !path.exists() {
        eprintln!("skipping {name}: file not found");
        return ParseResult {
            parsed: vec![],
            errors: 0,
            total: 0,
            stats: ParseStats::default(),
        };
    }
    let file = File::open(&path).unwrap();
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

fn assert_parse_stats(stats: &ParseStats, name: &str, max_partial: usize) {
    let partial_count = stats
        .unparsed_regions
        .iter()
        .filter(|r| r.reason == SkipReason::PartialFirstFrame)
        .count();
    let invalid_count = stats
        .unparsed_regions
        .iter()
        .filter(|r| r.reason == SkipReason::InvalidHeader)
        .count();

    eprintln!(
        "{name}: bytes_read={}, bytes_skipped={}, regions={} (partial={partial_count}, invalid={invalid_count})",
        stats.bytes_read,
        stats.bytes_skipped,
        stats.unparsed_regions.len(),
    );

    assert!(
        partial_count <= max_partial,
        "{name}: expected at most {max_partial} partial first frame(s), got {partial_count}"
    );
    assert_eq!(
        invalid_count, 0,
        "{name}: expected zero invalid header skips, got {invalid_count}"
    );
}

#[test]
fn tcp_all_messages_parse() {
    let result = parse_file("esinet1-v4-tcp.dump.20");
    if result.total == 0 {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v4-tcp.dump.20", 1);
    let msgs = &result.parsed;

    eprintln!(
        "esinet1-v4-tcp.dump.20: {} parsed, {} errors out of {} total",
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

    assert!(requests > 0, "should have requests");
    assert!(responses > 0, "should have responses");

    // Parse success rate should be very high (>99.99%)
    let success_rate = msgs.len() as f64 / result.total as f64;
    assert!(
        success_rate > 0.999,
        "parse success rate too low: {:.3}%",
        success_rate * 100.0
    );

    // All parsed messages should have a Call-ID
    let with_callid = msgs.iter().filter(|m| m.call_id().is_some()).count();
    let ratio = with_callid as f64 / msgs.len() as f64;
    eprintln!(
        "  with Call-ID: {with_callid}/{} ({:.1}%)",
        msgs.len(),
        ratio * 100.0
    );
    assert!(
        ratio > 0.99,
        "expected >99% of messages to have Call-ID, got {:.1}%",
        ratio * 100.0
    );
}

#[test]
fn tcp_v4_dump_4_all_parse() {
    let result = parse_file("esinet1-v4-tcp.dump.4");
    if result.total == 0 {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v4-tcp.dump.4", 1);
    let msgs = &result.parsed;

    eprintln!(
        "esinet1-v4-tcp.dump.4: {} parsed, {} errors out of {} total",
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

    assert!(requests > 0, "should have requests");
    assert!(responses > 0, "should have responses");

    let success_rate = msgs.len() as f64 / result.total as f64;
    assert!(
        success_rate > 0.999,
        "parse success rate too low: {:.3}%",
        success_rate * 100.0
    );

    let with_callid = msgs.iter().filter(|m| m.call_id().is_some()).count();
    let ratio = with_callid as f64 / msgs.len() as f64;
    eprintln!(
        "  with Call-ID: {with_callid}/{} ({:.1}%)",
        msgs.len(),
        ratio * 100.0
    );
    assert!(
        ratio > 0.99,
        "expected >99% of messages to have Call-ID, got {:.1}%",
        ratio * 100.0
    );
}

#[test]
fn tcp_method_distribution() {
    let result = parse_file("esinet1-v4-tcp.dump.20");
    if result.total == 0 {
        return;
    }

    let mut methods: HashMap<String, usize> = HashMap::new();
    for msg in &result.parsed {
        let method = match &msg.message_type {
            SipMessageType::Request { method, .. } => method.clone(),
            SipMessageType::Response { code, .. } => format!("{code}"),
        };
        *methods.entry(method).or_default() += 1;
    }

    let mut sorted: Vec<_> = methods.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));

    eprintln!("esinet1-v4-tcp method distribution:");
    for (method, count) in &sorted {
        eprintln!("  {method}: {count}");
    }
}

#[test]
fn udp_all_messages_parse() {
    let result = parse_file("esinet1-v4-udp.dump.20");
    if result.total == 0 {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v4-udp.dump.20", 1);
    let msgs = &result.parsed;

    eprintln!("esinet1-v4-udp.dump.20: {} parsed messages", msgs.len());
    assert!(msgs.iter().all(|m| m.transport == Transport::Udp));
    assert_eq!(result.errors, 0, "UDP should have zero parse errors");

    let with_callid = msgs.iter().filter(|m| m.call_id().is_some()).count();
    let ratio = with_callid as f64 / msgs.len() as f64;
    eprintln!(
        "  with Call-ID: {with_callid}/{} ({:.1}%)",
        msgs.len(),
        ratio * 100.0
    );
    assert!(ratio > 0.99);
}

#[test]
fn tls_v6_all_messages_parse() {
    let result = parse_file("esinet1-v6-tls.dump.180");
    if result.total == 0 {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v6-tls.dump.180", 1);
    let msgs = &result.parsed;

    eprintln!("esinet1-v6-tls.dump.180: {} parsed messages", msgs.len());
    assert!(msgs.iter().all(|m| m.transport == Transport::Tls));

    let mut methods: HashMap<String, usize> = HashMap::new();
    for msg in msgs {
        let method = match &msg.message_type {
            SipMessageType::Request { method, .. } => method.clone(),
            SipMessageType::Response { code, .. } => format!("{code}"),
        };
        *methods.entry(method).or_default() += 1;
    }

    let mut sorted: Vec<_> = methods.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));

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

    eprintln!("esinet1-v4-tls.dump.180: {} parsed messages", msgs.len());
    assert!(msgs.iter().all(|m| m.transport == Transport::Tls));

    let with_callid = msgs.iter().filter(|m| m.call_id().is_some()).count();
    eprintln!("  with Call-ID: {with_callid}/{}", msgs.len());
}

#[test]
fn tcp_v6_all_messages_parse() {
    let result = parse_file("esinet1-v6-tcp.dump.205");
    if result.total == 0 {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v6-tcp.dump.205", 1);
    let msgs = &result.parsed;

    eprintln!(
        "esinet1-v6-tcp.dump.205: {} parsed, {} errors out of {} total",
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

    assert!(requests > 0, "should have requests");
    assert!(responses > 0, "should have responses");

    let success_rate = msgs.len() as f64 / result.total as f64;
    assert!(
        success_rate > 0.999,
        "parse success rate too low: {:.3}%",
        success_rate * 100.0
    );
}

#[test]
fn udp_v6_all_messages_parse() {
    let result = parse_file("esinet1-v6-udp.dump.205");
    if result.total == 0 {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v6-udp.dump.205", 1);
    let msgs = &result.parsed;

    eprintln!("esinet1-v6-udp.dump.205: {} parsed messages", msgs.len());
    assert!(msgs.iter().all(|m| m.transport == Transport::Udp));

    let with_callid = msgs.iter().filter(|m| m.call_id().is_some()).count();
    let ratio = with_callid as f64 / msgs.len() as f64;
    eprintln!(
        "  with Call-ID: {with_callid}/{} ({:.1}%)",
        msgs.len(),
        ratio * 100.0
    );
    assert!(ratio > 0.99);
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
            ratio > 0.99,
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

    let with_cseq = msgs.iter().filter(|m| m.cseq().is_some()).count();
    let ratio = with_cseq as f64 / msgs.len() as f64;
    eprintln!(
        "with CSeq: {with_cseq}/{} ({:.1}%)",
        msgs.len(),
        ratio * 100.0
    );
    assert!(ratio > 0.99, "expected >99% with CSeq");
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

    let with_method = responses.iter().filter(|m| m.method().is_some()).count();
    let ratio = with_method as f64 / responses.len() as f64;
    eprintln!(
        "responses with method from CSeq: {with_method}/{} ({:.1}%)",
        responses.len(),
        ratio * 100.0
    );
    assert!(ratio > 0.99, "responses should extract method from CSeq");
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

    let mut ct_distribution: HashMap<String, usize> = HashMap::new();
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
}
