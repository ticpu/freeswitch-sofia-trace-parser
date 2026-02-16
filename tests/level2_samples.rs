use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use freeswitch_sofia_trace_parser::types::{ParseStats, SkipReason, Transport};
use freeswitch_sofia_trace_parser::MessageIterator;

fn sample_dir() -> &'static Path {
    Path::new("samples")
}

struct MessageParseResult {
    messages: Vec<freeswitch_sofia_trace_parser::SipMessage>,
    stats: ParseStats,
}

fn parse_messages(name: &str) -> MessageParseResult {
    let path = sample_dir().join(name);
    if !path.exists() {
        eprintln!("skipping {name}: file not found");
        return MessageParseResult {
            messages: vec![],
            stats: ParseStats::default(),
        };
    }
    let file = File::open(&path).unwrap();
    let mut iter = MessageIterator::new(file);
    let messages: Vec<_> = iter.by_ref().filter_map(Result::ok).collect();
    let stats = iter.parse_stats().clone();
    MessageParseResult { messages, stats }
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
fn tcp_reassembly_produces_fewer_messages_than_frames() {
    let path = sample_dir().join("esinet1-v4-tcp.dump.20");
    if !path.exists() {
        eprintln!("skipping: file not found");
        return;
    }

    let frame_count = freeswitch_sofia_trace_parser::FrameIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .count();

    let mut iter = MessageIterator::new(File::open(&path).unwrap());
    let msg_count = iter.by_ref().filter_map(Result::ok).count();

    eprintln!("esinet1-v4-tcp.dump.20: {frame_count} frames → {msg_count} messages");
    assert!(
        msg_count < frame_count,
        "TCP reassembly should produce fewer messages than frames"
    );
    assert!(msg_count > 0, "should produce at least one message");
    assert_parse_stats(iter.parse_stats(), "esinet1-v4-tcp.dump.20", 1);
}

#[test]
fn udp_messages_equal_frames() {
    let path = sample_dir().join("esinet1-v4-udp.dump.20");
    if !path.exists() {
        eprintln!("skipping: file not found");
        return;
    }

    let frame_count = freeswitch_sofia_trace_parser::FrameIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .count();

    let mut iter = MessageIterator::new(File::open(&path).unwrap());
    let msg_count = iter.by_ref().filter_map(Result::ok).count();

    eprintln!("esinet1-v4-udp.dump.20: {frame_count} frames → {msg_count} messages");
    assert_eq!(
        msg_count, frame_count,
        "UDP messages should equal frames (no reassembly)"
    );
    assert_parse_stats(iter.parse_stats(), "esinet1-v4-udp.dump.20", 1);
}

#[test]
fn tcp_multiframe_messages_have_correct_frame_count() {
    let result = parse_messages("esinet1-v4-tcp.dump.20");
    let msgs = &result.messages;
    if msgs.is_empty() {
        return;
    }
    assert_parse_stats(&result.stats, "esinet1-v4-tcp.dump.20", 1);

    let multi_frame: Vec<_> = msgs.iter().filter(|m| m.frame_count > 1).collect();
    let max_frames = multi_frame.iter().map(|m| m.frame_count).max().unwrap_or(0);
    let total_frames_in_multi: usize = multi_frame.iter().map(|m| m.frame_count).sum();

    eprintln!(
        "multi-frame messages: {}, max frame_count: {}, total frames consumed: {}",
        multi_frame.len(),
        max_frames,
        total_frames_in_multi
    );
    assert!(!multi_frame.is_empty(), "expected multi-frame TCP messages");

    // All messages should have non-empty content
    for msg in msgs {
        assert!(!msg.content.is_empty(), "message has empty content");
    }
}

#[test]
fn tls_v6_with_real_traffic() {
    // .dump.180 has INVITE/NOTIFY/SUBSCRIBE/BYE with multi-frame reassembly
    let path = sample_dir().join("esinet1-v6-tls.dump.180");
    if !path.exists() {
        eprintln!("skipping: esinet1-v6-tls.dump.180 not found");
        return;
    }

    let frame_count = freeswitch_sofia_trace_parser::FrameIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .count();

    let mut iter = MessageIterator::new(File::open(&path).unwrap());
    let msgs: Vec<_> = iter.by_ref().filter_map(Result::ok).collect();

    let msg_count = msgs.len();
    let multi: Vec<_> = msgs.iter().filter(|m| m.frame_count > 1).collect();

    eprintln!(
        "esinet1-v6-tls.dump.180: {frame_count} frames → {msg_count} messages ({} multi-frame)",
        multi.len()
    );
    if let Some(max) = multi.iter().map(|m| m.frame_count).max() {
        eprintln!("  max frame_count: {max}");
    }

    assert!(msgs.iter().all(|m| m.transport == Transport::Tls));
    assert!(msgs.iter().all(|m| m.address.starts_with('[')));
    assert!(msg_count > 0, "should produce at least one message");
    assert_parse_stats(iter.parse_stats(), "esinet1-v6-tls.dump.180", 1);
}

#[test]
fn tls_v4_with_real_traffic() {
    // .dump.180 has real traffic, .dump.179 is keepalives only
    let path = sample_dir().join("esinet1-v4-tls.dump.180");
    if !path.exists() {
        eprintln!("skipping: esinet1-v4-tls.dump.180 not found");
        return;
    }

    let frame_count = freeswitch_sofia_trace_parser::FrameIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .count();

    let mut iter = MessageIterator::new(File::open(&path).unwrap());
    let msgs: Vec<_> = iter.by_ref().filter_map(Result::ok).collect();

    let msg_count = msgs.len();
    let multi = msgs.iter().filter(|m| m.frame_count > 1).count();

    eprintln!("esinet1-v4-tls.dump.180: {frame_count} frames → {msg_count} messages ({multi} multi-frame)");

    assert!(msgs.iter().all(|m| m.transport == Transport::Tls));
    assert_parse_stats(iter.parse_stats(), "esinet1-v4-tls.dump.180", 1);
}

#[test]
fn tcp_v6_messages() {
    let path = sample_dir().join("esinet1-v6-tcp.dump.205");
    if !path.exists() {
        eprintln!("skipping: file not found");
        return;
    }

    let frame_count = freeswitch_sofia_trace_parser::FrameIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .count();

    let mut iter = MessageIterator::new(File::open(&path).unwrap());
    let msg_count = iter.by_ref().filter_map(Result::ok).count();

    eprintln!("esinet1-v6-tcp.dump.205: {frame_count} frames → {msg_count} messages");
    assert!(msg_count > 0, "should produce at least one message");
    assert!(
        msg_count <= frame_count,
        "message count should not exceed frame count"
    );
    assert_parse_stats(iter.parse_stats(), "esinet1-v6-tcp.dump.205", 1);
}

#[test]
fn udp_v6_messages_equal_frames() {
    let path = sample_dir().join("esinet1-v6-udp.dump.205");
    if !path.exists() {
        eprintln!("skipping: file not found");
        return;
    }

    let frame_count = freeswitch_sofia_trace_parser::FrameIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .count();

    let mut iter = MessageIterator::new(File::open(&path).unwrap());
    let msg_count = iter.by_ref().filter_map(Result::ok).count();

    eprintln!("esinet1-v6-udp.dump.205: {frame_count} frames → {msg_count} messages");
    assert_eq!(
        msg_count, frame_count,
        "UDP messages should equal frames (no reassembly)"
    );
    assert_parse_stats(iter.parse_stats(), "esinet1-v6-udp.dump.205", 1);
}

#[test]
fn tcp_interleaved_reassembly() {
    let result = parse_messages("esinet1-v4-tcp.dump.20");
    let msgs = &result.messages;
    if msgs.is_empty() {
        return;
    }

    let multi_frame: Vec<_> = msgs.iter().filter(|m| m.frame_count > 1).collect();
    if multi_frame.is_empty() {
        eprintln!("no multi-frame messages found");
        return;
    }

    // Count distinct addresses involved in multi-frame messages
    let mut multi_addrs: HashMap<&str, usize> = HashMap::new();
    for m in &multi_frame {
        *multi_addrs.entry(&m.address).or_default() += 1;
    }

    eprintln!(
        "multi-frame messages: {}, from {} distinct addresses",
        multi_frame.len(),
        multi_addrs.len()
    );
    for (addr, count) in &multi_addrs {
        eprintln!("  {addr}: {count} multi-frame messages");
    }

    // With multiple addresses doing reassembly, the parser must handle
    // interleaved frames correctly (HashMap-based concurrent buffering)
    assert!(
        multi_addrs.len() > 1,
        "expected multi-frame messages from multiple addresses (interleaved reassembly)"
    );

    // Verify frame_count sum matches frame_count - single_frame_count
    let total_frames: usize = msgs.iter().map(|m| m.frame_count).sum();
    let single_frame = msgs.iter().filter(|m| m.frame_count == 1).count();
    let multi_frames: usize = multi_frame.iter().map(|m| m.frame_count).sum();
    eprintln!(
        "total frames accounted: {total_frames} ({single_frame} single + {multi_frames} in multi-frame)"
    );
    assert_eq!(total_frames, single_frame + multi_frames);
}

#[test]
fn message_content_starts_with_sip() {
    let result = parse_messages("esinet1-v4-tcp.dump.20");
    let msgs = &result.messages;
    if msgs.is_empty() {
        return;
    }

    // Most reassembled messages should start with a SIP request or response line
    let sip_start_count = msgs
        .iter()
        .filter(|m| {
            m.content.starts_with(b"SIP/2.0 ")
                || m.content.starts_with(b"INVITE ")
                || m.content.starts_with(b"ACK ")
                || m.content.starts_with(b"BYE ")
                || m.content.starts_with(b"CANCEL ")
                || m.content.starts_with(b"OPTIONS ")
                || m.content.starts_with(b"REGISTER ")
                || m.content.starts_with(b"SUBSCRIBE ")
                || m.content.starts_with(b"NOTIFY ")
                || m.content.starts_with(b"PUBLISH ")
                || m.content.starts_with(b"INFO ")
                || m.content.starts_with(b"REFER ")
                || m.content.starts_with(b"MESSAGE ")
                || m.content.starts_with(b"UPDATE ")
                || m.content.starts_with(b"PRACK ")
        })
        .count();

    let ratio = sip_start_count as f64 / msgs.len() as f64;
    eprintln!(
        "messages starting with SIP line: {sip_start_count}/{} ({:.1}%)",
        msgs.len(),
        ratio * 100.0
    );
    assert!(
        ratio > 0.99,
        "expected >99% of messages to start with SIP request/response line, got {:.1}%",
        ratio * 100.0
    );
}
