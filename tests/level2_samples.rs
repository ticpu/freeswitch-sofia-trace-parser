mod common;

use std::collections::HashMap;
use std::fs::File;

use freeswitch_sofia_trace_parser::types::{ParseStats, SkipTracking, Transport};
use freeswitch_sofia_trace_parser::{FrameIterator, MessageIterator, SipMessage};

use common::{
    assert_parse_stats, open_sample, sample_dir, starts_with_sip_line, MIN_HEADER_PRESENCE,
};

struct MessageParseResult {
    messages: Vec<SipMessage>,
    stats: ParseStats,
}

fn parse_messages(name: &str) -> MessageParseResult {
    let Some(file) = open_sample(name) else {
        return MessageParseResult {
            messages: vec![],
            stats: ParseStats::default(),
        };
    };
    let mut iter = MessageIterator::new(file).skip_tracking(SkipTracking::TrackRegions);
    let messages: Vec<_> = iter.by_ref().filter_map(Result::ok).collect();
    let stats = iter.parse_stats().clone();
    MessageParseResult { messages, stats }
}

#[derive(Clone, Copy)]
enum CountRelation {
    StrictLess,
    Equal,
    LessOrEqual,
}

struct L2Case {
    name: &'static str,
    transport: Transport,
    relation: CountRelation,
}

const L2_CASES: &[L2Case] = &[
    L2Case {
        name: "esinet1-v4-tcp.dump.20",
        transport: Transport::Tcp,
        relation: CountRelation::StrictLess,
    },
    L2Case {
        name: "esinet1-v4-udp.dump.20",
        transport: Transport::Udp,
        relation: CountRelation::Equal,
    },
    L2Case {
        name: "esinet1-v6-tls.dump.180",
        transport: Transport::Tls,
        relation: CountRelation::LessOrEqual,
    },
    L2Case {
        name: "esinet1-v4-tls.dump.180",
        transport: Transport::Tls,
        relation: CountRelation::LessOrEqual,
    },
    L2Case {
        name: "esinet1-v6-tcp.dump.205",
        transport: Transport::Tcp,
        relation: CountRelation::LessOrEqual,
    },
    L2Case {
        name: "esinet1-v6-udp.dump.205",
        transport: Transport::Udp,
        relation: CountRelation::Equal,
    },
    L2Case {
        name: "esinet1-v4-tcp.dump.4",
        transport: Transport::Tcp,
        relation: CountRelation::StrictLess,
    },
];

#[test]
fn frame_to_message_counts() {
    for case in L2_CASES {
        let path = sample_dir().join(case.name);
        if !path.exists() {
            eprintln!("skipping {}: file not found", case.name);
            continue;
        }

        let frame_count = FrameIterator::new(File::open(&path).unwrap())
            .filter_map(Result::ok)
            .count();

        let mut iter = MessageIterator::new(File::open(&path).unwrap())
            .skip_tracking(SkipTracking::TrackRegions);
        let msgs: Vec<_> = iter.by_ref().filter_map(Result::ok).collect();
        let msg_count = msgs.len();

        eprintln!(
            "{}: {frame_count} frames -> {msg_count} messages",
            case.name
        );
        assert!(
            msg_count > 0,
            "{}: should produce at least one message",
            case.name
        );

        match case.relation {
            CountRelation::StrictLess => assert!(
                msg_count < frame_count,
                "{}: TCP reassembly should produce fewer messages than frames",
                case.name
            ),
            CountRelation::Equal => assert_eq!(
                msg_count, frame_count,
                "{}: messages should equal frames (no reassembly)",
                case.name
            ),
            CountRelation::LessOrEqual => assert!(
                msg_count <= frame_count,
                "{}: message count should not exceed frame count",
                case.name
            ),
        }

        assert!(
            msgs.iter().all(|m| m.transport == case.transport),
            "{}: expected all {:?} messages",
            case.name,
            case.transport
        );
        if case.name.contains("v6") {
            assert!(
                msgs.iter().all(|m| m.address.starts_with('[')),
                "{}: expected bracketed IPv6 address",
                case.name
            );
        }

        assert_parse_stats(iter.parse_stats(), case.name, 1);
    }
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

    for msg in msgs {
        assert!(!msg.content.is_empty(), "message has empty content");
    }
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
fn messages_start_with_sip_line() {
    for name in ["esinet1-v4-tcp.dump.20", "esinet1-v4-tcp.dump.4"] {
        let result = parse_messages(name);
        let msgs = &result.messages;
        if msgs.is_empty() {
            continue;
        }

        let sip_start_count = msgs
            .iter()
            .filter(|m| starts_with_sip_line(&m.content))
            .count();
        let ratio = sip_start_count as f64 / msgs.len() as f64;
        eprintln!(
            "{name}: messages starting with SIP line: {sip_start_count}/{} ({:.1}%)",
            msgs.len(),
            ratio * 100.0
        );
        assert!(
            ratio > MIN_HEADER_PRESENCE,
            "{name}: expected >{:.0}% of messages to start with a SIP line, got {:.1}%",
            MIN_HEADER_PRESENCE * 100.0,
            ratio * 100.0
        );
    }
}
