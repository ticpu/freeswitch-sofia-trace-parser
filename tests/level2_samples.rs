use std::fs::File;
use std::path::Path;

use freeswitch_sofia_trace_parser::types::Transport;
use freeswitch_sofia_trace_parser::MessageIterator;

fn sample_dir() -> &'static Path {
    Path::new("samples")
}

fn parse_messages(name: &str) -> Vec<freeswitch_sofia_trace_parser::SipMessage> {
    let path = sample_dir().join(name);
    if !path.exists() {
        eprintln!("skipping {name}: file not found");
        return vec![];
    }
    let file = File::open(&path).unwrap();
    MessageIterator::new(file).filter_map(Result::ok).collect()
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

    let msg_count = MessageIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .count();

    eprintln!("esinet1-v4-tcp.dump.20: {frame_count} frames → {msg_count} messages");
    assert!(
        msg_count < frame_count,
        "TCP reassembly should produce fewer messages than frames"
    );
    assert!(msg_count > 0, "should produce at least one message");
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

    let msg_count = MessageIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .count();

    eprintln!("esinet1-v4-udp.dump.20: {frame_count} frames → {msg_count} messages");
    assert_eq!(
        msg_count, frame_count,
        "UDP messages should equal frames (no reassembly)"
    );
}

#[test]
fn tcp_multiframe_messages_have_correct_frame_count() {
    let msgs = parse_messages("esinet1-v4-tcp.dump.20");
    if msgs.is_empty() {
        return;
    }

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
    for msg in &msgs {
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

    let msgs: Vec<_> = MessageIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .collect();

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
    assert!(
        msg_count < frame_count,
        "TLS with real traffic should have multi-frame reassembly"
    );
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

    let msgs: Vec<_> = MessageIterator::new(File::open(&path).unwrap())
        .filter_map(Result::ok)
        .collect();

    let msg_count = msgs.len();
    let multi = msgs.iter().filter(|m| m.frame_count > 1).count();

    eprintln!("esinet1-v4-tls.dump.180: {frame_count} frames → {msg_count} messages ({multi} multi-frame)");

    assert!(msgs.iter().all(|m| m.transport == Transport::Tls));
}

#[test]
fn message_content_starts_with_sip() {
    let msgs = parse_messages("esinet1-v4-tcp.dump.20");
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
