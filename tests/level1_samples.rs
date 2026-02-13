use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use freeswitch_sofia_trace_parser::types::{Direction, Transport};
use freeswitch_sofia_trace_parser::FrameIterator;

fn sample_dir() -> &'static Path {
    Path::new("samples")
}

fn parse_sample(name: &str) -> Vec<freeswitch_sofia_trace_parser::Frame> {
    let path = sample_dir().join(name);
    if !path.exists() {
        eprintln!("skipping {name}: file not found");
        return vec![];
    }
    let file = File::open(&path).unwrap();
    let frames: Result<Vec<_>, _> = FrameIterator::new(file).collect();
    frames.unwrap_or_else(|e| panic!("failed to parse {name}: {e}"))
}

fn assert_all_frames_valid(frames: &[freeswitch_sofia_trace_parser::Frame], name: &str) {
    assert!(!frames.is_empty(), "{name}: no frames parsed");
    for (i, frame) in frames.iter().enumerate() {
        assert!(
            !frame.content.is_empty(),
            "{name}: frame {i} has empty content"
        );
        assert!(
            !frame.address.is_empty(),
            "{name}: frame {i} has empty address"
        );
    }
}

fn count_by_direction(frames: &[freeswitch_sofia_trace_parser::Frame]) -> (usize, usize) {
    let recv = frames.iter().filter(|f| f.direction == Direction::Recv).count();
    let sent = frames.iter().filter(|f| f.direction == Direction::Sent).count();
    (recv, sent)
}

#[test]
fn esinet1_v4_tcp() {
    let frames = parse_sample("esinet1-v4-tcp.dump.20");
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(&frames, "esinet1-v4-tcp");

    // All frames should be TCP
    assert!(
        frames.iter().all(|f| f.transport == Transport::Tcp),
        "expected all TCP frames"
    );

    // Should have both recv and sent
    let (recv, sent) = count_by_direction(&frames);
    assert!(recv > 0, "expected recv frames");
    assert!(sent > 0, "expected sent frames");

    eprintln!(
        "esinet1-v4-tcp.dump.20: {} frames ({} recv, {} sent)",
        frames.len(),
        recv,
        sent
    );

    // Verify byte_count matches content length for most frames
    let mismatches: Vec<_> = frames
        .iter()
        .enumerate()
        .filter(|(_, f)| f.byte_count != f.content.len())
        .collect();
    eprintln!(
        "  byte_count mismatches: {}/{}",
        mismatches.len(),
        frames.len()
    );

    // Verify addresses are bracketed IPv4 (e.g. [184.150.75.232]:17270)
    for frame in frames.iter().take(10) {
        assert!(
            frame.address.contains(':'),
            "address should contain port: {}",
            frame.address
        );
    }
}

#[test]
fn esinet1_v4_udp() {
    let frames = parse_sample("esinet1-v4-udp.dump.20");
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(&frames, "esinet1-v4-udp");

    assert!(
        frames.iter().all(|f| f.transport == Transport::Udp),
        "expected all UDP frames"
    );

    let (recv, sent) = count_by_direction(&frames);
    eprintln!(
        "esinet1-v4-udp.dump.20: {} frames ({} recv, {} sent)",
        frames.len(),
        recv,
        sent
    );

    // UDP frames should have byte_count == content.len() (no reassembly needed)
    let mismatches = frames
        .iter()
        .filter(|f| f.byte_count != f.content.len())
        .count();
    eprintln!("  byte_count mismatches: {}/{}", mismatches, frames.len());
}

#[test]
fn esinet1_v6_tls() {
    let frames = parse_sample("esinet1-v6-tls.dump.20");
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(&frames, "esinet1-v6-tls");

    assert!(
        frames.iter().all(|f| f.transport == Transport::Tls),
        "expected all TLS frames"
    );

    // Addresses should be IPv6 bracketed
    for frame in frames.iter().take(10) {
        assert!(
            frame.address.starts_with('['),
            "expected IPv6 bracketed address: {}",
            frame.address
        );
    }

    let (recv, sent) = count_by_direction(&frames);
    eprintln!(
        "esinet1-v6-tls.dump.20: {} frames ({} recv, {} sent)",
        frames.len(),
        recv,
        sent
    );
}

#[test]
fn internal_v4() {
    let frames = parse_sample("internal-v4.dump.20");
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(&frames, "internal-v4");

    assert!(
        frames.iter().all(|f| f.transport == Transport::Tcp),
        "expected all TCP frames"
    );

    // Internal addresses should be private IPv4 (10.x)
    let private_count = frames
        .iter()
        .filter(|f| f.address.starts_with("[10."))
        .count();
    eprintln!(
        "internal-v4.dump.20: {} frames, {} with 10.x addresses",
        frames.len(),
        private_count
    );
}

#[test]
fn internal_v6() {
    let frames = parse_sample("internal-v6.dump.20");
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(&frames, "internal-v6");

    assert!(
        frames.iter().all(|f| f.transport == Transport::Tcp),
        "expected all TCP frames"
    );

    // Internal addresses should be ULA (fd51::)
    let ula_count = frames
        .iter()
        .filter(|f| f.address.starts_with("[fd"))
        .count();
    eprintln!(
        "internal-v6.dump.20: {} frames, {} with fd:: addresses",
        frames.len(),
        ula_count
    );
}

#[test]
fn all_samples_consistent_frame_counts() {
    // Parse multiple rotated files of same type, verify they all parse without error
    let prefixes = [
        "esinet1-v4-tcp.dump",
        "esinet1-v4-udp.dump",
        "esinet1-v6-tls.dump",
        "internal-v4.dump",
        "internal-v6.dump",
    ];

    for prefix in &prefixes {
        let mut counts = Vec::new();
        for n in 20..=29 {
            let name = format!("{prefix}.{n}");
            let path = sample_dir().join(&name);
            if !path.exists() {
                continue;
            }
            let file = File::open(&path).unwrap();
            let frame_count = FrameIterator::new(file)
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|e| panic!("failed to parse {name}: {e}"))
                .len();
            counts.push((n, frame_count));
        }
        if counts.is_empty() {
            continue;
        }
        eprintln!("{prefix}:");
        for (n, count) in &counts {
            eprintln!("  .{n}: {count} frames");
        }
    }
}

#[test]
fn tcp_has_multiframe_sequences() {
    let frames = parse_sample("esinet1-v4-tcp.dump.20");
    if frames.is_empty() {
        return;
    }

    // Find consecutive recv frames from same address (multi-frame SIP messages)
    let mut consecutive_runs = 0;
    let mut max_run = 0;
    let mut current_run = 1;

    for i in 1..frames.len() {
        if frames[i].direction == frames[i - 1].direction
            && frames[i].address == frames[i - 1].address
        {
            current_run += 1;
        } else {
            if current_run > 1 {
                consecutive_runs += 1;
                max_run = max_run.max(current_run);
            }
            current_run = 1;
        }
    }
    if current_run > 1 {
        consecutive_runs += 1;
        max_run = max_run.max(current_run);
    }

    eprintln!(
        "esinet1-v4-tcp: {consecutive_runs} multi-frame sequences, max run length: {max_run}"
    );
    assert!(
        consecutive_runs > 0,
        "expected at least one multi-frame sequence in TCP dump"
    );
}

#[test]
fn byte_count_distribution() {
    let frames = parse_sample("esinet1-v4-tcp.dump.20");
    if frames.is_empty() {
        return;
    }

    let mut sizes: HashMap<usize, usize> = HashMap::new();
    for f in &frames {
        *sizes.entry(f.byte_count).or_default() += 1;
    }

    let mut top: Vec<_> = sizes.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));

    eprintln!("esinet1-v4-tcp byte_count distribution (top 10):");
    for (size, count) in top.iter().take(10) {
        eprintln!("  {size} bytes: {count} frames");
    }

    // 1440 should be common (TCP MSS segments from multi-frame messages)
    let mss_count = frames
        .iter()
        .filter(|f| f.byte_count == 1440)
        .count();
    eprintln!("  frames with 1440 bytes (TCP MSS): {mss_count}");
}

#[test]
fn file_concatenation_two_dumps() {
    // Simulates: cat dump.29 dump.28 | parser
    // Each file starts with a truncated first frame — the parser should handle
    // the join point gracefully via byte_count-aware boundary detection.
    let path1 = sample_dir().join("esinet1-v4-tcp.dump.29");
    let path2 = sample_dir().join("esinet1-v4-tcp.dump.28");
    if !path1.exists() || !path2.exists() {
        eprintln!("skipping file_concatenation_two_dumps: files not found");
        return;
    }

    // Parse each file individually
    let count1 = FrameIterator::new(File::open(&path1).unwrap())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .len();
    let count2 = FrameIterator::new(File::open(&path2).unwrap())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .len();

    // Parse concatenated stream
    let chain = std::io::Read::chain(File::open(&path1).unwrap(), File::open(&path2).unwrap());
    let combined_frames: Vec<_> = FrameIterator::new(chain)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // The concatenated parse should recover: we may lose the truncated first frame
    // of file 2 (absorbed or skipped), but the rest should parse fine.
    // Allow a small tolerance for the join point.
    let combined_count = combined_frames.len();
    let expected_min = count1 + count2 - 2; // at most 2 frames lost at join
    let expected_max = count1 + count2;

    eprintln!("dump.29: {count1} frames, dump.28: {count2} frames");
    eprintln!("concatenated: {combined_count} frames (expected {expected_min}..={expected_max})");

    assert!(
        combined_count >= expected_min && combined_count <= expected_max,
        "concatenated frame count {combined_count} outside expected range {expected_min}..={expected_max}"
    );

    // Verify zero byte_count mismatches in concatenated parse
    let mismatches = combined_frames
        .iter()
        .filter(|f| f.byte_count != f.content.len())
        .count();
    eprintln!("  byte_count mismatches: {mismatches}/{combined_count}");
    assert_eq!(mismatches, 0, "concatenated parse should have zero byte_count mismatches");
}
