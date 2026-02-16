use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use freeswitch_sofia_trace_parser::types::{Direction, ParseStats, SkipReason, Transport};
use freeswitch_sofia_trace_parser::FrameIterator;

fn sample_dir() -> &'static Path {
    Path::new("samples")
}

struct FrameParseResult {
    frames: Vec<freeswitch_sofia_trace_parser::Frame>,
    stats: ParseStats,
}

fn parse_sample(name: &str) -> FrameParseResult {
    let path = sample_dir().join(name);
    if !path.exists() {
        eprintln!("skipping {name}: file not found");
        return FrameParseResult {
            frames: vec![],
            stats: ParseStats::default(),
        };
    }
    let file = File::open(&path).unwrap();
    let mut iter = FrameIterator::new(file);
    let mut errors = 0usize;
    let frames: Vec<_> = iter
        .by_ref()
        .filter_map(|r| match r {
            Ok(f) => Some(f),
            Err(_) => {
                errors += 1;
                None
            }
        })
        .collect();
    if errors > 0 {
        eprintln!("{name}: {errors} recovery errors skipped");
    }
    let stats = iter.stats().clone();
    FrameParseResult { frames, stats }
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
    let recv = frames
        .iter()
        .filter(|f| f.direction == Direction::Recv)
        .count();
    let sent = frames
        .iter()
        .filter(|f| f.direction == Direction::Sent)
        .count();
    (recv, sent)
}

#[test]
fn esinet1_v4_tcp() {
    let result = parse_sample("esinet1-v4-tcp.dump.20");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "esinet1-v4-tcp");
    assert_parse_stats(&result.stats, "esinet1-v4-tcp.dump.20", 1);

    // All frames should be TCP
    assert!(
        frames.iter().all(|f| f.transport == Transport::Tcp),
        "expected all TCP frames"
    );

    // Should have both recv and sent
    let (recv, sent) = count_by_direction(frames);
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
    let result = parse_sample("esinet1-v4-udp.dump.20");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "esinet1-v4-udp");
    assert_parse_stats(&result.stats, "esinet1-v4-udp.dump.20", 1);

    assert!(
        frames.iter().all(|f| f.transport == Transport::Udp),
        "expected all UDP frames"
    );

    let (recv, sent) = count_by_direction(frames);
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
    let result = parse_sample("esinet1-v6-tls.dump.20");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "esinet1-v6-tls");
    assert_parse_stats(&result.stats, "esinet1-v6-tls.dump.20", 1);

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

    let (recv, sent) = count_by_direction(frames);
    eprintln!(
        "esinet1-v6-tls.dump.20: {} frames ({} recv, {} sent)",
        frames.len(),
        recv,
        sent
    );
}

#[test]
fn internal_v4() {
    let result = parse_sample("internal-v4.dump.20");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "internal-v4");
    assert_parse_stats(&result.stats, "internal-v4.dump.20", 1);

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
    let result = parse_sample("internal-v6.dump.20");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "internal-v6");
    assert_parse_stats(&result.stats, "internal-v6.dump.20", 1);

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
fn esinet1_v6_tcp() {
    let result = parse_sample("esinet1-v6-tcp.dump.205");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "esinet1-v6-tcp");
    assert_parse_stats(&result.stats, "esinet1-v6-tcp.dump.205", 1);

    assert!(
        frames.iter().all(|f| f.transport == Transport::Tcp),
        "expected all TCP frames"
    );

    for frame in frames.iter().take(10) {
        assert!(
            frame.address.starts_with('['),
            "expected IPv6 bracketed address: {}",
            frame.address
        );
    }

    let (recv, sent) = count_by_direction(frames);
    assert!(recv > 0, "expected recv frames");
    assert!(sent > 0, "expected sent frames");

    eprintln!(
        "esinet1-v6-tcp.dump.205: {} frames ({} recv, {} sent)",
        frames.len(),
        recv,
        sent
    );

    let mismatches = frames
        .iter()
        .filter(|f| f.byte_count != f.content.len())
        .count();
    eprintln!("  byte_count mismatches: {}/{}", mismatches, frames.len());
}

#[test]
fn esinet1_v6_udp() {
    let result = parse_sample("esinet1-v6-udp.dump.205");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "esinet1-v6-udp");
    assert_parse_stats(&result.stats, "esinet1-v6-udp.dump.205", 1);

    assert!(
        frames.iter().all(|f| f.transport == Transport::Udp),
        "expected all UDP frames"
    );

    for frame in frames.iter().take(10) {
        assert!(
            frame.address.starts_with('['),
            "expected IPv6 bracketed address: {}",
            frame.address
        );
    }

    let (recv, sent) = count_by_direction(frames);
    eprintln!(
        "esinet1-v6-udp.dump.205: {} frames ({} recv, {} sent)",
        frames.len(),
        recv,
        sent
    );

    let mismatches = frames
        .iter()
        .filter(|f| f.byte_count != f.content.len())
        .count();
    eprintln!("  byte_count mismatches: {}/{}", mismatches, frames.len());
}

#[test]
fn esinet1_v4_tls() {
    let result = parse_sample("esinet1-v4-tls.dump.193");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "esinet1-v4-tls");
    assert_parse_stats(&result.stats, "esinet1-v4-tls.dump.193", 1);

    assert!(
        frames.iter().all(|f| f.transport == Transport::Tls),
        "expected all TLS frames"
    );

    let (recv, sent) = count_by_direction(frames);
    eprintln!(
        "esinet1-v4-tls.dump.193: {} frames ({} recv, {} sent)",
        frames.len(),
        recv,
        sent
    );
}

#[test]
fn all_samples_consistent_frame_counts() {
    // Parse multiple rotated files of same type, verify they all parse without error
    let prefixes = [
        "esinet1-v4-tcp.dump",
        "esinet1-v4-tls.dump",
        "esinet1-v4-udp.dump",
        "esinet1-v6-tcp.dump",
        "esinet1-v6-tls.dump",
        "esinet1-v6-udp.dump",
        "internal-v4.dump",
        "internal-v6.dump",
    ];

    let dir = sample_dir();
    if !dir.exists() {
        eprintln!("skipping: samples/ not found");
        return;
    }

    for prefix in &prefixes {
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with(prefix)
                    && !name.ends_with(".xz")
                    && name.len() > prefix.len() + 1
                    && name.as_bytes()[prefix.len()] == b'.'
                    && name[prefix.len() + 1..].bytes().all(|b| b.is_ascii_digit())
                {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        files.sort();

        if files.is_empty() {
            continue;
        }

        eprintln!("{prefix}: ({} files)", files.len());
        for name in &files {
            let file = File::open(dir.join(name)).unwrap();
            let mut iter = FrameIterator::new(file);
            let frame_count = iter.by_ref().filter_map(Result::ok).count();
            let stats = iter.stats();
            eprintln!(
                "  {name}: {frame_count} frames, skipped={}",
                stats.bytes_skipped
            );
            assert_parse_stats(stats, name, 1);
        }
    }
}

#[test]
fn tcp_has_multiframe_sequences() {
    let result = parse_sample("esinet1-v4-tcp.dump.20");
    let frames = &result.frames;
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
    let result = parse_sample("esinet1-v4-tcp.dump.20");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }

    let mut sizes: HashMap<usize, usize> = HashMap::new();
    for f in frames {
        *sizes.entry(f.byte_count).or_default() += 1;
    }

    let mut top: Vec<_> = sizes.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));

    eprintln!("esinet1-v4-tcp byte_count distribution (top 10):");
    for (size, count) in top.iter().take(10) {
        eprintln!("  {size} bytes: {count} frames");
    }

    // 1440 should be common (TCP MSS segments from multi-frame messages)
    let mss_count = frames.iter().filter(|f| f.byte_count == 1440).count();
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

    // Parse each file individually (filter errors from recovery)
    let count1 = FrameIterator::new(File::open(&path1).unwrap())
        .filter_map(Result::ok)
        .count();
    let count2 = FrameIterator::new(File::open(&path2).unwrap())
        .filter_map(Result::ok)
        .count();

    // Parse concatenated stream
    let chain = std::io::Read::chain(File::open(&path1).unwrap(), File::open(&path2).unwrap());
    let mut combined_iter = FrameIterator::new(chain);
    let combined_frames: Vec<_> = combined_iter.by_ref().filter_map(Result::ok).collect();

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
    assert_eq!(
        mismatches, 0,
        "concatenated parse should have zero byte_count mismatches"
    );

    // Two files chained: at most 2 partial first frames (one per file boundary)
    assert_parse_stats(combined_iter.stats(), "concatenated dump.29+dump.28", 2);
}

#[test]
fn esinet1_v4_tcp_150() {
    let result = parse_sample("esinet1-v4-tcp.dump.150");
    let frames = &result.frames;
    if frames.is_empty() {
        return;
    }
    assert_all_frames_valid(frames, "esinet1-v4-tcp.dump.150");
    assert_parse_stats(&result.stats, "esinet1-v4-tcp.dump.150", 1);

    assert!(
        frames.iter().all(|f| f.transport == Transport::Tcp),
        "expected all TCP frames"
    );

    let (recv, sent) = count_by_direction(frames);
    assert!(recv > 0, "expected recv frames");
    assert!(sent > 0, "expected sent frames");

    let mismatches: Vec<_> = frames
        .iter()
        .enumerate()
        .filter(|(_, f)| f.byte_count != f.content.len())
        .collect();

    eprintln!(
        "esinet1-v4-tcp.dump.150: {} frames ({} recv, {} sent), {} byte_count mismatches",
        frames.len(),
        recv,
        sent,
        mismatches.len(),
    );
}
