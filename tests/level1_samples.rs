mod common;

use std::collections::HashMap;
use std::fs::File;

use freeswitch_sofia_trace_parser::types::{
    Direction, ParseStats, SkipReason, SkipTracking, Transport,
};
use freeswitch_sofia_trace_parser::{Frame, FrameIterator};

use common::{assert_parse_stats, frame_count, list_dumps, open_sample, sample_dir};

struct FrameParseResult {
    frames: Vec<Frame>,
    stats: ParseStats,
}

fn parse_sample(name: &str) -> FrameParseResult {
    let Some(file) = open_sample(name) else {
        return FrameParseResult {
            frames: vec![],
            stats: ParseStats::default(),
        };
    };
    let mut iter = FrameIterator::new(file).skip_tracking(SkipTracking::TrackRegions);
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

fn assert_all_frames_valid(frames: &[Frame], name: &str) {
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

fn count_by_direction(frames: &[Frame]) -> (usize, usize) {
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

#[derive(Clone, Copy)]
enum AddrFamily {
    V4,
    V6,
}

struct FileCase {
    name: &'static str,
    transport: Transport,
    addr_family: AddrFamily,
    assert_bidirectional: bool,
}

const FILE_CASES: &[FileCase] = &[
    FileCase {
        name: "esinet1-v4-tcp.dump.20",
        transport: Transport::Tcp,
        addr_family: AddrFamily::V4,
        assert_bidirectional: true,
    },
    FileCase {
        name: "esinet1-v4-udp.dump.20",
        transport: Transport::Udp,
        addr_family: AddrFamily::V4,
        assert_bidirectional: false,
    },
    FileCase {
        name: "esinet1-v6-tls.dump.20",
        transport: Transport::Tls,
        addr_family: AddrFamily::V6,
        assert_bidirectional: false,
    },
    FileCase {
        name: "internal-v4.dump.20",
        transport: Transport::Tcp,
        addr_family: AddrFamily::V4,
        assert_bidirectional: false,
    },
    FileCase {
        name: "internal-v6.dump.20",
        transport: Transport::Tcp,
        addr_family: AddrFamily::V6,
        assert_bidirectional: false,
    },
    FileCase {
        name: "esinet1-v6-tcp.dump.205",
        transport: Transport::Tcp,
        addr_family: AddrFamily::V6,
        assert_bidirectional: true,
    },
    FileCase {
        name: "esinet1-v6-udp.dump.205",
        transport: Transport::Udp,
        addr_family: AddrFamily::V6,
        assert_bidirectional: false,
    },
    FileCase {
        name: "esinet1-v4-tls.dump.193",
        transport: Transport::Tls,
        addr_family: AddrFamily::V4,
        assert_bidirectional: false,
    },
    FileCase {
        name: "esinet1-v4-tcp.dump.4",
        transport: Transport::Tcp,
        addr_family: AddrFamily::V4,
        assert_bidirectional: true,
    },
    FileCase {
        name: "esinet1-v4-tcp.dump.150",
        transport: Transport::Tcp,
        addr_family: AddrFamily::V4,
        assert_bidirectional: true,
    },
];

#[test]
fn per_file_frame_parsing() {
    for case in FILE_CASES {
        let result = parse_sample(case.name);
        let frames = &result.frames;
        if frames.is_empty() {
            continue;
        }
        assert_all_frames_valid(frames, case.name);
        assert_parse_stats(&result.stats, case.name, 1);

        assert!(
            frames.iter().all(|f| f.transport == case.transport),
            "{}: expected all {:?} frames",
            case.name,
            case.transport
        );

        match case.addr_family {
            AddrFamily::V4 => {
                for frame in frames.iter().take(10) {
                    let addr = frame.socket_addr();
                    assert!(
                        matches!(addr, Some(a) if a.is_ipv4()),
                        "{}: expected bracketed IPv4 address, got {}",
                        case.name,
                        frame.address
                    );
                }
            }
            AddrFamily::V6 => {
                for frame in frames.iter().take(10) {
                    assert!(
                        frame.address.starts_with('['),
                        "{}: expected IPv6 bracketed address, got {}",
                        case.name,
                        frame.address
                    );
                }
            }
        }

        let (recv, sent) = count_by_direction(frames);
        eprintln!(
            "{}: {} frames ({recv} recv, {sent} sent)",
            case.name,
            frames.len()
        );
        if case.assert_bidirectional {
            assert!(recv > 0, "{}: expected recv frames", case.name);
            assert!(sent > 0, "{}: expected sent frames", case.name);
        }
    }
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

    if !sample_dir().exists() {
        eprintln!("skipping: samples/ not found");
        return;
    }

    for prefix in &prefixes {
        let files = list_dumps(Some(prefix));
        if files.is_empty() {
            continue;
        }

        eprintln!("{prefix}: ({} files)", files.len());
        for path in &files {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let file = File::open(path).unwrap();
            let mut iter = FrameIterator::new(file).skip_tracking(SkipTracking::TrackRegions);
            let count = iter.by_ref().filter_map(Result::ok).count();
            let stats = iter.stats();
            eprintln!("  {name}: {count} frames, skipped={}", stats.bytes_skipped);
            assert_parse_stats(stats, &name, 1);
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
    top.sort_by_key(|b| std::cmp::Reverse(b.1));

    eprintln!("esinet1-v4-tcp byte_count distribution (top 10):");
    for (size, count) in top.iter().take(10) {
        eprintln!("  {size} bytes: {count} frames");
    }

    // 1440 is the common TCP MSS segment size for multi-frame messages
    let mss_count = frames.iter().filter(|f| f.byte_count == 1440).count();
    eprintln!("  frames with 1440 bytes (TCP MSS): {mss_count}");
    assert!(
        mss_count > 0,
        "expected TCP MSS-sized (1440 byte) frames in multi-frame TCP dump"
    );
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

    let count1 = frame_count(&path1);
    let count2 = frame_count(&path2);

    // Parse concatenated stream
    let chain = std::io::Read::chain(File::open(&path1).unwrap(), File::open(&path2).unwrap());
    let mut combined_iter = FrameIterator::new(chain).skip_tracking(SkipTracking::TrackRegions);
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

    // dump.28 opens with the tail of dump.29's last frame (logrotate's
    // copytruncate race) — the join point must be classified, not silently
    // swallowed as ordinary skipped bytes.
    let replayed = combined_iter
        .stats()
        .unparsed_regions
        .iter()
        .filter(|r| r.reason == SkipReason::ReplayedFrame)
        .count();
    eprintln!("  replayed-frame regions: {replayed}");
    assert!(
        replayed > 0,
        "expected a ReplayedFrame region at the logrotate join point"
    );
}
