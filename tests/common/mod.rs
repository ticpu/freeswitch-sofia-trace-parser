#![allow(dead_code)]

use std::fs::File;
use std::path::{Path, PathBuf};

use freeswitch_sofia_trace_parser::types::{
    ParseStats, ParsedSipMessage, SipMessageType, SkipReason,
};

/// Minimum fraction of Level 3 parses that must succeed on a sample file.
pub const MIN_PARSE_SUCCESS: f64 = 0.999;

/// Minimum fraction of messages that must carry a given header (Call-ID, CSeq, ...).
pub const MIN_HEADER_PRESENCE: f64 = 0.99;

/// Directory holding production sample dump files (gitignored, symlinked into
/// this worktree from the main checkout's `samples/`).
pub fn sample_dir() -> PathBuf {
    PathBuf::from("samples")
}

/// Open a sample file by name, printing one skip line and returning `None`
/// when it is absent. Tests that receive `None` should return early rather
/// than treat it as a failure: samples are gitignored production data.
pub fn open_sample(name: &str) -> Option<File> {
    let path = sample_dir().join(name);
    if !path.exists() {
        eprintln!("skipping {name}: file not found");
        return None;
    }
    File::open(&path).ok()
}

/// List dump files in `samples/`, optionally restricted to a rotation prefix
/// (e.g. `Some("esinet1-v4-tcp.dump")` matches `esinet1-v4-tcp.dump.20`, not
/// `.dump.20.xz`). Without a prefix, every non-`.xz` file containing `.dump`
/// is returned. Sorted for deterministic iteration.
pub fn list_dumps(prefix: Option<&str>) -> Vec<PathBuf> {
    let dir = sample_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".xz") {
                return None;
            }
            match prefix {
                Some(prefix) => {
                    if name.starts_with(prefix)
                        && name.len() > prefix.len() + 1
                        && name.as_bytes()[prefix.len()] == b'.'
                        && name[prefix.len() + 1..].bytes().all(|b| b.is_ascii_digit())
                    {
                        Some(dir.join(name))
                    } else {
                        None
                    }
                }
                None => {
                    if name.contains(".dump") {
                        Some(dir.join(name))
                    } else {
                        None
                    }
                }
            }
        })
        .collect();
    files.sort();
    files
}

/// Assert the byte-level parse coverage a sample file must meet: at most
/// `max_partial` `PartialFirstFrame` skips (logrotate truncation) and zero
/// `InvalidHeader` skips.
pub fn assert_parse_stats(stats: &ParseStats, name: &str, max_partial: usize) {
    let partial_count = stats
        .unparsed_regions()
        .iter()
        .filter(|r| r.reason == SkipReason::PartialFirstFrame)
        .count();
    let invalid_count = stats
        .unparsed_regions()
        .iter()
        .filter(|r| r.reason == SkipReason::InvalidHeader)
        .count();

    eprintln!(
        "{name}: bytes_read={}, bytes_skipped={}, regions={} (partial={partial_count}, invalid={invalid_count})",
        stats.bytes_read(),
        stats.bytes_skipped(),
        stats.unparsed_regions().len(),
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

/// Whether reassembled bytes begin with a SIP request or status line, judged
/// purely by shape: the first line starts with `SIP/2.0 ` (a response) or
/// ends with ` SIP/2.0` (a request), independent of which method it names.
pub fn starts_with_sip_line(content: &[u8]) -> bool {
    let line_end = content
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(content.len());
    let line = match content[..line_end].split_last() {
        Some((b'\r', rest)) => rest,
        _ => &content[..line_end],
    };
    line.starts_with(b"SIP/2.0 ") || line.ends_with(b" SIP/2.0")
}

/// Count Level 1 frames in a sample file, ignoring recovery errors.
pub fn frame_count(path: &Path) -> usize {
    let Ok(file) = File::open(path) else {
        return 0;
    };
    freeswitch_sofia_trace_parser::FrameIterator::new(file)
        .filter_map(Result::ok)
        .count()
}

/// Method/response-code histogram over parsed messages, sorted by
/// descending count. Responses are keyed by their status code.
pub fn method_histogram(msgs: &[ParsedSipMessage]) -> Vec<(String, usize)> {
    use std::collections::HashMap;

    let mut methods: HashMap<String, usize> = HashMap::new();
    for msg in msgs {
        let key = match &msg.message_type {
            SipMessageType::Request { method, .. } => method.clone(),
            SipMessageType::Response { code, .. } => code.to_string(),
        };
        *methods.entry(key).or_default() += 1;
    }

    let mut sorted: Vec<_> = methods.into_iter().collect();
    sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    sorted
}
