use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use freeswitch_sofia_trace_parser::types::SipMessageType;
use freeswitch_sofia_trace_parser::ParsedMessageIterator;
use rayon::prelude::*;
use sip_uri::{NameAddr, Uri};

const NAMEADDR_HEADERS: &[&str] = &[
    "from",
    "to",
    "contact",
    "p-asserted-identity",
    "p-preferred-identity",
    "route",
    "record-route",
    "refer-to",
    "call-info",
    "reply-to",
];

#[derive(Default)]
struct UriStats {
    request_uri_total: usize,
    request_uri_ok: usize,
    nameaddr_total: usize,
    nameaddr_ok: usize,
    by_scheme: HashMap<String, usize>,
    by_header: HashMap<String, (usize, usize)>,
    failures: Vec<(String, String, String)>,
}

impl UriStats {
    fn record_uri_type(&mut self, uri: &Uri) {
        *self.by_scheme.entry(uri.scheme().to_string()).or_default() += 1;
    }

    fn record_request_uri(&mut self, uri: &str, file: &str) {
        self.request_uri_total += 1;
        match uri.parse::<Uri>() {
            Ok(parsed) => {
                self.request_uri_ok += 1;
                self.record_uri_type(&parsed);
            }
            Err(e) => {
                if self.failures.len() < 50 {
                    self.failures.push((
                        file.to_string(),
                        format!("Request-URI: {uri}"),
                        e.to_string(),
                    ));
                }
            }
        }
    }

    fn record_nameaddr(&mut self, header: &str, value: &str, file: &str) {
        self.nameaddr_total += 1;
        let entry = self
            .by_header
            .entry(header.to_lowercase())
            .or_insert((0, 0));
        entry.1 += 1;
        match value.parse::<NameAddr>() {
            Ok(parsed) => {
                self.nameaddr_ok += 1;
                entry.0 += 1;
                self.record_uri_type(parsed.uri());
            }
            Err(e) => {
                if self.failures.len() < 50 {
                    self.failures.push((
                        file.to_string(),
                        format!("{header}: {value}"),
                        e.to_string(),
                    ));
                }
            }
        }
    }

    fn total(&self) -> usize {
        self.request_uri_total + self.nameaddr_total
    }

    fn ok(&self) -> usize {
        self.request_uri_ok + self.nameaddr_ok
    }

    fn merge(&mut self, other: UriStats) {
        self.request_uri_total += other.request_uri_total;
        self.request_uri_ok += other.request_uri_ok;
        self.nameaddr_total += other.nameaddr_total;
        self.nameaddr_ok += other.nameaddr_ok;
        for (scheme, count) in other.by_scheme {
            *self.by_scheme.entry(scheme).or_default() += count;
        }
        for (header, (ok, total)) in other.by_header {
            let entry = self.by_header.entry(header).or_insert((0, 0));
            entry.0 += ok;
            entry.1 += total;
        }
        self.failures.extend(other.failures);
    }
}

fn sample_dir() -> &'static Path {
    Path::new("samples")
}

fn parse_file_uris(name: &str) -> UriStats {
    let mut stats = UriStats::default();
    let path = sample_dir().join(name);

    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return stats,
    };

    for result in ParsedMessageIterator::new(file) {
        let msg = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        if let SipMessageType::Request { ref uri, .. } = msg.message_type {
            stats.record_request_uri(uri, name);
        }

        for (header_name, header_value) in &msg.headers {
            if NAMEADDR_HEADERS
                .iter()
                .any(|h| header_name.eq_ignore_ascii_case(h))
            {
                stats.record_nameaddr(header_name, header_value, name);
            }
        }
    }

    stats
}

#[test]
#[ignore]
fn sip_uri_torture_all_samples() {
    let dir = sample_dir();
    if !dir.exists() {
        eprintln!("samples/ directory not found, skipping");
        return;
    }

    let mut entries: Vec<String> = fs::read_dir(dir)
        .expect("read samples/")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".xz") {
                return None;
            }
            if name.contains(".dump") {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    entries.sort();

    if entries.is_empty() {
        eprintln!("no .dump files found in samples/, skipping");
        return;
    }

    let per_file: Mutex<HashMap<String, (usize, usize)>> = Mutex::new(HashMap::new());

    let file_stats: Vec<UriStats> = entries
        .par_iter()
        .map(|name| {
            let stats = parse_file_uris(name);
            if stats.total() > 0 {
                per_file
                    .lock()
                    .unwrap()
                    .insert(name.clone(), (stats.ok(), stats.total()));
            }
            stats
        })
        .collect();

    let mut total = UriStats::default();
    for stats in file_stats {
        total.merge(stats);
    }

    eprintln!("\n=== sip-uri torture test results ===");
    eprintln!("files processed: {}", entries.len());
    eprintln!(
        "request URIs: {}/{} parsed",
        total.request_uri_ok, total.request_uri_total
    );
    eprintln!(
        "name-addr headers: {}/{} parsed",
        total.nameaddr_ok, total.nameaddr_total
    );
    eprintln!(
        "overall: {}/{} ({:.5}%)",
        total.ok(),
        total.total(),
        if total.total() > 0 {
            total.ok() as f64 / total.total() as f64 * 100.0
        } else {
            0.0
        }
    );

    eprintln!("\nby URI scheme:");
    let mut schemes: Vec<_> = total.by_scheme.iter().collect();
    schemes.sort_by(|a, b| b.1.cmp(a.1));
    for (scheme, count) in &schemes {
        eprintln!("  {scheme}: {count}");
    }

    eprintln!("\nby header:");
    let mut headers: Vec<_> = total.by_header.iter().collect();
    headers.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    for (header, (ok, hdr_total)) in &headers {
        let pct = if *hdr_total > 0 {
            *ok as f64 / *hdr_total as f64 * 100.0
        } else {
            0.0
        };
        eprintln!("  {header}: {ok}/{hdr_total} ({pct:.2}%)");
    }

    if !total.failures.is_empty() {
        eprintln!("\nfailure samples (first {}):", total.failures.len());
        for (file, input, err) in &total.failures {
            eprintln!("  [{file}] {input}");
            eprintln!("    error: {err}");
        }
    }

    eprintln!("\nper-file breakdown:");
    let per_file = per_file.into_inner().unwrap();
    let mut sorted_files: Vec<_> = per_file.iter().collect();
    sorted_files.sort_by_key(|(name, _)| (*name).clone());
    for (name, (ok, file_total)) in &sorted_files {
        let pct = if *file_total > 0 {
            *ok as f64 / *file_total as f64 * 100.0
        } else {
            0.0
        };
        eprintln!("  {name}: {ok}/{file_total} ({pct:.1}%)");
    }

    assert!(total.total() > 0, "expected to find URIs in trace samples");

    let success_rate = total.ok() as f64 / total.total() as f64;
    assert!(
        success_rate > 0.99,
        "expected >99% parse success rate, got {:.2}% ({} failures out of {})",
        success_rate * 100.0,
        total.total() - total.ok(),
        total.total()
    );
}
