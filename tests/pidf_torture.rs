#![cfg(feature = "pidf-test")]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use eido::pidf::Presence;
use freeswitch_sofia_trace_parser::ParsedMessageIterator;
use rayon::prelude::*;

#[derive(Default)]
struct PidfStats {
    invites: usize,
    invites_with_pidf: usize,
    pidf_parts: usize,
    pidf_ok: usize,
    failures: Vec<(String, String)>,
}

impl PidfStats {
    fn record_success(&mut self) {
        self.pidf_parts += 1;
        self.pidf_ok += 1;
    }

    fn record_failure(&mut self, file: &str, err: String) {
        self.pidf_parts += 1;
        if self.failures.len() < 50 {
            self.failures.push((file.to_string(), err));
        }
    }

    fn merge(&mut self, other: PidfStats) {
        self.invites += other.invites;
        self.invites_with_pidf += other.invites_with_pidf;
        self.pidf_parts += other.pidf_parts;
        self.pidf_ok += other.pidf_ok;
        self.failures.extend(other.failures);
    }
}

fn sample_dir() -> &'static Path {
    Path::new("samples")
}

fn parse_file_pidf(name: &str) -> PidfStats {
    let mut stats = PidfStats::default();
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

        if msg.method() != Some("INVITE") {
            continue;
        }

        stats.invites += 1;

        let parts = match msg.body_parts() {
            Some(p) => p,
            None => continue,
        };

        let pidf_parts: Vec<_> = parts
            .iter()
            .filter(|p| p.content_type().is_some_and(|ct| ct.contains("pidf")))
            .collect();

        if pidf_parts.is_empty() {
            continue;
        }

        stats.invites_with_pidf += 1;

        for part in pidf_parts {
            let xml = match std::str::from_utf8(&part.body) {
                Ok(s) => s,
                Err(e) => {
                    stats.record_failure(name, format!("UTF-8: {e}"));
                    continue;
                }
            };

            match Presence::from_xml(xml) {
                Ok(_) => stats.record_success(),
                Err(e) => stats.record_failure(name, e.to_string()),
            }
        }
    }

    stats
}

#[test]
#[ignore]
fn pidf_torture_all_samples() {
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

    let per_file: Mutex<HashMap<String, (usize, usize, usize)>> = Mutex::new(HashMap::new());

    let file_stats: Vec<PidfStats> = entries
        .par_iter()
        .map(|name| {
            let stats = parse_file_pidf(name);
            if stats.pidf_parts > 0 {
                per_file.lock().unwrap().insert(
                    name.clone(),
                    (stats.invites, stats.invites_with_pidf, stats.pidf_ok),
                );
            }
            stats
        })
        .collect();

    let mut total = PidfStats::default();
    for stats in file_stats {
        total.merge(stats);
    }

    eprintln!("\n=== PIDF-LO torture test results ===");
    eprintln!("files processed: {}", entries.len());
    eprintln!("INVITEs: {}", total.invites);
    eprintln!("INVITEs with PIDF: {}", total.invites_with_pidf);
    eprintln!(
        "PIDF parts: {}/{} parsed ({:.3}%)",
        total.pidf_ok,
        total.pidf_parts,
        if total.pidf_parts > 0 {
            total.pidf_ok as f64 / total.pidf_parts as f64 * 100.0
        } else {
            0.0
        }
    );

    if !total.failures.is_empty() {
        eprintln!("\nfailure samples (first {}):", total.failures.len());
        for (file, err) in &total.failures {
            eprintln!("  [{file}] {err}");
        }
    }

    eprintln!("\nper-file breakdown:");
    let per_file = per_file.into_inner().unwrap();
    let mut sorted_files: Vec<_> = per_file.iter().collect();
    sorted_files.sort_by_key(|(name, _)| (*name).clone());
    for (name, (invites, with_pidf, ok)) in &sorted_files {
        eprintln!("  {name}: {invites} INVITEs, {with_pidf} with PIDF, {ok} parsed OK");
    }

    if total.pidf_parts > 0 {
        let success_rate = total.pidf_ok as f64 / total.pidf_parts as f64;
        assert!(
            success_rate > 0.99,
            "expected >99% PIDF parse success rate, got {:.2}% ({} failures out of {})",
            success_rate * 100.0,
            total.pidf_parts - total.pidf_ok,
            total.pidf_parts
        );
    }
}
