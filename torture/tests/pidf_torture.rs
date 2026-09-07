use std::path::Path;

use eido::pidf::Presence;
use freeswitch_sofia_trace_parser::ParsedMessageIterator;
use freeswitch_sofia_trace_torture::{Corpus, Stats};

#[derive(Default)]
struct PidfStats {
    invites: usize,
    invites_with_pidf: usize,
    pidf_parts: usize,
    pidf_ok: usize,
    failures: Vec<(String, String)>,
}

impl Stats for PidfStats {
    fn ok(&self) -> usize {
        self.pidf_ok
    }

    fn total(&self) -> usize {
        self.pidf_parts
    }

    fn merge(&mut self, other: Self) {
        self.invites += other.invites;
        self.invites_with_pidf += other.invites_with_pidf;
        self.pidf_parts += other.pidf_parts;
        self.pidf_ok += other.pidf_ok;
        self.failures.extend(other.failures);
    }
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
}

fn parse_file_pidf(path: &Path) -> PidfStats {
    let mut stats = PidfStats::default();
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    let file = match std::fs::File::open(path) {
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
                    stats.record_failure(&name, format!("UTF-8: {e}"));
                    continue;
                }
            };

            match Presence::from_xml(xml) {
                Ok(_) => stats.record_success(),
                Err(e) => stats.record_failure(&name, e.to_string()),
            }
        }
    }

    stats
}

#[test]
fn pidf_torture_all_samples() {
    let corpus = Corpus::discover();
    if corpus.is_empty() {
        eprintln!("no .dump files found in samples/, skipping");
        return;
    }

    eprintln!("\n=== PIDF-LO torture test results ===");
    eprintln!("files processed: {}", corpus.len());

    let total = corpus.run(parse_file_pidf);

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
