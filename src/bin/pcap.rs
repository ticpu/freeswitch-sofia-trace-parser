//! CLI runners for `--pcap-export`. Wraps the library's pcap module with the
//! filter/iterator scaffolding used by the rest of the binary.

use std::io::{self, BufWriter, Read, StdoutLock};
use std::process;

use tracing::warn;

use freeswitch_sofia_trace_parser::{
    FrameIterator, MessageIterator, ParseStats, PcapConfig, PcapLayer, PcapWriter,
};

use super::{log_parse_error, CompiledFilters};

type StdoutPcap = PcapWriter<BufWriter<StdoutLock<'static>>>;

/// Stdout's default `LineWriter` would syscall on every `\n` in a SIP payload.
fn stdout_writer(cfg: PcapConfig) -> StdoutPcap {
    match PcapWriter::new(BufWriter::new(io::stdout().lock()), cfg) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("pcap header error: {e}");
            process::exit(1);
        }
    }
}

fn finish(writer: &mut StdoutPcap) {
    if let Err(e) = writer.flush() {
        eprintln!("pcap flush error: {e}");
        process::exit(1);
    }
}

pub fn run_layer3(reader: Box<dyn Read>, capture_skipped: bool) -> ParseStats {
    let mut writer = stdout_writer(PcapConfig {
        layer: PcapLayer::Network,
        ..PcapConfig::default()
    });
    let mut iter = FrameIterator::new(reader).capture_skipped(capture_skipped);
    for result in &mut iter {
        match result {
            Ok(frame) => {
                if let Err(e) = writer.write_frame(&frame) {
                    warn!("pcap write error: {e}");
                }
            }
            Err(ref e) => log_parse_error("frame error", e),
        }
    }
    finish(&mut writer);
    iter.stats().clone()
}

pub fn run_layer4(
    reader: Box<dyn Read>,
    filters: &CompiledFilters,
    capture_skipped: bool,
) -> ParseStats {
    let mut writer = stdout_writer(PcapConfig::default());
    let mut iter = MessageIterator::new(reader).capture_skipped(capture_skipped);
    for result in &mut iter {
        match result {
            Ok(msg) => {
                if filters.rejected_before_parse(&msg) {
                    continue;
                }
                let parsed = match msg.parse() {
                    Ok(p) => p,
                    Err(ref e) => {
                        log_parse_error("parse error", e);
                        continue;
                    }
                };
                if !filters.matches(&parsed) {
                    continue;
                }
                if let Err(e) = writer.write_message(&msg) {
                    warn!("pcap write error: {e}");
                }
            }
            Err(ref e) => log_parse_error("message error", e),
        }
    }
    finish(&mut writer);
    iter.parse_stats().clone()
}
