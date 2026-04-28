//! CLI runners for `--pcap-export`. Wraps the library's pcap module with the
//! filter/iterator scaffolding used by the rest of the binary.

use std::io::{self, Read};
use std::process;

use tracing::warn;

use freeswitch_sofia_trace_parser::{
    FrameIterator, MessageIterator, ParseStats, PcapConfig, PcapLayer, PcapWriter,
};

use super::{log_parse_error, CompiledFilters};

pub fn run_layer3(reader: Box<dyn Read>, capture_skipped: bool) -> ParseStats {
    let cfg = PcapConfig {
        layer: PcapLayer::Network,
        ..PcapConfig::default()
    };
    let stdout = io::stdout().lock();
    let mut writer = match PcapWriter::new(stdout, cfg) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("pcap header error: {e}");
            process::exit(1);
        }
    };
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
    iter.stats().clone()
}

pub fn run_layer4(
    reader: Box<dyn Read>,
    filters: &CompiledFilters,
    capture_skipped: bool,
) -> ParseStats {
    let cfg = PcapConfig::default();
    let stdout = io::stdout().lock();
    let mut writer = match PcapWriter::new(stdout, cfg) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("pcap header error: {e}");
            process::exit(1);
        }
    };
    let mut iter = MessageIterator::new(reader).capture_skipped(capture_skipped);
    for result in &mut iter {
        match result {
            Ok(msg) => {
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
    iter.parse_stats().clone()
}
