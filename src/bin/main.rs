use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::process;

use clap::Parser;
use regex::Regex;
use tracing::error;

use freeswitch_sofia_trace_parser::types::{Direction, SipMessageType};
use freeswitch_sofia_trace_parser::{
    FrameIterator, MessageIterator, ParsedMessageIterator, ParsedSipMessage,
};

#[derive(Parser)]
#[command(
    name = "freeswitch-sofia-trace-parser",
    about = "Parse and filter FreeSWITCH mod_sofia SIP trace dump files"
)]
struct Cli {
    /// Dump files to parse (- for stdin, default: stdin)
    files: Vec<String>,

    /// Include SIP method (request + responses via CSeq), repeatable
    #[arg(short, long = "method", value_name = "VERB")]
    method: Vec<String>,

    /// Exclude SIP method (request + responses via CSeq), repeatable
    #[arg(short = 'x', long = "exclude", value_name = "VERB")]
    exclude: Vec<String>,

    /// Match Call-ID by regex
    #[arg(short = 'c', long = "call-id", value_name = "REGEX")]
    call_id: Option<String>,

    /// Filter by direction (recv/sent)
    #[arg(short, long, value_name = "DIR")]
    direction: Option<String>,

    /// Match address by regex
    #[arg(short, long, value_name = "REGEX")]
    address: Option<String>,

    /// Match header value by regex (NAME=REGEX), repeatable
    #[arg(short = 'H', long = "header", value_name = "NAME=REGEX")]
    header: Vec<String>,

    /// Show full SIP message content
    #[arg(long, group = "output_mode")]
    full: bool,

    /// Show headers only, no body
    #[arg(long, group = "output_mode")]
    headers: bool,

    /// Show body only
    #[arg(long, group = "output_mode")]
    body: bool,

    /// Show raw reassembled bytes (level 2)
    #[arg(long, group = "output_mode")]
    raw: bool,

    /// Show raw frames (level 1)
    #[arg(long, group = "output_mode")]
    frames: bool,

    /// Show statistics summary
    #[arg(long, group = "output_mode")]
    stats: bool,

    /// Increase verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

struct CompiledFilters {
    methods: Vec<String>,
    excludes: Vec<String>,
    call_id: Option<Regex>,
    direction: Option<Direction>,
    address: Option<Regex>,
    headers: Vec<(String, Regex)>,
}

impl CompiledFilters {
    fn matches(&self, msg: &ParsedSipMessage) -> bool {
        if !self.methods.is_empty() {
            let method = msg.method().unwrap_or("");
            if !self.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
                return false;
            }
        }

        if !self.excludes.is_empty() {
            let method = msg.method().unwrap_or("");
            if self.excludes.iter().any(|m| m.eq_ignore_ascii_case(method)) {
                return false;
            }
        }

        if let Some(ref re) = self.call_id {
            match msg.call_id() {
                Some(cid) if re.is_match(cid) => {}
                _ => return false,
            }
        }

        if let Some(dir) = self.direction {
            if msg.direction != dir {
                return false;
            }
        }

        if let Some(ref re) = self.address {
            if !re.is_match(&msg.address) {
                return false;
            }
        }

        for (name, re) in &self.headers {
            let matched = msg
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                .any(|(_, v)| re.is_match(v));
            if !matched {
                return false;
            }
        }

        true
    }
}

fn compile_regex(pattern: &str, label: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(re) => re,
        Err(e) => {
            eprintln!("invalid {label} regex '{pattern}': {e}");
            process::exit(2);
        }
    }
}

fn compile_filters(cli: &Cli) -> CompiledFilters {
    let methods: Vec<String> = cli.method.iter().map(|m| m.to_uppercase()).collect();
    let excludes: Vec<String> = cli.exclude.iter().map(|m| m.to_uppercase()).collect();

    let call_id = cli.call_id.as_ref().map(|p| compile_regex(p, "call-id"));

    let direction = cli.direction.as_ref().map(|d| match d.as_str() {
        "recv" => Direction::Recv,
        "sent" => Direction::Sent,
        other => {
            eprintln!("invalid direction '{other}': expected recv or sent");
            process::exit(2);
        }
    });

    let address = cli.address.as_ref().map(|p| compile_regex(p, "address"));

    let mut headers = Vec::new();
    for spec in &cli.header {
        let eq = match spec.find('=') {
            Some(pos) => pos,
            None => {
                eprintln!("invalid header filter '{spec}': expected NAME=REGEX");
                process::exit(2);
            }
        };
        let name = spec[..eq].to_string();
        let re = compile_regex(&spec[eq + 1..], &format!("header {name}"));
        headers.push((name, re));
    }

    CompiledFilters {
        methods,
        excludes,
        call_id,
        direction,
        address,
        headers,
    }
}

fn open_input(files: &[String]) -> Box<dyn Read> {
    if files.is_empty() || (files.len() == 1 && files[0] == "-") {
        return Box::new(io::stdin().lock());
    }

    let mut readers: Vec<Box<dyn Read>> = Vec::new();
    for path in files {
        if path == "-" {
            readers.push(Box::new(io::stdin().lock()));
        } else {
            match File::open(path) {
                Ok(f) => readers.push(Box::new(f)),
                Err(e) => {
                    eprintln!("{path}: {e}");
                    process::exit(1);
                }
            }
        }
    }

    if readers.len() == 1 {
        return readers.remove(0);
    }

    let mut chain: Box<dyn Read> = readers.remove(0);
    for r in readers {
        chain = Box::new(chain.chain(r));
    }
    chain
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| level.into()),
        )
        .with_writer(io::stderr)
        .init();
}

fn format_summary(msg: &ParsedSipMessage) -> String {
    let method_or_status = match &msg.message_type {
        SipMessageType::Request { method, .. } => method.clone(),
        SipMessageType::Response { code, reason, .. } => format!("{code} {reason}"),
    };
    let call_id = msg.call_id().unwrap_or("-");
    format!(
        "{} {} {}/{} {} {}",
        msg.timestamp, msg.direction, msg.transport, msg.address, method_or_status, call_id
    )
}

fn format_frame_header(msg: &ParsedSipMessage) -> String {
    let prep = match msg.direction {
        Direction::Recv => "from",
        Direction::Sent => "to",
    };
    let method_or_status = match &msg.message_type {
        SipMessageType::Request { method, .. } => method.clone(),
        SipMessageType::Response { code, reason, .. } => format!("{code} {reason}"),
    };
    format!(
        "{} {} {}/{} at {} ({} frames) {}",
        msg.direction,
        prep,
        msg.transport,
        msg.address,
        msg.timestamp,
        msg.frame_count,
        method_or_status,
    )
}

fn output_full(msg: &ParsedSipMessage) {
    println!("{}", format_frame_header(msg));
    let rebuilt = rebuild_message(msg);
    let content_str = String::from_utf8_lossy(&rebuilt);
    print!("{content_str}");
    if !content_str.ends_with('\n') {
        println!();
    }
}

fn rebuild_message(msg: &ParsedSipMessage) -> Vec<u8> {
    let mut out = Vec::new();
    match &msg.message_type {
        SipMessageType::Request { method, uri } => {
            out.extend_from_slice(format!("{method} {uri} SIP/2.0\r\n").as_bytes());
        }
        SipMessageType::Response { code, reason } => {
            out.extend_from_slice(format!("SIP/2.0 {code} {reason}\r\n").as_bytes());
        }
    }
    for (name, value) in &msg.headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if !msg.body.is_empty() {
        out.extend_from_slice(&msg.body);
    }
    out
}

fn output_headers(msg: &ParsedSipMessage) {
    println!("{}", format_frame_header(msg));
    match &msg.message_type {
        SipMessageType::Request { method, uri } => {
            println!("{method} {uri} SIP/2.0");
        }
        SipMessageType::Response { code, reason } => {
            println!("SIP/2.0 {code} {reason}");
        }
    }
    for (name, value) in &msg.headers {
        println!("{name}: {value}");
    }
}

fn output_body(msg: &ParsedSipMessage) {
    if !msg.body.is_empty() {
        let body_str = String::from_utf8_lossy(&msg.body);
        print!("{body_str}");
        if !body_str.ends_with('\n') {
            println!();
        }
    }
}

fn run_frames(reader: Box<dyn Read>) {
    for result in FrameIterator::new(reader) {
        match result {
            Ok(frame) => {
                let prep = match frame.direction {
                    Direction::Recv => "from",
                    Direction::Sent => "to",
                };
                println!(
                    "{} {} bytes {} {}/{} at {}",
                    frame.direction,
                    frame.byte_count,
                    prep,
                    frame.transport,
                    frame.address,
                    frame.timestamp,
                );
                let content_str = String::from_utf8_lossy(&frame.content);
                print!("{content_str}");
                if !content_str.ends_with('\n') {
                    println!();
                }
            }
            Err(e) => error!("frame error: {e}"),
        }
    }
}

fn run_raw(reader: Box<dyn Read>) {
    for result in MessageIterator::new(reader) {
        match result {
            Ok(msg) => {
                let prep = match msg.direction {
                    Direction::Recv => "from",
                    Direction::Sent => "to",
                };
                println!(
                    "{} {} {}/{} at {} ({} frames, {} bytes)",
                    msg.direction,
                    prep,
                    msg.transport,
                    msg.address,
                    msg.timestamp,
                    msg.frame_count,
                    msg.content.len(),
                );
                let content_str = String::from_utf8_lossy(&msg.content);
                print!("{content_str}");
                if !content_str.ends_with('\n') {
                    println!();
                }
            }
            Err(e) => error!("message error: {e}"),
        }
    }
}

fn run_stats(reader: Box<dyn Read>, filters: &CompiledFilters) {
    let mut method_counts: HashMap<String, usize> = HashMap::new();
    let mut status_counts: HashMap<u16, usize> = HashMap::new();
    let mut direction_counts: HashMap<Direction, usize> = HashMap::new();
    let mut total: usize = 0;
    let mut matched: usize = 0;
    let mut errors: usize = 0;

    for result in ParsedMessageIterator::new(reader) {
        total += 1;
        match result {
            Ok(msg) => {
                if !filters.matches(&msg) {
                    continue;
                }
                matched += 1;
                *direction_counts.entry(msg.direction).or_default() += 1;
                match &msg.message_type {
                    SipMessageType::Request { method, .. } => {
                        *method_counts.entry(method.clone()).or_default() += 1;
                    }
                    SipMessageType::Response { code, .. } => {
                        *status_counts.entry(*code).or_default() += 1;
                        if let Some(method) = msg.method() {
                            *method_counts.entry(method.to_string()).or_default() += 1;
                        }
                    }
                }
            }
            Err(_) => errors += 1,
        }
    }

    println!("total: {total}");
    println!("matched: {matched}");
    if errors > 0 {
        println!("parse errors: {errors}");
    }

    if let Some(&n) = direction_counts.get(&Direction::Recv) {
        println!("recv: {n}");
    }
    if let Some(&n) = direction_counts.get(&Direction::Sent) {
        println!("sent: {n}");
    }

    let mut methods: Vec<_> = method_counts.into_iter().collect();
    methods.sort_by(|a, b| b.1.cmp(&a.1));
    if !methods.is_empty() {
        println!("\nmethods:");
        for (method, count) in &methods {
            println!("  {method}: {count}");
        }
    }

    let mut statuses: Vec<_> = status_counts.into_iter().collect();
    statuses.sort_by_key(|&(code, _)| code);
    if !statuses.is_empty() {
        println!("\nresponse codes:");
        for (code, count) in &statuses {
            println!("  {code}: {count}");
        }
    }
}

fn run_filtered(reader: Box<dyn Read>, cli: &Cli, filters: &CompiledFilters) {
    for result in ParsedMessageIterator::new(reader) {
        match result {
            Ok(msg) => {
                if !filters.matches(&msg) {
                    continue;
                }
                if cli.full {
                    output_full(&msg);
                } else if cli.headers {
                    output_headers(&msg);
                } else if cli.body {
                    output_body(&msg);
                } else {
                    println!("{}", format_summary(&msg));
                }
            }
            Err(e) => error!("parse error: {e}"),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let reader = open_input(&cli.files);

    if cli.frames {
        run_frames(reader);
        return;
    }

    if cli.raw {
        run_raw(reader);
        return;
    }

    let filters = compile_filters(&cli);

    if cli.stats {
        run_stats(reader, &filters);
        return;
    }

    run_filtered(reader, &cli, &filters);
}
