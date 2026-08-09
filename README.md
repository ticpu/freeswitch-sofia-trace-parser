# freeswitch-sofia-trace-parser

Rust library and CLI for parsing FreeSWITCH `mod_sofia` SIP trace dump files.

```sh
cargo run --features cli -- [OPTIONS] [FILES...]
```

```toml
[dependencies]
freeswitch-sofia-trace-parser = "0"
```

## Overview

FreeSWITCH logs SIP traffic to dump files at
`/var/log/freeswitch/sip_traces/{profile}/{profile}.dump` (rotated as `.dump.1.xz`, etc.).

This library provides a streaming, multi-level parser:

- **Level 0 — Raw dump**: FreeSWITCH frame headers (`recv/sent N bytes from/to <transport>/<addr> at <ts>:`) and payloads delimited by `\x0B\n` boundaries
- **Level 1 — Frames**: Split raw bytes on `\x0B\n` boundaries, parse frame headers
- **Level 2 — Messages**: Reassemble TCP segments, split aggregated messages by Content-Length
- **Level 3 — Parsed SIP**: Extract method/status, headers, body, and multipart MIME parts

## At a Glance

Point the CLI at a dump file and filter — full reference under [CLI Tool](#cli-tool):

```sh
$ freeswitch-sofia-trace-parser -m INVITE profile.dump
2026-06-16 14:32:01.123456 recv tls/[2001:db8::1]:5061 INVITE a1b2c3d4@example.test
2026-06-16 14:32:01.124891 sent tls/[2001:db8::1]:5061 100 Trying a1b2c3d4@example.test
2026-06-16 14:32:01.298765 sent tls/[2001:db8::1]:5061 180 Ringing a1b2c3d4@example.test
2026-06-16 14:32:04.567012 sent tls/[2001:db8::1]:5061 200 OK a1b2c3d4@example.test
```

## Library Usage

### Raw messages (Level 2)

```rust
use std::fs::File;
use freeswitch_sofia_trace_parser::{MessageIterator, SipMessage};

let file = File::open("profile.dump")?;
for result in MessageIterator::new(file) {
    let msg: SipMessage = result?;
    println!("{} {} {}:{} ({} frames, {} bytes)",
        msg.timestamp, msg.direction, msg.transport, msg.address,
        msg.frame_count, msg.content.len());
}
```

### Parsed SIP messages (Level 3)

```rust
use std::fs::File;
use freeswitch_sofia_trace_parser::ParsedMessageIterator;

let file = File::open("profile.dump")?;
for result in ParsedMessageIterator::new(file) {
    let msg = result?;
    println!("{} {} {} call-id={}",
        msg.timestamp, msg.direction, msg.message_type,
        msg.call_id().unwrap_or("-"));
}
```

`socket_addr()` gives the remote address typed, family and port preserved, on
`Frame`, `SipMessage` and `ParsedSipMessage` alike.

Headers live in a `Headers` newtype over `(name, value)` pairs in wire order —
it derefs to the slice for iteration, and `header_value(name)` on
`ParsedSipMessage`, `MimePart` and `SipFragment` is the case-insensitive
lookup. Typed accessors (`call_id()`, `content_type()`, …) resolve SIP compact
forms; `header_value()` does not.

### Multipart body splitting (SDP + EIDO/PIDF)

`body_parts()` returns `None` for a body that does not split. Use
`body_as_parts()` to handle every body the same way: it yields the multipart
children, or a single part for a body that has none. `media_type()` gives the
type with parameters stripped and lowercased, ready to match on.

```rust
use std::fs::File;
use freeswitch_sofia_trace_parser::ParsedMessageIterator;

let file = File::open("profile.dump")?;
for result in ParsedMessageIterator::new(file) {
    let msg = result?;
    for part in msg.body_as_parts() {
        match part.media_type().as_deref() {
            Some("application/sdp") => println!("  SDP ({} bytes)", part.body.len()),
            Some("application/pidf+xml") => println!("  location"),
            Some("message/sipfrag") => {
                let frag = part.parse_sipfrag()?;
                println!("  fragment: {:?}", frag.message_type);
            }
            other => println!("  unhandled: {}", other.unwrap_or("(none)")),
        }
    }
}
```

A part split from a multipart body carries the headers the sender wrote between
the boundary and the blank line, whatever they are. The single part for a body
that does not split has no such block on the wire, so `body_as_parts()`
fabricates one: the body verbatim, and the message's `Content-*` headers copied
down — compact `c`/`e` expanded to their full names, `Content-Length`
left off because it counts the message body and stops describing the part once
you rewrite it. So `part.content_transfer_encoding()` answers the same on both
kinds, and a loop that dispatches on `media_type()` cannot mistake an encoded
body for the text its type claims.

A body typed `multipart/*` that carries no `boundary` parameter, or one the body
never uses, is a body that does not split: it comes back as that single part,
still typed `multipart/*`, rather than as nothing at all.

Splitting descends one level. A nested `multipart/*` comes back as a part with
its type intact; call `part.body_parts()` on it to go deeper — the depth is
yours to choose.

### Content-type-aware body access

`ParsedSipMessage` provides three methods for body access:

- `body_data()` — raw bytes as UTF-8 (no processing, exact wire representation)
- `body_text()` — for JSON content types, unescapes RFC 8259 string escape sequences (`\r\n` → CRLF, `\t` → tab, `\"` → `"`, `\uXXXX` → Unicode including surrogate pairs); passthrough for all other content types
- `json_field(key)` — parses body as JSON, returns unescaped string value for a top-level key; returns `None` if content type is not JSON, body is invalid, key is missing, or value is not a string

JSON-aware behavior activates for `application/json` and any `application/*+json` subtype (e.g., `application/emergencyCallData.AbandonedCall+json`). Matching is case-insensitive; media type parameters like `charset=utf-8` are ignored.

```rust
use std::fs::File;
use freeswitch_sofia_trace_parser::ParsedMessageIterator;

let file = File::open("profile.dump")?;
for result in ParsedMessageIterator::new(file) {
    let msg = result?;

    // Extract embedded INVITE from NG9-1-1 AbandonedCall JSON NOTIFY
    if let Some(invite) = msg.json_field("invite") {
        println!("{}", invite); // actual CRLF, not literal \r\n
    }

    // body_text() unescapes JSON — greppable with regex
    let text = msg.body_text();
    if text.contains("urn:service:sos") {
        println!("Emergency call: {}", msg.call_id().unwrap_or("-"));
    }
}
```

### Pcap export (feature: `pcap`)

```toml
[dependencies]
freeswitch-sofia-trace-parser = { version = "0", features = ["pcap"] }
```

```rust
use std::fs::File;
use freeswitch_sofia_trace_parser::{MessageIterator, PcapConfig, PcapWriter};

let dump = File::open("profile.dump")?;
let pcap = File::create("trace.pcap")?;
let mut w = PcapWriter::new(pcap, PcapConfig::default())?;
for result in MessageIterator::new(dump) {
    w.write_message(&result?)?;
}
```

`PcapWriter` synthesizes a libpcap-classic file from parsed frames or
reassembled messages. The dump only carries the remote endpoint, so the
caller supplies a local endpoint via `PcapConfig` (defaults: RFC 5737
`192.0.2.1:5060` and RFC 3849 `[2001:db8::1]:5060` documentation
addresses). TLS/WSS payloads are decrypted SIP in the dump and are
emitted as plain TCP on the original ports.

`PcapLayer::Transport` (default) emits SLL + IP + UDP/TCP + SIP for
direct Wireshark dissection. `PcapLayer::Network` emits LINKTYPE_RAW + IP
+ SIP-as-IP-payload (proto 253) for tooling that consumes raw IP.

### Streaming from pipes

```rust
use std::process::{Command, Stdio};
use freeswitch_sofia_trace_parser::MessageIterator;

let child = Command::new("xzcat")
    .arg("profile.dump.1.xz")
    .stdout(Stdio::piped())
    .spawn()?;

for msg in MessageIterator::new(child.stdout.unwrap()) {
    let msg = msg?;
    // process message...
}
```

### Concatenating multiple files

```rust
use std::fs::File;
use freeswitch_sofia_trace_parser::FrameIterator;

let f1 = File::open("profile.dump.2")?;
let f2 = File::open("profile.dump.1")?;
let chain = std::io::Read::chain(f1, f2);

for frame in FrameIterator::new(chain) {
    let frame = frame?;
    // Truncated first frames at file boundaries are handled automatically
}
```

## Edge Cases Handled

- Truncated first frame (rotated files, `xzgrep` extracts, pipe mid-stream)
- `\x0B` in XML/binary content (not a boundary unless followed by valid header)
- Multiple SIP messages aggregated in one TCP read
- TCP segment reassembly (consecutive same-direction same-address frames)
- File concatenation (`cat dump.2 dump.1 | parser`)
- Non-UTF-8 content (works on `&[u8]`)
- EOF without trailing `\x0B\n`
- Multipart MIME bodies (SDP + PIDF/EIDO splitting for NG-911)
- Nested multipart parts (split on request, one level per call)
- `message/sipfrag` bodies without a start line or trailing CRLF (RFC 3420)
- JSON body unescaping for `application/json` and `application/*+json` content types
- TLS keep-alive whitespace (RFC 5626 CRLF probes, sofia-sip bare `\n`)
- Logrotate replay detection (partial frame re-written at start of new file)
- Incomplete frames at EOF (byte_count exceeds available content)
- Byte-level input coverage tracking (`ParseStats` with unparsed region reporting)

## Validated Against Production Data

Tested against 83 production dump files (~12GB) from FreeSWITCH NG-911 infrastructure:

| Profile | Files | Frames | Messages | Multi-frame | byte_count mismatches |
|---|---|---|---|---|---|
| TCP IPv4 | 14 | 6.2M | 6.0M | 21,492 (max 7) | 0 |
| UDP IPv4 | 13 | 4.8M | 4.8M (1:1) | 0 | 0 |
| TLS IPv6 | 18 | 5.9M | 5.9M | 108 | 0 |
| TLS IPv4 | 5 | 660K | 660K | 70 | 0 |
| TCP IPv6 | 3 | 327K | 327K | - | 0 |
| UDP IPv6 | 3 | 301K | 301K (1:1) | 0 | 0 |
| Internal TCP v4 | 13 | 723K | - | - | 0 |
| Internal TCP v6 | 13 | 836K | - | - | 0 |

- Zero byte_count mismatches across all frames
- 99.99%+ of reassembled messages start with a valid SIP request/response line
- Level 3 SIP parsing: 100% on all tested profiles (TCP, UDP, TLS)
- Multipart body splitting: 1,223 multipart messages, 2,446 parts (SDP + PIDF), 0 failures
- File concatenation (`cat dump.29 dump.28 |`): 965,515 frames, zero mismatches

### Input coverage tracking

Every sample file is verified for byte-level parse coverage. Each unparsed region is
classified by `SkipReason`:

- `PartialFirstFrame` — truncated frame at start of file (logrotate, pipe, grep extract), capped at 65535 bytes
- `OversizedFrame` — skipped region exceeds 65535 bytes (corrupt or non-dump content)
- `ReplayedFrame` — logrotate wrote a partial frame tail at the start of the new file
- `MidStreamSkip` — unrecoverable bytes skipped mid-stream (e.g., TCP reassembly edge case)
- `IncompleteFrame` — frame at EOF with fewer bytes than declared in the header
- `InvalidHeader` — data starts with `recv`/`sent` but header fails to parse

`ParseStats` exposes `bytes_read`, `bytes_skipped`, and detailed `UnparsedRegion` records
with offset, length, and skip reason for each region.

## Memory Profile

The parser is designed for constant-memory streaming of arbitrarily large inputs,
including multi-day dump file chains (50GB+). Memory behavior was validated using
jemalloc heap profiling (`_RJEM_MALLOC_CONF=prof:true`) and gdb inspection of live
data structures during processing of 50+ chained dump files.

**Parser internals at runtime (gdb-verified):**

- `FrameIterator::buf` — 64KB capacity, ~200 bytes used (single read buffer, never grows)
- `MessageIterator::buffers` — 0 entries (TCP reassembly buffers evicted after message extraction)
- `MessageIterator::ready` — 0 entries, capacity 10 (drained each iteration)

**Design choices that maintain constant memory:**

- `SkipTracking` defaults to `CountOnly` — no allocation for unparsed region tracking unless opted in
- TCP connection buffers are eagerly removed after complete message extraction
- Stale buffers (>2h inactive) are evicted via time-based sweep to handle TLS ephemeral port accumulation
- `flush_all()` clears the entire buffer map at EOF

**Consumers processing many files** should open files lazily (one at a time) rather
than using `Read::chain()` upfront, which keeps all file handles and decompression
state alive for the entire run. With 50+ XZ-compressed dump files, eager chaining
consumed 172MB of LZMA decoder state alone.

## CLI Tool

OPTIONS keepalives are excluded by default (use `--all-methods` to include them).

```sh
# One-line summary (OPTIONS excluded by default)
freeswitch-sofia-trace-parser profile.dump

# Pipe from xzcat
xzcat profile.dump.1.xz | freeswitch-sofia-trace-parser

# Filter by method — shows INVITE requests and their 100/180/200 responses
freeswitch-sofia-trace-parser -m INVITE profile.dump

# Filter by Call-ID regex
freeswitch-sofia-trace-parser -c '6fba3e7e-dddf' profile.dump

# Header regex — all sent INVITEs from a specific extension
freeswitch-sofia-trace-parser -m INVITE -d sent -H 'From=Extension 1583' profile.dump

# Grep for a string anywhere in the SIP message (headers + body)
freeswitch-sofia-trace-parser -g '15551234567' profile.dump

# Body grep — match only in message body (SDP, EIDO XML, etc.)
freeswitch-sofia-trace-parser -b 'conference-info' -m NOTIFY --body profile.dump

# Extract SDP body from a specific call's INVITEs
freeswitch-sofia-trace-parser -c '6fba3e7e' -m INVITE -d sent --body profile.dump

# Full SIP message output
freeswitch-sofia-trace-parser -c '6fba3e7e' --full profile.dump

# Statistics: method and status code distribution
freeswitch-sofia-trace-parser --stats profile.dump

# Multiple files (concatenated in order)
freeswitch-sofia-trace-parser profile.dump.2 profile.dump.1 profile.dump

# Raw frames (level 1) or reassembled messages (level 2)
freeswitch-sofia-trace-parser --frames profile.dump
freeswitch-sofia-trace-parser --raw profile.dump

# Export matched messages to pcap (stdout)
freeswitch-sofia-trace-parser -c '6fba3e7e' --pcap-export profile.dump > call.pcap
freeswitch-sofia-trace-parser --pcap-export --pcap-layer 3 profile.dump > raw-ip.pcap
```

### Dialog mode

Use `-D` to expand matched messages to full Call-ID conversations. When any message
matches, all messages sharing its Call-ID are output. Single pass — works with stdin/pipes.

```sh
# Find dialogs containing INVITEs, show full call flow
freeswitch-sofia-trace-parser -D -m INVITE profile.dump

# Find all dialogs related to an incident ID (across profiles)
freeswitch-sofia-trace-parser -D -H 'Call-Info=abc123def456' \
    esinet1-v4-tcp.dump.* esinet1-v6-tcp.dump.*

# Find dialogs by phone number anywhere in message
freeswitch-sofia-trace-parser -D -g '15551234567' profile.dump.*

# Find dialogs by body content (EIDO XML, PIDF)
freeswitch-sofia-trace-parser -D -b 'Moncton' --full profile.dump.*

# Works with stdin/pipes
xzcat profile.dump.1.xz | freeswitch-sofia-trace-parser -D -m INVITE
```

Terminated dialogs (BYE + 200 OK) that never matched are pruned during processing
to limit memory usage. Unmatched Call-IDs with only OPTIONS traffic are never buffered.

### Filter options

| Flag | Description |
|---|---|
| `-m, --method <VERB>` | Include method (request + responses via CSeq), repeatable |
| `-x, --exclude <VERB>` | Exclude method (request + responses), repeatable |
| `-c, --call-id <REGEX>` | Match Call-ID by regex |
| `-d, --direction <DIR>` | Filter by direction (`recv`/`sent`) |
| `-a, --address <REGEX>` | Match address by regex |
| `-H, --header <NAME=REGEX>` | Match header value by regex, repeatable |
| `-g, --grep <REGEX>` | Match regex against full reconstructed SIP message |
| `-b, --body-grep <REGEX>` | Match regex against message body only |
| `-D, --dialog` | Expand matches to full Call-ID conversations |
| `--all-methods` | Include OPTIONS (excluded by default) |

### Output modes

| Flag | Description |
|---|---|
| *(default)* | One-line summary per message |
| `--full` | Full SIP message with metadata header |
| `--headers` | Headers only, no body |
| `--body` | Body only (for SDP/PIDF extraction) |
| `--raw` | Raw reassembled bytes (level 2) |
| `--frames` | Raw frames (level 1) |
| `--stats` | Method and status code distribution + input coverage |
| `--pcap-export` | Emit libpcap-classic to stdout (use with `--pcap-layer 3\|4`) |
| `--pcap-layer N` | 3 = Level-1 frames as IP+SIP (proto 253); 4 = Level-2 messages as IP+UDP/TCP+SIP (default) |
| `--unparsed` | Report unparsed input regions to stderr (combinable with any mode) |

## FreeSWITCH Setup

See [docs/freeswitch-setup.md](docs/freeswitch-setup.md) for the required patches,
SIP profile configuration, and log rotation setup.

## Building

```sh
cargo build --release
```

## Testing

```sh
# Unit tests (no external files needed)
cargo test --lib

# Integration tests (requires production samples in samples/)
cargo test --test level1_samples -- --nocapture  # Frame parsing
cargo test --test level2_samples -- --nocapture  # TCP reassembly, Content-Length splitting
cargo test --test level3_samples -- --nocapture  # SIP parsing, multipart, method extraction
```

Integration tests validate at each parser level:

- **Level 1**: Frame parsing, transport detection, address format, byte_count accuracy, and parse stats coverage (max 1 partial first frame per file, zero invalid header skips)
- **Level 2**: TCP reassembly, UDP pass-through, interleaved multi-address reassembly, frame accounting, and parse stats delegation
- **Level 3**: SIP request/response parsing, Call-ID/CSeq extraction, multipart MIME splitting, method distribution, and parse stats delegation

The `all_samples_consistent_frame_counts` test iterates all sample files per profile and asserts parse stats on each individually.

See [CLAUDE.md](CLAUDE.md) for test architecture details.

## Related crates

FreeSWITCH and SIP crates by the same author, usable independently:

- [`freeswitch-log-parser`](https://crates.io/crates/freeswitch-log-parser) —
  parses FreeSWITCH's own logs and ships the `fslog` CLI. Complements this
  crate: it gives you the channel-level view, this one gives you the SIP
  messages behind it.
- [`freeswitch-types`](https://crates.io/crates/freeswitch-types) — typed
  FreeSWITCH enums (call direction, channel/call state, hangup causes).
- [`freeswitch-esl-tokio`](https://crates.io/crates/freeswitch-esl-tokio) — async
  ESL client, for reading events off a live switch.
- [`sip-uri`](https://crates.io/crates/sip-uri) — RFC 3261 SIP/SIPS, RFC 3966
  `tel:`, RFC 8141 URN parser. Zero dependencies.
- [`sip-header`](https://crates.io/crates/sip-header) — SIP header field parsers
  (name-addr, Call-Info, History-Info, Geolocation, conference-info).

## License

LGPL-2.1-or-later
