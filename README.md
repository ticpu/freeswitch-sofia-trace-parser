# freeswitch-sofia-trace-parser

Rust library and CLI for parsing FreeSWITCH `mod_sofia` SIP trace dump files.

## Overview

FreeSWITCH logs SIP traffic to dump files at
`/var/log/freeswitch/sip_traces/{profile}/{profile}.dump` (rotated as `.dump.1.xz`, etc.).

This library provides a streaming, multi-level parser:

- **Level 1 — Frames**: Split raw bytes on `\x0B\n` boundaries, parse frame headers
- **Level 2 — Messages**: Reassemble TCP segments, split aggregated messages by Content-Length
- **Level 3 — Parsed SIP**: Extract method/status, headers, and body

## Library Usage

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

## Validated Against Production Data

Tested against 53 production dump files (~5.5GB) from FreeSWITCH NG-911 infrastructure:

| Profile | Frames | Messages | Multi-frame | byte_count mismatches |
|---|---|---|---|---|
| TCP IPv4 (10 files) | 4.8M | 4.6M | 17,935 (max 6) | 0 |
| UDP IPv4 (10 files) | 4.1M | 4.1M (1:1) | 0 | 0 |
| TLS IPv6 (11 files) | 4.7M | 4.7M | 108 | 0 |
| TLS IPv4 (2 files) | 252K | 251K | 70 | 0 |
| Internal TCP v4 (10 files) | 605K | - | - | 0 |
| Internal TCP v6 (10 files) | 716K | - | - | 0 |

- Zero byte_count mismatches across all frames
- 99.99%+ of reassembled messages start with a valid SIP request/response line
- File concatenation (`cat dump.29 dump.28 |`): 965,515 frames, zero mismatches

## Building

```sh
cargo build --release
```

## Testing

```sh
# Unit tests (no external files needed)
cargo test --lib

# Integration tests (requires production samples in samples/)
cargo test --test level1_samples -- --nocapture
```

See [CLAUDE.md](CLAUDE.md) for testing details.

## License

LGPL-2.1-or-later
