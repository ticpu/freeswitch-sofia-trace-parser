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
