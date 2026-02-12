# FreeSWITCH Sofia Trace Parser — Library + CLI

## Goal

Build a Rust **library crate** + **CLI binary** that robustly parses FreeSWITCH SIP trace
dump files. Multi-level architecture: raw text → segments → frames → SIP messages → dialogs.
The library must handle all real-world edge cases and be reusable across multiple projects.

## Existing Projects to Study

**READ BOTH of these before starting. They contain hard-won production insights.**

### 1. noans-report (consumer of this library)

**Path**: `/mnt/bcachefs/@home/jerome.poulin/GIT/freeswitch-database_utils/tools/noans-report/`

- `src/parser.rs` — line-by-line parser with heuristic workarounds (fragile, being replaced)
- `src/models.rs` — `AbandonedCallEvent`, `normalize_phone`
- `src/main.rs` — CLI with `-v`/`-vv`/`-vvv` tracing

**Use case**: Extract `incident_id` and `caller_phone` from `AbandonedCall` NOTIFY messages.
The NOTIFY body is JSON containing an embedded INVITE. With proper reassembly, extraction
becomes a simple regex on the complete reassembled content — no heuristics needed.

### 2. freeswitch-sip-trace-analyzer (prior attempt, has useful patterns)

**Path**: `/home/jerome.poulin/GIT/freeswitch-sip-trace-analyzer/`

Key files to study:

- `src/structured_parser/phase1_stream_parser.rs` — `\x0B\n` boundary splitting, chunked reading
- `src/sip_segment.rs` — `Segment`, `Packet` structs
- `src/lazy_stitcher.rs` — reassembles fragments by direction+address+timestamp
- `src/sip_parser.rs` — splits aggregated messages using Content-Length
- `CLAUDE.md` — detailed format documentation and pitfalls

This project confirmed `\x0B\n` as the boundary marker and has extensive notes on edge cases.
Its stitcher uses: `same direction + same TCP address + timestamps within 1 second`.

## Dump File Format Specification

FreeSWITCH `mod_sofia` writes SIP trace dumps to:
`/var/log/freeswitch/sip_traces/{profile}/{profile}.dump`
Rotated files: `.dump.1.xz`, `.dump.2.xz`, etc.

### Segment Boundary: `\x0B\n`

Each TCP/UDP segment is logged as a **frame** delimited by `\x0B\n` (vertical tab + newline):

```
recv 1440 bytes from tcp/[2001:db8::1]:5060 at 13:03:21.674883:\r\n
<SIP headers with \r\n line endings>\r\n
\r\n
<body bytes>\x0B\n
```

Hex proof from production data:
```
000002b0: 3138 0b0a 7265 6376     18..recv    ← content ends, \x0B\n, next frame
```

The `\x0B\n` is the PRIMARY and RELIABLE boundary. This is how FreeSWITCH separates frames
in its trace logger. The `\x0B` appears at the END of each frame's content.

### Frame Header Format

```
(recv|sent) <byte_count> bytes (from|to) <transport>/<address> at <timestamp>:
```

- **Direction**: `recv` (inbound) or `sent` (outbound)
- **Byte count**: decimal integer — size of content that follows (until `\x0B`)
- **Preposition**: `from` (with recv) or `to` (with sent)
- **Transport**: `tcp`, `udp`, `tls`, or `wss`
- **Address**: IPv4 `ip:port` or IPv6 `[ip]:port`
- **Timestamp**: Two formats exist:
  - Time-only (current): `HH:MM:SS.microseconds` (e.g. `13:03:21.674883`)
  - Full datetime (future, plan for this): `YYYY-MM-DD HH:MM:SS.microseconds` (e.g. `2026-02-01 13:03:21.674883`)
- Trailing colon+newline `:\n` terminates the header

Examples:
```
recv 1440 bytes from tcp/[2001:4958:10:14::4]:30046 at 13:03:21.674883:
sent 681 bytes to tcp/[2001:4958:10:14::4]:30046 at 13:03:21.675500:
recv 457 bytes from udp/10.0.0.1:5060 at 00:19:47.123456:
recv 100 bytes from tcp/192.168.1.1:5060 at 2026-02-01 10:00:00.000000:
```

### SIP Content Within Frames

SIP headers use real `\r\n` (bytes 0x0D 0x0A). Blank line `\r\n\r\n` separates headers
from body. Body format depends on Content-Type.

When the body is JSON (e.g. `AbandonedCall`), the JSON string contains `\r\n` as
JSON-escaped sequences (literal bytes `\`, `r`, `\`, `n` — 0x5C 0x72 0x5C 0x6E),
NOT real newlines. This means the JSON body has NO real `\n` characters and spans
the entire frame content between the blank line and the `\x0B` boundary.

### TCP Segment Reassembly

A single SIP message may span multiple frames. FreeSWITCH logs each TCP segment as a
separate frame. Consecutive `recv` frames from the **same address** belong to the same
SIP message and must be concatenated to reconstruct the complete message.

A typical NOTIFY with a 6KB JSON body produces 5-7 frames of ~1440 bytes each.
The byte count in the header tells you how many content bytes are in THAT frame.

### Multiple SIP Messages in One Frame (Aggregation)

A single frame can contain 2+ complete SIP messages back-to-back. This happens when
FreeSWITCH reads multiple messages from the TCP buffer at once. Use `Content-Length`
to split them.

Example: `recv 2856 bytes` containing two NOTIFYs — first has `Content-Length: 14`,
body is 14 bytes, second NOTIFY starts immediately after without any separator.

### Edge Cases (Production-Verified)

1. **`\x0B` in content**: XML payloads can contain `\x0B` that is NOT a boundary.
   Boundary is ONLY `\x0B\n` where what follows is a valid frame header.
   The analyzer uses: `\x0B\n(recv|sent) \d{1,5} bytes (from|to) (tcp|udp)/`

2. **Non-UTF-8 bytes**: Binary data in SDP, multipart MIME, or corrupted streams.
   Parser MUST work on `&[u8]`, never assume valid UTF-8.

3. **UDP vs TCP**: UDP frames are always complete messages (no reassembly needed).
   TCP frames may need reassembly. Transport info is in the frame header.

4. **EOF handling**: Last frame may lack trailing `\x0B\n`.

5. **Byte count validation**: `byte_count` in header should match content size.
   Use for validation but don't hard-fail on mismatch.

6. **First frame in file**: May be partial (missing header) if file was truncated
   or extracted with grep. Skip gracefully.

7. **xz-compressed files**: Rotated dumps use xz. Library accepts `impl Read`,
   callers handle decompression.

## Architecture — Multi-Level Parsing

```
Level 0: Raw bytes (impl Read)
   ↓ split on \x0B\n
Level 1: Frames (header + raw content bytes)
   ↓ group consecutive same-direction same-address frames
Level 2: SIP Messages (reassembled complete messages)
   ↓ split aggregated frames by Content-Length
Level 2b: Split Messages (one SIP message per item)
   ↓ parse SIP headers
Level 3: Parsed SIP Messages (method/status, headers, body)
   ↓ group by Call-ID
Level 4: SIP Dialogs (all messages sharing a Call-ID)
```

### Level 1: Frame Iterator

```rust
pub struct Frame {
    pub direction: Direction,
    pub byte_count: usize,
    pub transport: Transport,
    pub address: String,
    pub timestamp: Timestamp,
    pub content: Vec<u8>,        // raw bytes between header \n and \x0B
}

pub enum Direction { Recv, Sent }
pub enum Transport { Tcp, Udp, Tls, Wss }

/// Timestamp supports both time-only and full datetime
pub enum Timestamp {
    TimeOnly { hour: u8, min: u8, sec: u8, usec: u32 },
    DateTime { date: (u16, u8, u8), hour: u8, min: u8, sec: u8, usec: u32 },
}
```

`FrameIterator<R: Read>` — streaming, yields `Frame` values. Reads chunks, splits on
`\x0B\n`. This is the foundation all other levels build on.

### Level 2: SIP Message Reassembler

```rust
pub struct SipMessage {
    pub direction: Direction,
    pub transport: Transport,
    pub address: String,
    pub timestamp: Timestamp,       // from first frame
    pub content: Vec<u8>,           // reassembled complete SIP message bytes
    pub frame_count: usize,         // how many frames were combined
}
```

`MessageIterator<R: Read>` wraps FrameIterator:

- Groups consecutive frames with same direction + address
- Concatenates content bytes
- Handles aggregated frames (split by Content-Length)
- UDP frames pass through as-is (always complete)

### Level 3: Parsed SIP Message

```rust
pub struct ParsedSipMessage {
    pub direction: Direction,
    pub transport: Transport,
    pub address: String,
    pub timestamp: Timestamp,
    pub message_type: SipMessageType,
    pub headers: Vec<(String, String)>,  // ordered header list
    pub body: Vec<u8>,
    pub frame_count: usize,
}

pub enum SipMessageType {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
}
```

Parses the first line (request-line or status-line), extracts headers until blank line,
body is everything after. Provides helper methods: `call_id()`, `content_type()`,
`content_length()`, `cseq()`, etc.

### Level 4: SIP Dialog (future, lower priority)

Group parsed messages by Call-ID into dialog sequences. Not needed for initial release
but the architecture should make it easy to add.

## CLI Tool

Binary target alongside the library. Used for testing the parser and extracting data.

```
freeswitch-sofia-trace-parser [OPTIONS] <FILE>
freeswitch-sofia-trace-parser [OPTIONS] -    # stdin
```

### Filter Options

```
-m, --method <VERB>         Filter by SIP method (INVITE, NOTIFY, OPTIONS, etc.)
-c, --call-id <ID>          Filter by Call-ID (substring match)
-x, --exclude <VERB>        Exclude SIP method (repeatable)
    --exclude-ok            Exclude 200 OK responses (shortcut for common case)
-d, --direction <DIR>       Filter by direction (recv/sent)
-a, --address <ADDR>        Filter by address (substring match)
```

### Output Modes

```
    --frames                Show raw frames (level 1)
    --messages              Show reassembled messages (level 2, default)
    --headers-only          Show only SIP headers, omit body
    --summary               One-line summary per message: timestamp direction method call-id
-v, --verbose               Increase verbosity (-v info, -vv debug, -vvv trace)
```

### Example Usage

```sh
# Show all NOTIFYs, exclude keepalive OPTIONS
freeswitch-sofia-trace-parser -m NOTIFY dump.log

# Show everything except OPTIONS and 200 OK
freeswitch-sofia-trace-parser -x OPTIONS --exclude-ok dump.log

# One-line summary of all messages
freeswitch-sofia-trace-parser --summary dump.log

# Filter by Call-ID
freeswitch-sofia-trace-parser -c "abc123" dump.log

# Pipe from xzcat
xzcat dump.1.xz | freeswitch-sofia-trace-parser --summary -

# Debug frame splitting
freeswitch-sofia-trace-parser --frames -vvv dump.log
```

## Sample Data

Directory: `samples/`

- `options_keepalive.dump` — simple recv/sent OPTIONS pairs (from production, IPv4+IPv6)
- `abandoned_call_notify.dump` — multi-frame AbandonedCall NOTIFY (7 frames, ~8KB, real data)

Larger test data (not in repo):
- `/mnt/bcachefs/@home/jerome.poulin/GIT/freeswitch-database_utils/artifacts/debug.log`
  (13.8MB, 401 abandoned call events, created with `xzgrep -C 300`)
- `/home/jerome.poulin/GIT/freeswitch-sip-trace-analyzer/siptraces/` (284-346MB full dumps)

## Testing Strategy

### Unit Tests Per Level

**Frame header parsing**:
- IPv4 address: `recv 100 bytes from tcp/192.168.1.1:5060 at 00:00:01.350874:`
- IPv6 address: `recv 1440 bytes from tcp/[2001:4958:10:14::4]:30046 at 13:03:21.674883:`
- UDP transport: `recv 457 bytes from udp/10.0.0.1:5060 at 00:19:47.123456:`
- TLS transport: `sent 500 bytes to tls/10.0.0.1:5061 at 12:00:00.000000:`
- Time-only timestamp: `at 13:03:21.674883:`
- Full datetime timestamp: `at 2026-02-01 13:03:21.674883:`
- Sent direction with `to`: `sent 681 bytes to tcp/...`
- Invalid/malformed headers → error, not panic

**Frame splitting**:
- Multiple frames separated by `\x0B\n`
- `\x0B` in XML content (NOT a boundary): `<confInfo:us\x0Ber-count>`
- `\x0B\n` NOT followed by valid header (not a boundary)
- `\x0B` at EOF without trailing `\n`
- First frame missing header (partial file) → skip to first valid header
- Byte count in header vs actual content size

**Message reassembly**:
- Single-frame complete message (UDP or small TCP)
- Multi-frame TCP reassembly (same direction + same address)
- Direction change terminates message (recv → sent)
- Address change terminates message (recv from A, recv from B)
- Verify reassembled content is byte-for-byte correct
- Aggregated frame (2 SIP messages in 1 frame, split by Content-Length)

**SIP parsing**:
- Request line: `INVITE sip:user@host SIP/2.0`
- Status line: `SIP/2.0 200 OK`
- Header extraction with correct ordering
- Body after blank line `\r\n\r\n`
- Missing Content-Length (no body expected)
- Multipart MIME bodies

**Integration tests with sample files**:
- Parse `samples/options_keepalive.dump` → verify frame count, methods, addresses
- Parse `samples/abandoned_call_notify.dump` → verify reassembly, extract incident_id + phone

## Project Setup

```toml
[package]
name = "freeswitch-sofia-trace-parser"
edition = "2021"

[lib]
name = "freeswitch_sofia_trace_parser"

[[bin]]
name = "freeswitch-sofia-trace-parser"
path = "src/bin/main.rs"

[dependencies]
memchr = "2"
tracing = "0.1"
clap = { version = "4", features = ["derive"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
```

Minimal dependencies. No regex at the parser level — frame headers have a fixed format
parseable with byte matching. Consumers bring their own regex for SIP content extraction.

## Implementation Order

1. Frame header parser (parse `recv/sent N bytes from/to transport/addr at time:` from `&[u8]`)
2. Frame iterator (chunked reader splitting on `\x0B\n`, yields `Frame`)
3. Unit tests for level 1
4. Message reassembler (group consecutive same-dir same-addr frames, concatenate content)
5. Aggregation splitter (split multi-message frames by Content-Length)
6. Unit tests for level 2
7. SIP message parser (request/status line, headers, body)
8. Unit tests for level 3
9. CLI binary with filter options
10. Integration tests with sample files
11. Test against large production dumps
