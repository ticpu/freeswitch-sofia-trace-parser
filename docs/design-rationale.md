# Design Rationale

## Why This Parser Exists

FreeSWITCH's `mod_sofia` writes SIP traffic to binary dump files at
`/var/log/freeswitch/sip_traces/{profile}/{profile}.dump`, rotated by logrotate
into `.dump.1.xz`, `.dump.2.xz`, etc. These files are the primary diagnostic
tool for NG-911 call tracing, incident reconstruction, and SIP interop debugging
in production PSAP environments.

Before this library, the only parser was a Bash/awk script (`cauca_freeswitch-sip-trace-analyzer`)
that loaded entire dump files into memory (~2GB per profile), performed line-by-line
text matching, and couldn't handle TCP reassembly, multipart MIME, or structured
SIP parsing. It worked, but it was slow, fragile, and couldn't be composed into
other tools.

This library was designed to be a correct, streaming, reusable foundation that
exposes the dump file format honestly and lets callers decide what to do with
the data.

## Why Three Levels

The parser is split into three independent layers, each wrapping the previous:

```
Level 1: FrameIterator      raw bytes -> Frame (header + content)
Level 2: MessageIterator     Frame -> SipMessage (reassembled, split)
Level 3: ParsedMessageIterator  SipMessage -> ParsedSipMessage (headers, body)
```

This wasn't designed top-down from a spec. It emerged from the dump file format
itself: FreeSWITCH writes each `send()`/`recv()` as a separate frame with a text
header and `\x0B\n` boundary. TCP segments arrive as separate frames that need
reassembly. And SIP messages need header/body parsing for anything useful.

Each level is independently useful. A tool that just needs raw frame timing
doesn't pay for SIP parsing. A tool that needs reassembled message bytes
doesn't need to parse headers. The downstream `freeswitch-sip-trace-analyzer`
uses `ParsedMessageIterator` directly, while the torture test uses
`MessageIterator` to extract URIs from raw content.

Every level accepts `impl Read`, so they compose with files, pipes,
`xzcat` subprocesses, `Read::chain()` for file concatenation, and
`GrepFilter` for grep-piped input.

## Boundary Detection: byte_count First

Each frame header includes the byte count FreeSWITCH wrote:

```
recv 1234 bytes from tcp/10.0.0.1:5060 at 14:30:00.123456:
```

The frame ends at the next `\x0B\n` (vertical tab + newline). The naive approach
is to scan for `\x0B\n` in the content, but `\x0B` is valid ASCII that appears
in XML bodies, SDP, and JSON content. A scan-only approach would split frames
incorrectly.

The solution uses byte_count as the primary signal:

1. **Primary**: Check at the expected position (`content_start + byte_count`).
   If `\x0B` is there, accept it. This is correct for well-formed frames and
   handles file concatenation where garbage follows the boundary.

2. **Fallback**: Scan for `\x0B\n` followed by a valid frame header
   (`recv`/`sent N bytes ...`). This handles the rare case where byte_count
   is wrong (never observed in production, but defensive).

Production validation: zero byte_count mismatches across 6.9M+ frames in
83 dump files (~12GB). The primary path handles 100% of real-world data.

## Per-Connection TCP Buffering

The initial Level 2 implementation used naive consecutive-frame grouping:
if two frames had the same direction and address, concatenate them. This
broke immediately on real production data where frames from different
connections interleave:

```
recv 500 bytes from tcp/10.0.0.1:5060 ...   (connection A, fragment 1)
sent 200 bytes to tcp/10.0.0.2:5060 ...     (connection B, response)
recv 800 bytes from tcp/10.0.0.1:5060 ...   (connection A, fragment 2)
```

The fix was per-connection buffering with
`HashMap<(Direction, Address), ConnectionBuffer>`. Each connection maintains
its own reassembly state. Frames are routed to the correct buffer regardless
of interleaving. Messages are emitted when headers (`\r\n\r\n`) and
Content-Length body bytes are fully available.

Buffers are eagerly removed after complete message extraction. This is critical
for constant-memory streaming: without eager removal, TLS profiles with
ephemeral source ports accumulate thousands of dead buffers over multi-day runs.

## Stale Buffer Eviction

TLS connections use ephemeral source ports. Over a multi-day dump stream,
the buffer HashMap grows without bound as new ports appear and old ones
go silent. The parser tracks a synthetic day counter (incrementing when
timestamps wrap past midnight) and evicts buffers inactive for more than
2 hours (RFC 793 TCP keepalive timeout). Empty buffers are evicted silently;
non-empty buffers emit a warning and flush as incomplete messages.

The 2-hour timeout was chosen because it's the standard TCP keepalive
interval. Any connection silent for that long in a VoIP environment
is dead. The synthetic day counter handles `TimeOnly` timestamps
(HH:MM:SS.usec) that don't include dates.

## Why SkipTracking Has Three Modes

Early versions accumulated every unparsed region in a `Vec<UnparsedRegion>`.
Processing 50+ dump files (50GB+) caused unbounded memory growth in the
region list alone, even though the actual parser maintained constant memory.

The fix was `SkipTracking`:

- **CountOnly** (default): Only maintain `bytes_read` and `bytes_skipped`
  counters. Zero allocation. This is what most consumers need.
- **TrackRegions**: Record offset, length, and reason for each skip.
  Useful for `--stats` output.
- **CaptureData**: Also keep the actual skipped bytes. Useful for
  `--unparsed` diagnostics with quoted-printable display.

The default is CountOnly because the parser processes arbitrarily large
inputs and most callers only care about the parse success rate, not the
exact bytes that were skipped.

## Skip Classification

Every byte in the input stream is either parsed into a frame or classified
with a `SkipReason`. This accounting was driven by a production need:
operators need to know whether "99.8% parsed" means "lost a few frames
at logrotate boundaries" or "hit corruption mid-stream."

The six reasons evolved from production observations:

- **PartialFirstFrame** — The first bytes of a dump file are almost always
  a truncated frame from logrotate. The file was rotated mid-write, so the
  new file starts with the tail of whatever frame was being written. This is
  expected and benign. Capped at 65,535 bytes (IP max datagram + boundary).

- **OversizedFrame** — A skip larger than 65,537 bytes at file start.
  Indicates the input isn't a dump file (compressed data, binary garbage).

- **ReplayedFrame** — Logrotate's `copytruncate` creates a race: the
  frame being written when the file is rotated appears partially in both
  the old and new files. Detection heuristic: the skipped content ends with
  `\r\n\r\n\x0B\n` (SIP header terminator + frame boundary). Confirmed by
  hexdump: dump.28 starts with `NS\r\nRoute:...` which is the tail of
  dump.29's last OPTIONS response.

- **MidStreamSkip** — Unclassifiable garbage between valid frames. Rare in
  practice (never observed outside synthetic tests).

- **IncompleteFrame** — EOF arrived before `byte_count` bytes of content.
  The frame header declared N bytes but the file ended with fewer. Tracked
  separately so operators know the file was truncated, not corrupt.

- **InvalidHeader** — Data starts with `recv`/`sent` but fails header
  parsing. Usually a dump restart marker or inter-frame padding that
  wasn't fully stripped.

## TLS Keep-Alive and TransportNoise

RFC 5626 Section 3.5.1 specifies CRLF as a SIP application-layer
keep-alive. sofia-sip sends bare `\n` instead. These 1-byte frames
accumulate in TCP reassembly buffers because the reassembly logic
only recognized `\r\n` pairs as inter-message padding.

The fix operates at two levels:

**Level 2** (MessageIterator): `extract_complete()` drains leading
whitespace (CR, LF, SP, TAB) before looking for SIP message starts.
If the entire buffer is whitespace, it's cleared. This handles the
common case silently during reassembly.

**Level 3** (ParsedMessageIterator): If whitespace-only content escapes
Level 2 (e.g., accumulated during a flush), it returns
`ParseError::TransportNoise` instead of the misleading
`InvalidMessage("no CRLF found")`. This is a distinct error variant so
callers can filter it: the CLI logs it at `debug` level, not `warn`.

The distinction matters operationally. On a TLS profile with keep-alives
enabled, ~353 noise frames per dump file is normal. Logging them as
warnings would drown real errors.

## Content-Type-Aware Body Parsing

NG-911 infrastructure embeds SIP messages inside JSON bodies. A NOTIFY
with Content-Type `application/emergencyCallData.AbandonedCall+json`
contains a JSON object with an `invite` field holding a complete
INVITE message, but with literal `\r\n` escape sequences instead of
actual CRLF line endings.

Grepping for SIP headers in these bodies fails unless the JSON escapes
are resolved. Three methods address different use cases:

- **`body_data()`** returns raw bytes as lossy UTF-8. No processing.
  Use when you need the exact wire representation.

- **`body_text()`** unescapes RFC 8259 JSON string sequences for JSON
  content types: `\r\n` becomes CRLF, `\t` becomes tab, `\uXXXX`
  becomes Unicode (including surrogate pairs). Passthrough for
  non-JSON types. Use when grepping body content.

- **`json_field(key)`** parses the body as JSON and returns the
  unescaped string value of a top-level key. Returns None if the
  content type isn't JSON, the body isn't valid JSON, the key is
  missing, or the value isn't a string.

JSON detection matches `application/json` and any `application/*+json`
subtype, case-insensitive, ignoring media type parameters like
`charset=utf-8`.

## GrepFilter: Handling Piped Input

A common workflow is `grep -C5 'Call-ID.*abc123' profile.dump | parser`.
But `grep -C` inserts `--\n` separator lines between match groups, which
corrupt the binary frame stream.

`GrepFilter<R>` is a `Read` adapter that strips exactly `--\n` and
`--\r\n` lines from the input. It's applied in the CLI before the parser,
making piped grep output transparent. The filter preserves lines like
`---\n` or `-- \n` that aren't grep separators.

This was moved from `src/bin/grep.rs` to `src/grep.rs` and re-exported
from the library when the downstream `freeswitch-sip-trace-analyzer`
needed it. Binary-only code belongs in `src/bin/`; shared utilities
belong in the library.

## Library-First Design

This is a library crate. The CLI (`src/bin/main.rs`) is a sample
implementation, feature-gated behind `cli` to avoid pulling clap, regex,
and tracing-subscriber into library consumers.

Rules that emerged from production use:

- **No `unwrap()`/`expect()`/`panic!()` in library code.** Return
  `Result` or `Option`. The pre-commit hook enforces this.

- **Binary-only deps must be feature-gated.** Library consumers with
  `default-features = false` must not pull CLI dependencies.

- **CLI-only modules stay in `src/bin/`.** No `pub mod` in lib.rs for
  code that only the binary uses.

- **Never expose dependency types in public signatures.** A dependency
  major-version bump becomes a semver break if its types leak into the
  public API. All public signatures use standard library types.

- **Errors are returned, not logged.** The library uses `tracing` for
  diagnostic messages (warn for unexpected conditions, debug for
  expected artifacts), but never swallows errors. The caller decides
  policy.

## Memory Profile

The parser processes arbitrarily large inputs with constant memory.
This was validated with jemalloc heap profiling and gdb inspection
during processing of 50+ chained dump files:

- `FrameIterator::buf` — 64KB capacity, ~200 bytes typical usage
- `MessageIterator::buffers` — 0 entries at steady state (evicted after extraction)
- `MessageIterator::ready` — 0 entries, capacity 10 (drained each iteration)

One production pitfall: using `Read::chain()` to concatenate 50+ XZ
files upfront keeps all LZMA decoder state alive simultaneously (172MB).
The fix is to open files lazily, one at a time, feeding them through
the parser sequentially.

## Multipart MIME for NG-911

NG-911 SIP messages carry both SDP (media negotiation) and PIDF/EIDO
(caller location) as multipart MIME bodies. The parser splits these
into separate `MimePart` structs with their own headers and bodies.

Production data: 1,223 multipart messages split into 2,446 parts
(always SDP + PIDF), zero failures. Boundary extraction handles
quoted boundaries and ignores MIME preamble text.

This was added specifically because emergency call analysis requires
extracting location data (PIDF-LO XML) separately from session
description (SDP), and no SIP library we found handled FreeSWITCH's
dump format.

## Error Recovery at Frame Boundaries

FreeSWITCH writes "dump started at Thu Oct 10 11:59:14 2024" lines
when the dump file is initialized. These appear as invalid frame
headers. The parser recognizes them and skips just the marker line
(plus trailing newlines), not the entire region up to the next boundary.

Between frames, extra `\n` or `\r\n` padding can appear from various
sources (dump restart markers with trailing blank lines, inter-frame
padding). The parser strips this whitespace before attempting header
parsing, which eliminated 10 false recovery events per dump file on
one production sample (recovering 10 previously-lost frames).

Recovery from genuine invalid headers scans forward to the next
`\x0B\n` + valid header pattern and returns `Some(Err(...))` so the
caller sees the error. The library never silently swallows parse
failures.
