# FreeSWITCH Sofia Trace Parser — Developer Guide

## Project Type

This is a **library-first** crate. `src/bin/main.rs` is a sample (but complete) CLI implementation.
`Cargo.lock` is gitignored per Cargo convention for libraries.

## Library Code Rules

- **No `unwrap()`/`expect()`/`panic!()` in library code** outside of tests. Return
  `Result` or `Option` instead.
- **Binary-only dependencies must be feature-gated** behind the `cli` feature.
  Library consumers (`default-features = false`) must not pull in CLI deps.
- **CLI-only modules must not be `pub` in `lib.rs`.** Code used only by the binary
  lives under `src/bin/` (e.g. `src/bin/grep.rs`), not in the library.
- **No `pub mod` names that shadow `std`** (e.g. don't name a module `fmt`, `io`,
  `collections`).
- **Never expose dependency types in public signatures.** A dependency major-version
  bump becomes a semver break if its types leak into the public API.

## Build & Test Workflow

**Always run `cargo fmt` before every commit.** The pre-commit hook enforces
formatting, clippy, gitleaks, tests, and semver-checks.

```sh
cargo fmt
cargo check --no-default-features --message-format=short  # lib only
cargo check --message-format=short
cargo clippy --fix --allow-dirty --message-format=short
cargo test --release --lib                    # unit tests (fast, no sample files needed)
cargo test --release --test level1_samples    # Level 1 integration tests (requires samples/)
cargo test --release --test level2_samples    # Level 2 integration tests (requires samples/)
cargo test --release --test level3_samples    # Level 3 integration tests (requires samples/)
```

## Release Workflow

Before tagging a release:

```sh
cargo semver-checks --baseline-rev <previous-tag> --only-explicit-features
cargo clippy --release -- -D warnings
cargo test --release
cargo build --release
```

Tag with a signed annotated tag. Include a brief changelog in the tag message:

```sh
git tag -as v0.X.0 -m "v0.X.0

- Brief changelog entry
- Another change"
git push --tags
```

**Never `cargo publish` without completing these steps first:**

1. Create a signed annotated tag (`git tag -as`)
2. Push the tag (`git push --tags`)
3. Wait for CI to pass on the tagged commit
4. Only then `cargo publish`

## Test Architecture

### Unit tests (`cargo test --lib`)

Always available, no external dependencies. Cover:

- Frame header parsing (all transports, address formats, timestamp variants)
- Frame iterator (boundary detection, truncated first/last frames, file concatenation, garbage recovery)
- Message reassembly (TCP grouping, UDP pass-through, direction/address splits)
- Aggregation splitting (Content-Length based multi-message splitting)
- SIP parsing (request/status lines, headers, body extraction)

### Integration tests (`cargo test --test level{1,2,3}_samples`)

Require production sample files in `samples/` (gitignored, contain PII).
Tests skip gracefully if files are missing — they check `path.exists()` and return early.

Sample files are raw binary FreeSWITCH dump files (~50-350MB each):

- `esinet1-v4-tcp.dump.{20..29}` — TCP IPv4
- `esinet1-v4-udp.dump.{20..29}` — UDP IPv4
- `esinet1-v6-tls.dump.{20..29}` — TLS IPv6
- `internal-v4.dump.{20..29}` — internal TCP IPv4
- `internal-v6.dump.{20..29}` — internal TCP IPv6
- `esinet1-v6-tls.dump.180` — TLS IPv6 with real traffic (INVITE/NOTIFY/BYE)
- `esinet1-v4-tls.dump.{179,180}` — TLS IPv4 (180 has real traffic)
- `esinet1-v4-tcp.dump.4` — TCP IPv4 with ESInet provider traffic

Logrotate numbering: higher number = older file.

Level 3 tests tolerate a small number of parse failures (~0.004% on TCP) caused by
TCP reassembly edge cases producing fragments without valid SIP first lines.

The `file_concatenation_two_dumps` test validates `Read::chain()` across two files
(simulating `cat dump.29 dump.28 | parser`).

### Running integration tests

```sh
# All integration tests
cargo test --release --test level1_samples -- --nocapture
cargo test --release --test level2_samples -- --nocapture
cargo test --release --test level3_samples -- --nocapture

# Single test
cargo test --release --test level1_samples esinet1_v4_tcp -- --nocapture
```

## Development Methodology — TDD

This project follows test-driven development:

1. Write failing tests that reproduce the bug or specify the new behavior
2. Confirm tests fail (`cargo test --lib`)
3. `cargo fmt && git commit --no-verify` (red phase — clippy/tests will fail, but code must be formatted)
4. Implement the fix/feature
5. Confirm all tests pass
6. Commit the implementation (hooks run normally)

## Investigation Principle

Before modifying the data stream (frame parsing, message reassembly, SIP parsing),
consider all 3 parsing levels. The parser aims for 100% accuracy — no missing bytes.
If a new dump file triggers errors, investigate the root cause across all levels before
assuming malformed data and adding workarounds.

## Key Design Decisions

See [`docs/design-rationale.md`](docs/design-rationale.md) for the full
engineering rationale. Summary of the major decisions:

### Boundary detection: byte_count-first strategy

The `\x0B\n` boundary is validated two ways:

1. **Primary**: Check at expected position (`content_start + byte_count`). If `\x0B` is there, accept it. This handles file concatenation where garbage follows the boundary.
2. **Fallback**: Scan for `\x0B\n` followed by a valid frame header (`recv/sent N bytes ...`). This handles `\x0B` appearing in XML/binary content.

### Streaming design

All iterators accept `impl Read`. Truncated first frames are expected and logged via `tracing::warn!`. The parser never panics on malformed input.

### Multi-level architecture

```
Level 1: FrameIterator  — raw bytes → Frame (header + content)
Level 2: MessageIterator — Frame → SipMessage (reassembled + split)
Level 3: ParsedSipMessage — SipMessage → parsed headers/body
```

Each level wraps the previous, all streaming.
