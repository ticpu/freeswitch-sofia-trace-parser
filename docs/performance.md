# Performance

Measured with the bundled CLI on production NG-911 dump files. Every number here
came from a pinned, interleaved A/B run; the method is in
[Measuring a change](#measuring-a-change) and matters more than the figures,
which are workload- and build-specific.

## Throughput

Parse-only, reading an uncompressed dump from page cache, all messages parsed
(`--stats --all-methods`), one core:

| CPU | corpus | messages | wall | MB/s | per message |
|---|---|---|---|---|---|
| Ryzen 9 7950X3D (Zen 4) | 352 MB, TCP IPv4 | 477,616 | 0.70 s | 500 | 1.5 µs |
| Xeon Silver 4214 (Cascade Lake) | 248 MB, mixed TCP/UDP/TLS | 330,196 | 1.35 s | 184 | 4.1 µs |
| Neoverse-N1 | 400 MB, TCP IPv4 | 555,765 | 2.17 s | 184 | 3.9 µs |

Per-message cost tracks message *count* far more than byte count — a dump of
short keep-alives costs more per megabyte than one carrying multipart bodies.
Compare like corpora only.

## Rejecting before Level 3

Level 3 turns every header into two owned `String`s. A consumer keeping a small
fraction of a trace should reject earlier, using
[`SipMessage::method`](../src/sip.rs), which reads the method from the
reassembled bytes with no parse.

Same 352 MB TCP dump, Zen 4, before and after the CLI adopted that prefilter:

| invocation | before | after |
|---|---|---|
| `--full --all-methods` (parses everything) | 1.82 s | 1.69 s |
| `--full` (OPTIONS excluded by default) | 937 ms | 558 ms |
| `--full -m INVITE` | 818 ms | 378 ms |

The gap is the traffic mix: OPTIONS keep-alives are ~87% of messages in an
ESInet trace, and INVITE requests under 0.2%. On such a trace the prefilter
skips almost all header extraction.

Decompression does not dominate. Piping a 400 MB xz-compressed slice through
`xzcat` on the Neoverse-N1 took 2.5 s, against 1.6 s for `xzcat` alone and 2.2 s
for the parse alone — the two overlap in the pipe and the parse is the critical
path.

## Measuring a change

Wall clock alone is not enough to accept or reject a parser change at this
scale; several effects are larger than the change being measured.

1. **Prove output identity first.** Hash `--full --all-methods` over several
   dumps before and after, and compare `--stats` in full. A performance change
   that alters output is a bug, and `--stats` is only comparable because its
   ordering is deterministic by construction.
2. **Pin the core.** `taskset -c N`. On a 7950X3D the two CCDs differ (96 MB vs
   32 MB L3, different clocks) and an unpinned run picks between them — worth
   ~9% here, far more than most changes.
3. **Count instructions, not just time.** `perf stat -r 7 -e instructions,cycles`.
   Instruction counts are reproducible to six significant figures; wall clock on
   a shared or thermally-loaded box is not.
4. **Interleave A/B/A/B.** Machine state drifts. A single A-then-B pass has
   repeatedly shown a difference that reversed when run again.
5. **Watch IPC.** Fewer instructions is not faster. Both variants below scan the
   same bytes, and the one retiring less work lost on IPC.

## UTF-8 conversion: measured, not assumed

Header blocks and start-line tokens reach `&str` through one conversion
(`bytes_to_str`), which borrows valid UTF-8 and falls back to lossy only for
malformed input. An earlier version instead tested `is_ascii()` and took
`from_utf8_unchecked`, on the reasoning that SIP is ASCII and full UTF-8
validation is waste.

That reasoning does not survive measurement, because both paths scan every byte
either way. Across three microarchitectures, same corpus per machine, pinned and
interleaved:

| CPU | instruction count | wall clock |
|---|---|---|
| Zen 4 | `is_ascii` 0.50% fewer | no difference; ordering flips between runs |
| Neoverse-N1 | `from_utf8` 0.17% fewer | no difference; ordering flips between runs |
| Cascade Lake | `is_ascii` 0.48% fewer | **`from_utf8` 1.2–1.9% faster**, every pairing |

The instruction-count advantage is real, reproducible, and points in *opposite
directions* per architecture — and it never made `is_ascii` faster on any of the
three. On Cascade Lake `from_utf8` wins on time while retiring more
instructions, by holding higher IPC (2.37 vs 2.28), with roughly a third of the
run-to-run variance.

So the safe conversion is kept: it is never slower, sometimes faster, and it
removes the crate's only `unsafe` block. Anyone reproposing the unchecked path
should bring instruction counts and IPC from more than one CPU.
