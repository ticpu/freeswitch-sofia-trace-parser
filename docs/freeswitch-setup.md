# FreeSWITCH Setup

This parser reads dump files produced by libsofia-sip's `TPTAG_DUMP()` feature. Two
patches are required to enable file-based SIP trace logging with full timestamps.
Both patches are included in `patches/`.

## Patches

Apply against FreeSWITCH v1.10.x and its bundled sofia-sip:

1. **`0001-sofia-sip-add-date-to-tport-logging.patch`** (sofia-sip)
   Adds `YYYY-MM-DD` date prefix to frame timestamps. Without this patch, timestamps
   are time-only (`HH:MM:SS.usec`) and lack date context across rotated files. The
   parser supports both formats.

2. **`0002-mod_sofia-add-sip-dump-file-option.patch`** (FreeSWITCH)
   Adds the `sip-dump-file` SIP profile parameter that passes a file path to
   `TPTAG_DUMP()`, enabling persistent binary SIP trace logging to disk.

## SIP Profile Configuration

Add `sip-dump-file` to each SIP profile that should be traced. Create the target
directory before starting FreeSWITCH:

```sh
mkdir -p /var/log/freeswitch/sip_traces/esinet1-v6-tcp
```

In the SIP profile XML (e.g., `conf/sip_profiles/esinet1-v6-tcp.xml`), add after
the `sip-trace` parameter:

```xml
<param name="sip-dump-file" value="/var/log/freeswitch/sip_traces/esinet1-v6-tcp/esinet1-v6-tcp.dump"/>
```

One dump file per profile. The file grows continuously until rotated.

## Log Rotation

Dump files grow fast on busy systems. The included `patches/sip-traces.logrotate`
rotates daily with XZ compression and 10-year retention. Install it as:

```sh
cp patches/sip-traces.logrotate /etc/logrotate.d/sip-traces
```

The rotation uses `copy` + `fallocate -c` (punch-hole) instead of `copytruncate`,
which avoids the race condition where writes between the copy and truncate are lost.
The `fallocate` call deallocates the already-rotated blocks from the original file
on filesystems that support hole-punching (ext4, XFS, btrfs, bcachefs), effectively
truncating the file without losing in-flight writes.

## Reading Dump Files

```sh
# Live file
freeswitch-sofia-trace-parser /var/log/freeswitch/sip_traces/esinet1-v6-tcp/esinet1-v6-tcp.dump

# Rotated compressed files (oldest first)
xzcat esinet1-v6-tcp.dump.3.xz esinet1-v6-tcp.dump.2.xz esinet1-v6-tcp.dump.1.xz \
    | freeswitch-sofia-trace-parser -D -m INVITE

# Or pass multiple files directly (parser handles concatenation)
freeswitch-sofia-trace-parser esinet1-v6-tcp.dump.2 esinet1-v6-tcp.dump.1 esinet1-v6-tcp.dump
```
