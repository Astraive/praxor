# Bounded cache metadata and owned descriptors

This batch fixes Praxor issues #12 and #13 on top of merged default
`f695e1387eebcf3315b91c541b50fecce2a1dddb`. It was independently reviewed.

## Behavior and compatibility

Dynamic durable descriptor checksum names now use owned `Cow` strings. Static
names stay borrowed. The disk format is unchanged; Rust callers constructing
`DurableFormatDescriptor` with string literals must use `.into()` or
`Cow::Borrowed` for the checksum field.

The cache periodically discards obsolete recency generations and releases their
allocation while preserving LRU order. Empty values consume one admission unit;
zero capacity admits no entries. `current_bytes` continues to report payload
bytes, not metadata or the empty-value charge. Queue bounds are relative to the
resident entry count, not a claim that the configured payload budget covers all
key and allocator memory. Generation overflow rebases live events in order.

## Verification

On Windows with pinned Rust 1.99.0:

```powershell
cargo test --locked --jobs 2 --target-dir D:/poiesis-targets/phase-02-memory
cargo fmt --check
cargo clippy --locked --jobs 2 --target-dir D:/poiesis-targets/phase-02-memory --all-targets --all-features -- -D warnings
```

The integrated suite passed 382 tests, failed none, and ignored eight (including
the manual cache profile). Formatting and strict Clippy passed. New regressions
cover dynamic checksum lifetime, cloning, zero retained descriptor allocations,
hot hits and overwrites, retained queue capacity, LRU eviction, retain, empty
entries, zero capacity and generation overflow. Before the fix, 2,048 descriptor
conversions leaked 36,864 measured bytes; afterward they retained zero.

## Memory and CPU tradeoff

A local debug profile used 256 resident integer keys and four-byte values, with
100,000 and 1,000,000 operations. The manual command is:

```powershell
cargo test --locked --lib cache::block_cache::tests::cache_metadata_workload_profile -- --ignored --nocapture
```

At one million operations, the retained recency queue allocation sampled after
operations changed as follows. These measurements exclude temporary old/new
queue overlap during compaction, keys, the entry map and allocator overhead;
they are not peak RSS measurements.

| Workload | Before queue bytes | After queue bytes | Before time | After time |
| --- | ---: | ---: | ---: | ---: |
| Repeated hits | 16,777,216 | 16,384 | 170,125 us | 369,760 us |
| Repeated overwrites | 16,777,216 | 16,384 | 223,198 us | 458,533 us |
| Mixed eviction | 8,388,608 | 16,384 | 172,260 us | 280,622 us |

The bound prevents operation-count-dependent retention, but this implementation
adds CPU and allocation work for periodic compaction. The debug profile is a
correctness and retention probe, not a production throughput benchmark. A
release-mode cache workload and an indexed recency structure remain candidates
for further performance work.
