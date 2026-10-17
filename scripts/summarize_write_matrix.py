#!/usr/bin/env python3
"""Render paired raw matrix samples without treating three repetitions as inference."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics

from parse_write_matrix_strace import read_rows


def grouped(path, measurement):
    groups = defaultdict(list)
    rows = read_rows(path)
    for row in rows:
        if row["measurement"]["measurement"] != measurement:
            raise ValueError("unexpected measurement kind")
        if not row["recovery_verified"]:
            raise ValueError("unverified recovery")
        groups[(row["active_cfs"], row["batch_ops"])].append(row)
    return groups


def distribution(values):
    return f"{statistics.median(values):,.1f} [{min(values):,.1f}, {max(values):,.1f}]"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timing", nargs=2, required=True, metavar=("OLD", "NEW"))
    parser.add_argument("--allocations", nargs=2, metavar=("OLD", "NEW"))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    old, new = [grouped(path, "uninstrumented_timing") for path in args.timing]
    if set(old) != set(new):
        raise ValueError("old/new grids differ")
    expected_grid = {(cfs, ops) for cfs in [1, 16, 256] for ops in [1, 16, 256]}
    if set(old) != expected_grid:
        raise ValueError("reported timing requires the full nine-case grid")
    harnesses = set()
    for group in [old, new]:
        revisions = set()
        for samples in group.values():
            if len(samples) != 3 or {row['repetition'] for row in samples} != {0, 1, 2}:
                raise ValueError("reported timing requires three distinct rotated repetitions")
            for row in samples:
                if (row['batches'], row['warmup_batches'], row['value_bytes']) != (256, 16, 128):
                    raise ValueError("reported timing differs from the declared sample protocol")
                revisions.add(row['source_revision'])
                harnesses.add(row['harness_hash'])
        if len(revisions) != 1:
            raise ValueError("mixed source revisions in one timing control")
    if len(harnesses) != 1 or 'unrecorded' in harnesses:
        raise ValueError("old/new harness hashes must be identical and recorded")
    lines = [
        "# Actual batch / active manifest descriptor matrix", "",
        "Local descriptive samples. Rates and mean batch latency are median [min, max] across rotated repetitions.",
        "This compares aggregate old/new revisions, not one isolated optimization.", "",
        "| Active CFs | Ops/batch | Old batches/s | New batches/s | Old ops/s | New ops/s | Old mean batch µs | New mean batch µs | Median rate ratio |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    latency_lines = [
        "", "| Active CFs | Ops/batch | Old call p50/p95/p99 µs | New call p50/p95/p99 µs |",
        "|---:|---:|---:|---:|",
    ]
    for key in sorted(old):
        rates = []
        means = []
        calls = []
        for groups in [old, new]:
            samples = groups[key]
            if len({row["repetition"] for row in samples}) != len(samples):
                raise ValueError("duplicate repetition")
            rates.append([row["batches"] * 1e9 / row["measurement"]["elapsed_ns"] for row in samples])
            means.append([row["measurement"]["elapsed_ns"] / row["batches"] / 1000 for row in samples])
            calls.append(" / ".join(f"{statistics.median(row['measurement'][f'call_p{p}_ns'] / 1000 for row in samples):,.1f}" for p in [50, 95, 99]))
        cfs, ops = key
        lines.append(f"| {cfs} | {ops} | {distribution(rates[0])} | {distribution(rates[1])} | {distribution([x * ops for x in rates[0]])} | {distribution([x * ops for x in rates[1]])} | {distribution(means[0])} | {distribution(means[1])} | {statistics.median(rates[1]) / statistics.median(rates[0]):.2f}× |")
        latency_lines.append(f"| {cfs} | {ops} | {calls[0]} | {calls[1]} |")
    lines.extend(latency_lines)
    lines += [
        "", "| Active CFs | Ops/batch | Old WAL bytes/batch (per op) | New WAL bytes/batch (per op) | Old app syncs/batch | New app syncs/batch (per op) |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for cfs, ops in sorted(old):
        wal_columns = []
        sync_columns = []
        for group in [old, new]:
            samples = group[(cfs, ops)]
            wal = statistics.median((row['after']['physical_wal_bytes'] - row['before']['physical_wal_bytes']) / row['batches'] for row in samples)
            wal_columns.append(f"{wal:,.1f} ({wal / ops:,.2f})")
            syncs = [row['metric_deltas']['commit_syncs'] for row in samples]
            sync_columns.append("unavailable" if any(x is None for x in syncs) else f"{statistics.median(x / row['batches'] for x, row in zip(syncs, samples)):,.3f}")
        current_syncs = sync_columns[1]
        if current_syncs != "unavailable":
            current_syncs += f" ({float(current_syncs.replace(',', '')) / ops:.6f})"
        lines.append(f"| {cfs} | {ops} | {wal_columns[0]} | {wal_columns[1]} | {sync_columns[0]} | {current_syncs} |")
    if args.allocations:
        groups = [grouped(path, "thread_local_allocation_probe") for path in args.allocations]
        if any(set(group) != set(old) for group in groups):
            raise ValueError("allocation grid differs")
        lines += [
            "", "Allocation probes are separate from timing; requested allocation/reallocation bytes on the submitting thread, not peak memory.", "",
            "| Active CFs | Ops/batch | Old alloc calls/batch | New alloc calls/batch | Old bytes/batch | New bytes/batch |",
            "|---:|---:|---:|---:|---:|---:|",
        ]
        for cfs, ops in sorted(old):
            columns = []
            for field in ["allocation_calls", "allocated_bytes"]:
                for group in groups:
                    columns.append(f"{statistics.median(row['measurement'][field] / row['batches'] for row in group[(cfs, ops)]):,.1f}")
            lines.append(f"| {cfs} | {ops} | " + " | ".join(columns) + " |")
    lines += [
        "", "Full before/after manifest hashes, byte sizes, descriptor counts, WAL byte deltas and optional application counter deltas remain in raw JSONL.",
        "Application sync counters are not total OS sync calls. Separate untimed Linux strace output supplies observed file/directory call evidence.",
    ]
    Path(args.output).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
