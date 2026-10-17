#!/usr/bin/env python3
"""Count observed syscalls between explicit matrix markers, never infer fsyncs."""
import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


MARKER = re.compile(r"PRAXIS_WRITE_MATRIX_(BEGIN|END) (\S+)\n")
WRITE = re.compile(r'write\(2(?:<[^>]*>)?, ("(?:\\.|[^"\\])*"), \d+\)\s+=\s+(-?\d+)')
SYNC = re.compile(r"\b(fsync|fdatasync)\(\d+<([^>]+)>\)\s+=\s+(-?\d+)")
RENAME = re.compile(r'\b(rename|renameat|renameat2)\(.*"([^"]*MANIFEST)".*\)\s+=\s+(-?\d+)')


def read_rows(path):
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.startswith("{"):
            row = json.loads(line)
            if row.get("benchmark") == "write_amplification_matrix":
                rows.append(row)
    return rows


def parse_trace(text, rows):
    by_id = {row["id"]: row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError("duplicate matrix IDs")
    active = None
    seen = set()
    counts = {}
    marker_buffer = ""
    for line in text.splitlines():
        write = WRITE.search(line)
        if write:
            # write_all emits each ASCII marker in one small write. Buffering also
            # accepts short writes using the actual returned byte count; unrelated
            # JSON/report writes between cases are ignored.
            payload = ast.literal_eval(write.group(1))
            if marker_buffer or payload.startswith("PRAXIS_WRITE_MATRIX_"):
                written = int(write.group(2))
                if written <= 0 or written > len(payload.encode("utf-8")):
                    raise ValueError("failed or truncated marker write")
                marker_buffer += payload.encode("utf-8")[:written].decode("ascii")
            if "\n" in marker_buffer:
                for complete in marker_buffer.splitlines(keepends=True):
                    marker = MARKER.fullmatch(complete)
                    if not marker:
                        continue
                    kind, case_id = marker.groups()
                    if kind == "BEGIN":
                        if active is not None or case_id in seen or case_id not in by_id:
                            raise ValueError("nested, duplicated or unknown BEGIN marker")
                        active = case_id
                        counts[active] = Counter()
                    else:
                        if active != case_id:
                            raise ValueError("END marker does not match active case")
                        seen.add(case_id)
                        active = None
                marker_buffer = marker_buffer.rsplit("\n", 1)[1]
        if active is None:
            continue
        if ("fsync(" in line or "fdatasync(" in line) and not SYNC.search(line):
            raise ValueError(f"unparsed sync in measured region: {line}")
        sync = SYNC.search(line)
        if sync:
            call, path, result = sync.groups()
            root = by_id[active]["data_dir"].rstrip("/")
            if path.endswith(".wal"):
                category = "wal_file"
            elif path == root + "/MANIFEST.tmp":
                category = "manifest_temporary_file"
            elif path == root:
                category = "database_parent_directory"
            elif path == root + "/wal":
                category = "wal_parent_directory"
            else:
                category = "other_path"
            outcome = "success" if int(result) == 0 else "failed"
            counts[active][f"{call}.{category}.{outcome}"] += 1
        rename = RENAME.search(line)
        if rename:
            outcome = "success" if int(rename.group(3)) == 0 else "failed"
            counts[active][f"manifest_rename.{outcome}"] += 1
    if active is not None or seen != set(by_id):
        raise ValueError("missing or unclosed measurement markers")
    return [
        {
            "id": row["id"],
            "label": row["label"],
            "source_revision": row["source_revision"],
            "active_cfs": row["active_cfs"],
            "batch_ops": row["batch_ops"],
            "batches": row["batches"],
            "observed_syscalls": dict(sorted(counts[row["id"]].items())),
        }
        for row in rows
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--rows", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    trace = Path(args.trace).read_bytes()
    results = parse_trace(trace.decode("utf-8"), read_rows(args.rows))
    output = {
        "schema_version": 1,
        "trace_sha256": hashlib.sha256(trace).hexdigest(),
        "scope": "Linux syscalls inside BEGIN/END markers; untimed; not device flushes",
        "cases": results,
    }
    Path(args.output).write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
