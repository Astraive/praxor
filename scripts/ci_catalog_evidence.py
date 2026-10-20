"""Reconcile Cargo test inventories and raw run summaries for the catalog CI gate.

The inputs are combined stdout/stderr logs from one frozen checkout and target.
Each Cargo harness, including explicit zero-test harnesses, needs one list footer
and one matching run result. Ignored inventories come from `--list --ignored`.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


RUNNING = re.compile(r"^\s*Running (.+?) \((.+)\)\s*$")
DOC_TESTS = re.compile(r"^\s*Doc-tests (.+?)\s*$")
ITEM = re.compile(r"^(.+): (test|benchmark)$")
FOOTER = re.compile(r"^\s*(\d+) tests?, (\d+) benchmarks?\s*$")
RESULT = re.compile(
    r"^\s*test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out; "
    r"finished in \d+(?:\.\d+)?s\s*$"
)
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass
class Inventory:
    names: dict[str, str] = field(default_factory=dict)
    tests: int | None = None
    benchmarks: int | None = None

    @property
    def total(self) -> int:
        if self.tests is None or self.benchmarks is None:
            raise ValueError("missing inventory footer")
        return self.tests + self.benchmarks


@dataclass(frozen=True)
class RunResult:
    passed: int
    failed: int
    ignored: int
    measured: int
    filtered: int


def harness_key(line: str) -> str | None:
    running = RUNNING.fullmatch(line)
    if running:
        label, executable = running.groups()
        return f"Running {label} ({executable.replace(chr(92), '/')})"
    docs = DOC_TESTS.fullmatch(line)
    if docs:
        return f"Doc-tests {docs.group(1)}"
    return None


def parse_inventory(raw: str) -> dict[str, Inventory]:
    groups: dict[str, Inventory] = {}
    current: Inventory | None = None
    for original in raw.splitlines():
        line = ANSI.sub("", original).rstrip("\r")
        key = harness_key(line)
        if key is not None:
            if current is not None and current.tests is None:
                raise ValueError("harness has no inventory footer")
            if key in groups:
                raise ValueError(f"duplicate inventory harness: {key}")
            current = groups[key] = Inventory()
            continue
        if current is None:
            continue
        item = ITEM.fullmatch(line)
        if item:
            if current.tests is not None:
                raise ValueError("test name after inventory footer")
            name, kind = item.groups()
            if name in current.names:
                raise ValueError(f"duplicate listed test: {name}")
            current.names[name] = kind
            continue
        footer = FOOTER.fullmatch(line)
        if footer:
            if current.tests is not None:
                raise ValueError("duplicate inventory footer")
            current.tests, current.benchmarks = map(int, footer.groups())
            actual_tests = sum(kind == "test" for kind in current.names.values())
            actual_benchmarks = sum(kind == "benchmark" for kind in current.names.values())
            if (current.tests, current.benchmarks) != (actual_tests, actual_benchmarks):
                raise ValueError("inventory footer does not match named tests/benchmarks")
    if not groups or current is None or current.tests is None:
        raise ValueError("missing or incomplete test inventory")
    return groups


def parse_results(raw: str) -> dict[str, RunResult]:
    groups: dict[str, RunResult] = {}
    pending: list[str] = []
    for original in raw.splitlines():
        line = ANSI.sub("", original).rstrip("\r")
        key = harness_key(line)
        if key is not None:
            if key in groups or key in pending:
                raise ValueError(f"duplicate result harness: {key}")
            pending.append(key)
            continue
        result = RESULT.fullmatch(line)
        if result:
            if not pending:
                raise ValueError("test result has no harness header")
            current = pending.pop(0)
            status, *counts = result.groups()
            parsed = RunResult(*map(int, counts))
            if status != "ok" or parsed.failed != 0:
                raise ValueError(f"failed test result: {current}")
            groups[current] = parsed
            current = None
    if not groups or pending:
        raise ValueError("missing or incomplete test results")
    return groups


def same_groups(expected: dict[str, object], actual: dict[str, object]) -> None:
    if expected.keys() != actual.keys():
        missing = sorted(expected.keys() - actual.keys())
        extra = sorted(actual.keys() - expected.keys())
        raise ValueError(f"harness mismatch: missing={missing}, unexpected={extra}")


def verify_exact(library: dict[str, Inventory], run: dict[str, RunResult], name: str) -> dict:
    if len(library) != 1:
        raise ValueError("exact library inventory must have one harness")
    same_groups(library, run)
    key = next(iter(library))
    listed = library[key]
    if listed.names.get(name) != "test":
        raise ValueError(f"exact test is absent from library inventory: {name}")
    expected = RunResult(1, 0, 0, 0, listed.total - 1)
    if run[key] != expected:
        raise ValueError(f"exact result {run[key]} differs from {expected}")
    return {"mode": "exact", "harness": key, "library_cases": listed.total, "test": name}


def verify_suite(
    listed: dict[str, Inventory],
    ignored: dict[str, Inventory],
    run: dict[str, RunResult],
    *,
    reference: dict[str, Inventory] | None = None,
    prefix: str | None = None,
) -> dict:
    same_groups(listed, ignored)
    same_groups(listed, run)
    if reference is not None:
        same_groups(reference, listed)
    if prefix is not None and len(listed) != 1:
        raise ValueError("focused inventory must have one harness")
    total = passed = ignored_total = filtered_total = 0
    details: list[dict] = []
    for key, inventory in listed.items():
        ignored_inventory = ignored[key]
        if any(
            inventory.names.get(name) != kind
            for name, kind in ignored_inventory.names.items()
        ):
            raise ValueError(f"ignored inventory is not a subset: {key}")
        if prefix is not None and any(not name.startswith(prefix) for name in inventory.names):
            raise ValueError(f"focused inventory includes an unexpected test: {key}")
        if reference is not None and any(
            reference[key].names.get(name) != kind
            for name, kind in inventory.names.items()
        ):
            raise ValueError(f"focused tests are absent from library inventory: {key}")
        expected_filtered = reference[key].total - inventory.total if reference else 0
        expected = RunResult(
            inventory.total - ignored_inventory.total,
            0,
            ignored_inventory.total,
            0,
            expected_filtered,
        )
        if run[key] != expected:
            raise ValueError(f"{key}: result {run[key]} differs from {expected}")
        total += inventory.total
        passed += expected.passed
        ignored_total += expected.ignored
        filtered_total += expected.filtered
        details.append(
            {
                "harness": key,
                "listed_tests": inventory.tests,
                "listed_benchmarks": inventory.benchmarks,
                "passed": expected.passed,
                "ignored": expected.ignored,
                "measured": expected.measured,
                "filtered": expected.filtered,
            }
        )
    if total == 0:
        raise ValueError("suite inventory has no named tests")
    return {
        "mode": "focused" if reference else "full",
        "harnesses": len(details),
        "listed_cases": total,
        "passed": passed,
        "ignored": ignored_total,
        "measured": 0,
        "filtered": filtered_total,
        "groups": details,
    }


def verify_included(full: dict[str, Inventory], focused: dict[str, Inventory]) -> None:
    for key, group in focused.items():
        if key not in full or any(
            full[key].names.get(name) != kind for name, kind in group.names.items()
        ):
            raise ValueError("full inventory omits a focused catalog witness test")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("exact", "focused", "full"))
    parser.add_argument("--list", required=True, type=Path)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--ignored-list", type=Path)
    parser.add_argument("--library-list", type=Path)
    parser.add_argument("--focused-list", type=Path)
    parser.add_argument("--name")
    parser.add_argument("--prefix")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    listed = parse_inventory(args.list.read_text(encoding="utf-8", errors="replace"))
    run = parse_results(args.run.read_text(encoding="utf-8", errors="replace"))
    if args.mode == "exact":
        if not args.name:
            parser.error("exact mode requires --name")
        evidence = verify_exact(listed, run, args.name)
    else:
        if args.ignored_list is None:
            parser.error("suite mode requires --ignored-list")
        ignored = parse_inventory(args.ignored_list.read_text(encoding="utf-8", errors="replace"))
        if args.mode == "focused":
            if args.library_list is None or args.prefix is None:
                parser.error("focused mode requires --library-list and --prefix")
            reference = parse_inventory(args.library_list.read_text(encoding="utf-8", errors="replace"))
            evidence = verify_suite(listed, ignored, run, reference=reference, prefix=args.prefix)
        else:
            evidence = verify_suite(listed, ignored, run)
            if args.focused_list is not None:
                focused = parse_inventory(args.focused_list.read_text(encoding="utf-8", errors="replace"))
                verify_included(listed, focused)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in evidence.items() if key != "groups"}, sort_keys=True))


if __name__ == "__main__":
    main()
