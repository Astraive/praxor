"""Run the frozen-head catalog platform gate on a fresh Windows CI runner.

Each command keeps a raw combined-output log. The workflow uploads those logs even
when a stage fails, so a green job alone is never the only evidence for this gate.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ci_catalog_evidence import (
    parse_inventory,
    parse_results,
    verify_exact,
    verify_included,
    verify_suite,
)


GIB = 1024**3
NATIVE = (
    "core_catalog::segment_witness_tests::"
    "bounded_zstd_native_workspace_is_aligned_and_refused_before_output_reserve"
)
JUNCTION = (
    "core_catalog::segment_witness_tests::"
    "segment_level_junction_refuses_without_following_parked_directory"
)
FOCUSED = "core_catalog::segment_witness_tests::"


class MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ulong),
        ("load", ctypes.c_ulong),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page", ctypes.c_ulonglong),
        ("available_page", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


def memory_status() -> MemoryStatus:
    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise OSError("GlobalMemoryStatusEx failed")
    return status


def main() -> None:
    if os.name != "nt":
        raise RuntimeError("This platform gate must run on Windows")

    repo = Path(__file__).resolve().parents[1]
    expected = os.environ["EXPECTED_HEAD"]
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True
    ).strip()
    if actual != expected:
        raise RuntimeError(f"checkout head {actual} differs from event head {expected}")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=repo):
        raise RuntimeError("checkout has preexisting changes")

    for key, value in {
        "CARGO_BUILD_JOBS": "2",
        "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_DEV_DEBUG": "0",
        "CARGO_PROFILE_TEST_DEBUG": "0",
    }.items():
        if os.environ.get(key) != value:
            raise RuntimeError(f"{key} must equal {value}")

    root = Path(os.environ["RUNNER_TEMP"]) / (
        f"p80-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    )
    target = root / "t"
    fixtures = root / "f"
    temp = root / "tmp"
    logs = root / "logs"
    if max(len(str(path)) for path in (root, target, fixtures, temp)) > 100:
        raise RuntimeError("Windows CI target/fixture root exceeds the 100-character path budget")
    for path in (target, fixtures, temp, logs):
        path.mkdir(parents=True, exist_ok=True)

    environment = os.environ.copy()
    environment.update(
        CARGO_TARGET_DIR=str(target),
        PRAXOR_TEST_TMP_ROOT=str(fixtures),
        TEMP=str(temp),
        TMP=str(temp),
    )
    (logs / "head.json").write_text(
        json.dumps(
            {
                "head": actual,
                "tree": tree,
                "target": str(target),
                "fixture_root": str(fixtures),
                "temp": str(temp),
                "fixture_root_characters": len(str(fixtures)),
                "cargo_incremental": environment["CARGO_INCREMENTAL"],
                "profile_dev_debug": environment["CARGO_PROFILE_DEV_DEBUG"],
                "profile_test_debug": environment["CARGO_PROFILE_TEST_DEBUG"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Frozen head: {actual}, tree: {tree}", flush=True)
    print(f"Target: {target}; fixture root: {fixtures}", flush=True)

    def resources(stage: str, *, initial: bool = False) -> None:
        disk = shutil.disk_usage(root)
        memory = memory_status()
        event = {
            "stage": stage,
            "disk_total_bytes": disk.total,
            "disk_free_bytes": disk.free,
            "ram_total_bytes": memory.total_physical,
            "ram_available_bytes": memory.available_physical,
        }
        with (logs / "resources.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps(event) + "\n")
        print(f"Resources {stage}: {event}", flush=True)
        disk_floor = 8 * GIB if initial else 2 * GIB
        memory_floor = 2 * GIB if initial else 1 * GIB
        if disk.free < disk_floor or memory.available_physical < memory_floor:
            raise RuntimeError(
                f"{stage}: free disk/RAM below {disk_floor}/{memory_floor} bytes"
            )

    def run(name: str, *command: str) -> Path:
        resources(f"before {name}")
        log_path = logs / f"{name}.log"
        print(f"Stage {name}: {' '.join(command)}", flush=True)
        with log_path.open("wb") as raw:
            process = subprocess.Popen(
                command,
                cwd=repo,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            assert process.stdout is not None
            while chunk := process.stdout.read1(65536):
                raw.write(chunk)
                raw.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            code = process.wait()
        resource_error = None
        try:
            resources(f"after {name}")
        except Exception as error:
            resource_error = str(error)
        if code or resource_error:
            raise RuntimeError(
                f"{name}: exit={code}, resource_guard={resource_error}; see {log_path}"
            )
        return log_path

    def output(path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    def evidence(name: str, value: dict) -> None:
        (logs / f"{name}-evidence.json").write_text(
            json.dumps(value, indent=2) + "\n", encoding="utf-8"
        )
        print(f"{name} evidence: {json.dumps({k: v for k, v in value.items() if k != 'groups'})}", flush=True)

    resources("initial", initial=True)
    run("00-parser-selftests", "python", "-m", "unittest", "-v", "scripts.test_ci_catalog_evidence")
    run("01-vendor", "python", "scripts/verify_zstd_vendor.py")
    run("02-format", "cargo", "fmt", "--check")
    run("03-check", "cargo", "check", "--locked", "--jobs", "2", "--benches", "--tests")
    run(
        "04-clippy",
        "cargo",
        "clippy",
        "--locked",
        "--jobs",
        "2",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    )
    library = run("05-lib-list", "cargo", "test", "--locked", "--jobs", "2", "--lib", "--", "--list")
    library_inventory = parse_inventory(output(library))
    for index, name in (("06-native", NATIVE), ("07-junction", JUNCTION)):
        passed = run(
            index,
            "cargo",
            "test",
            "--locked",
            "--jobs",
            "2",
            "--lib",
            name,
            "--",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
        )
        evidence(index, verify_exact(library_inventory, parse_results(output(passed)), name))

    focused_list = run(
        "08-focused-list",
        "cargo",
        "test",
        "--locked",
        "--jobs",
        "2",
        "--lib",
        FOCUSED,
        "--",
        "--list",
    )
    focused_ignored = run(
        "09-focused-ignored-list",
        "cargo", "test", "--locked", "--jobs", "2", "--lib", FOCUSED,
        "--", "--list", "--ignored",
    )
    focused_run = run(
        "10-focused-run",
        "cargo",
        "test",
        "--locked",
        "--jobs",
        "2",
        "--lib",
        FOCUSED,
        "--",
        "--test-threads",
        "2",
    )
    focused_inventory = parse_inventory(output(focused_list))
    focused_evidence = verify_suite(
        focused_inventory,
        parse_inventory(output(focused_ignored)),
        parse_results(output(focused_run)),
        reference=library_inventory,
        prefix=FOCUSED,
    )
    evidence("focused", focused_evidence)

    full_list = run("11-full-list", "cargo", "test", "--locked", "--jobs", "2", "--all", "--", "--list")
    full_ignored = run(
        "12-full-ignored-list",
        "cargo", "test", "--locked", "--jobs", "2", "--all", "--", "--list", "--ignored",
    )
    full_run = run(
        "13-full-run",
        "cargo",
        "test",
        "--locked",
        "--jobs",
        "2",
        "--all",
        "--",
        "--test-threads",
        "2",
    )
    full_inventory = parse_inventory(output(full_list))
    verify_included(full_inventory, focused_inventory)
    full_evidence = verify_suite(
        full_inventory,
        parse_inventory(output(full_ignored)),
        parse_results(output(full_run)),
    )
    evidence("full", full_evidence)
    run("14-slog", "pwsh", "-NoProfile", "-File", "scripts/verify_slog_storage.ps1")
    run("15-storage-boundary", "pwsh", "-NoProfile", "-File", "scripts/verify_storage_boundary.ps1")

    final_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    final_status = subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True)
    if final_head != expected or final_status:
        raise RuntimeError(f"source changed during platform gate: {final_head}, {final_status!r}")
    (logs / "result.json").write_text(
        json.dumps(
            {
                "head": final_head,
                "tree": tree,
                "focused_cases": focused_evidence["listed_cases"],
                "full_harnesses": full_evidence["harnesses"],
                "full_cases": full_evidence["listed_cases"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    required = [
        "head.json", "resources.jsonl", "05-lib-list.log", "06-native.log",
        "07-junction.log", "08-focused-list.log", "09-focused-ignored-list.log",
        "10-focused-run.log", "11-full-list.log", "12-full-ignored-list.log",
        "13-full-run.log", "14-slog.log", "15-storage-boundary.log",
        "06-native-evidence.json", "07-junction-evidence.json",
        "focused-evidence.json", "full-evidence.json", "result.json",
    ]
    missing = [name for name in required if not (logs / name).is_file() or not (logs / name).stat().st_size]
    if missing:
        raise RuntimeError(f"Windows platform evidence files missing or empty: {missing}")
    print(f"Windows platform gate passed at frozen head {final_head}", flush=True)


if __name__ == "__main__":
    main()
