"""Run the same frozen-source catalog gate on hosted Windows or native Linux."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from ci_catalog_evidence import (
    parse_inventory,
    parse_results,
    verify_exact,
    verify_included,
    verify_suite,
)
from ci_catalog_stage import StageRecorder, install_termination_handler, sha256_file


NATIVE = (
    "core_catalog::segment_witness_tests::"
    "bounded_zstd_native_workspace_is_aligned_and_refused_before_output_reserve"
)
JUNCTION = (
    "core_catalog::segment_witness_tests::"
    "segment_level_junction_refuses_without_following_parked_directory"
)
FOCUSED = "core_catalog::segment_witness_tests::"
COMMON_STAGES = (
    "00-workflow-provenance", "00-parser-selftests", "01-rustc-version",
    "02-cargo-version", "03-pwsh-version", "04-vendor", "05-format",
    "06-check", "07-clippy", "08-lib-list", "09-native",
)
TAIL_STAGES = (
    "11-focused-list", "12-focused-ignored-list", "13-focused-run",
    "14-full-list", "15-full-ignored-list", "16-full-run",
    "17-storage-slog", "18-storage-boundary",
)


def assert_rust_version(path: Path, command: str) -> None:
    raw = path.read_bytes().decode("utf-8", errors="replace")
    first = raw.splitlines()[0] if raw else ""
    if not re.match(rf"^{re.escape(command)} 1\.99\.0(?:\s|$)", first):
        raise RuntimeError(f"expected {command} 1.99.0, received: {first!r}")


def main() -> None:
    install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "linux"), required=True)
    args = parser.parse_args()
    if (args.platform == "windows") != (os.name == "nt"):
        parser.error("requested platform differs from runner OS")

    repo = Path(__file__).resolve().parents[1]
    expected = os.environ["EXPECTED_HEAD"]
    root = Path(os.environ["RUNNER_TEMP"]) / (
        f"p80-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    )
    target, fixtures, temp = root / "t", root / "f", root / "tmp"
    if args.platform == "windows" and max(len(str(path)) for path in (root, target, fixtures, temp)) > 100:
        raise RuntimeError("Windows target/fixture root exceeds the 100-character admission budget")
    for path in (target, fixtures, temp):
        path.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        CARGO_TARGET_DIR=str(target.resolve()),
        PRAXOR_TEST_TMP_ROOT=str(fixtures.resolve()),
        TEMP=str(temp.resolve()),
        TMP=str(temp.resolve()),
        TMPDIR=str(temp.resolve()),
    )
    if environment.get("CARGO_BUILD_JOBS") != "2":
        raise RuntimeError("CARGO_BUILD_JOBS must be 2")
    if args.platform == "windows":
        for key, value in {
            "CARGO_INCREMENTAL": "0",
            "CARGO_PROFILE_DEV_DEBUG": "0",
            "CARGO_PROFILE_TEST_DEBUG": "0",
        }.items():
            if environment.get(key) != value:
                raise RuntimeError(f"Windows {key} must equal {value}")

    gate = StageRecorder(repo, root, expected, environment, args.platform)

    def run(name: str, *argv: str, initial: bool = False) -> Path:
        return gate.run(name, list(argv), initial=initial)

    def inventory(path: Path) -> dict:
        return parse_inventory(path.read_text(encoding="utf-8", errors="replace"))

    def results(path: Path) -> dict:
        return parse_results(path.read_text(encoding="utf-8", errors="replace"))

    def evidence(name: str, value: dict, raw_inputs: list[Path]) -> dict:
        value = {
            **value,
            "head": expected,
            "source_manifest_sha256": gate.baseline["files_sha256"],
            "raw_inputs_sha256": {path.name: sha256_file(path) for path in raw_inputs},
        }
        path = gate.logs / f"{name}.evidence.json"
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(f"Evidence {name}: {path}", flush=True)
        return value

    run("00-workflow-provenance", "python", "scripts/ci_catalog_stage.py", "--verify-workflow", expected, initial=True)
    run(
        "00-parser-selftests", "python", "-m", "unittest", "-v",
        "scripts.test_ci_catalog_evidence", "scripts.test_ci_catalog_stage",
        "scripts.test_ci_catalog_aux_gate", initial=True,
    )
    assert_rust_version(run("01-rustc-version", "rustc", "--version", "--verbose"), "rustc")
    assert_rust_version(run("02-cargo-version", "cargo", "--version"), "cargo")
    run("03-pwsh-version", "pwsh", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()")
    run("04-vendor", "python", "scripts/verify_zstd_vendor.py")
    run("05-format", "cargo", "fmt", "--check")
    run("06-check", "cargo", "check", "--locked", "--jobs", "2", "--benches", "--tests")
    run("07-clippy", "cargo", "clippy", "--locked", "--jobs", "2", "--all-targets", "--", "-D", "warnings")

    library_path = run("08-lib-list", "cargo", "test", "--locked", "--jobs", "2", "--lib", "--", "--list")
    library = inventory(library_path)
    native_path = run(
        "09-native", "cargo", "test", "--locked", "--jobs", "2", "--lib", NATIVE,
        "--", "--exact", "--nocapture", "--test-threads", "1",
    )
    native = evidence("native", verify_exact(library, results(native_path), NATIVE), [library_path, native_path])
    junction = None
    if args.platform == "windows":
        junction_path = run(
            "10-junction", "cargo", "test", "--locked", "--jobs", "2", "--lib", JUNCTION,
            "--", "--exact", "--nocapture", "--test-threads", "1",
        )
        junction = evidence(
            "junction", verify_exact(library, results(junction_path), JUNCTION),
            [library_path, junction_path],
        )

    focused_path = run(
        "11-focused-list", "cargo", "test", "--locked", "--jobs", "2", "--lib",
        FOCUSED, "--", "--list",
    )
    focused_ignored_path = run(
        "12-focused-ignored-list", "cargo", "test", "--locked", "--jobs", "2",
        "--lib", FOCUSED, "--", "--list", "--ignored",
    )
    focused_run_path = run(
        "13-focused-run", "cargo", "test", "--locked", "--jobs", "2", "--lib",
        FOCUSED, "--", "--test-threads", "2",
    )
    focused_inventory = inventory(focused_path)
    focused = evidence(
        "focused",
        verify_suite(
            focused_inventory, inventory(focused_ignored_path), results(focused_run_path),
            reference=library, prefix=FOCUSED,
        ),
        [library_path, focused_path, focused_ignored_path, focused_run_path],
    )

    full_path = run("14-full-list", "cargo", "test", "--locked", "--jobs", "2", "--all", "--", "--list")
    full_ignored_path = run(
        "15-full-ignored-list", "cargo", "test", "--locked", "--jobs", "2", "--all",
        "--", "--list", "--ignored",
    )
    full_run_path = run(
        "16-full-run", "cargo", "test", "--locked", "--jobs", "2", "--all",
        "--", "--test-threads", "2",
    )
    full_inventory = inventory(full_path)
    verify_included(full_inventory, focused_inventory)
    full = evidence(
        "full", verify_suite(full_inventory, inventory(full_ignored_path), results(full_run_path)),
        [full_path, full_ignored_path, full_run_path, focused_path],
    )
    run("17-storage-slog", "pwsh", "-NoProfile", "-File", "scripts/verify_slog_storage.ps1")
    run("18-storage-boundary", "pwsh", "-NoProfile", "-File", "scripts/verify_storage_boundary.ps1")

    expected_evidence = ["native.evidence.json", "focused.evidence.json", "full.evidence.json"]
    if args.platform == "windows":
        expected_evidence.append("junction.evidence.json")
    for name in expected_evidence:
        if not (gate.logs / name).is_file():
            raise RuntimeError(f"missing required parsed evidence: {name}")
    gate.finish(
        {
            "head": expected,
            "tree": gate.baseline["tree"],
            "platform": args.platform,
            "stages": gate.stages,
            "native": native,
            "junction": junction,
            "focused": {key: value for key, value in focused.items() if key != "groups"},
            "full": {key: value for key, value in full.items() if key != "groups"},
            "qualification": "requires independent raw-artifact and current-head CI review",
        },
        expected_stages=COMMON_STAGES + (("10-junction",) if args.platform == "windows" else ()) + TAIL_STAGES,
    )


if __name__ == "__main__":
    main()
