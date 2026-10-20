"""Fail-closed tracked-source and generated-root check for hosted benchmarks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from ci_catalog_stage import (
    MAX_LOCK_DIFF_BYTES, cargo_lock_diff, raw_file_evidence, sha256_file,
    snapshot_cargo_lock, tracked_manifest, utc_now,
)


def git_lines(repo: Path, *args: str) -> list[str]:
    raw = subprocess.check_output(["git", *args, "-z"], cwd=repo)
    return [os.fsdecode(item) for item in raw.split(b"\0") if item]


def diagnostics(repo: Path, artifact_root: Path, label: str) -> dict:
    result = {
        "cargo_lock_raw": snapshot_cargo_lock(
            repo, artifact_root / f"cargo-lock-working.{label}.raw",
        ),
        "pretoolchain_cargo_lock_raw": raw_file_evidence(
            artifact_root / "logs" / "setup-pretoolchain.Cargo.lock.raw"
        ),
        "porcelain": git_lines(repo, "status", "--porcelain", "--untracked-files=all"),
        "unstaged_name_status": git_lines(repo, "diff", "--name-status"),
        "staged_name_status": git_lines(repo, "diff", "--cached", "--name-status"),
        "untracked_paths": git_lines(repo, "ls-files", "--others", "--exclude-standard"),
        "ignored_untracked_paths": git_lines(
            repo, "ls-files", "--others", "--ignored", "--exclude-standard"
        ),
        "cargo_lock_unstaged_diff": cargo_lock_diff(
            repo, staged=False, artifact=artifact_root / f"cargo-lock-unstaged.{label}.patch",
        ),
        "cargo_lock_staged_diff": cargo_lock_diff(
            repo, staged=True, artifact=artifact_root / f"cargo-lock-staged.{label}.patch",
        ),
    }
    print("Source boundary diagnostics: " + json.dumps(result, sort_keys=True), flush=True)
    return result


def generated_roots(repo: Path, paths: list[str]) -> list[str]:
    roots = sorted({str(Path(path).resolve()) for path in paths})
    if not roots:
        raise RuntimeError("generated artifact roots must be declared")
    for root in roots:
        if Path(root).is_relative_to(repo):
            raise RuntimeError(f"generated artifact root must be outside tracked checkout: {root}")
    return roots


def collect(repo: Path, expected_head: str, roots: list[str], artifact_root: Path, label: str) -> dict:
    diagnostic = diagnostics(repo, artifact_root, label)
    # The complete Cargo.lock patches are already on disk before strict manifest validation.
    snapshot = {
        "utc": utc_now(),
        "expected_head": expected_head,
        "generated_artifact_roots": roots,
        "cargo_lock_sha256": sha256_file(repo / "Cargo.lock"),
        "diagnostics": diagnostic,
    }
    try:
        if snapshot["cargo_lock_sha256"] != diagnostic["cargo_lock_raw"]["sha256"]:
            raise RuntimeError("Cargo.lock changed while collecting benchmark raw snapshot")
        manifest = tracked_manifest(repo)
        lock_files = [entry for entry in manifest["files"] if entry["path"] == "Cargo.lock"]
        if len(lock_files) != 1:
            raise RuntimeError("Cargo.lock missing from tracked manifest")
        if lock_files[0]["sha256"] != snapshot["cargo_lock_sha256"]:
            raise RuntimeError("Cargo.lock changed during benchmark source boundary")
        snapshot["manifest"] = manifest
    except BaseException as exc:
        snapshot["manifest"] = None
        snapshot["manifest_error"] = str(exc) or type(exc).__name__
    return snapshot


def check(before: dict | None, after: dict) -> list[str]:
    errors = []
    if after.get("collection_error"):
        errors.append("source evidence collection failed: " + after["collection_error"])
    current = after.get("manifest")
    if current is None:
        errors.append("strict tracked manifest failed: " + after.get("manifest_error", "missing manifest"))
    elif current["head"] != after["expected_head"]:
        errors.append("HEAD differs from exact event head")
    diagnostic = after.get("diagnostics") or {}
    if not {"unstaged_name_status", "staged_name_status", "untracked_paths", "ignored_untracked_paths", "porcelain"} <= diagnostic.keys():
        errors.append("source diagnostics are missing required path inventories")
    if diagnostic.get("porcelain"):
        errors.append("tracked or untracked Git porcelain status is nonempty")
    if current is not None and current.get("tracked_status"):
        errors.append("strict manifest tracked Git status is nonempty")
    if diagnostic.get("unstaged_name_status") or diagnostic.get("staged_name_status"):
        errors.append("tracked Git diff is nonempty")
    if diagnostic.get("untracked_paths"):
        errors.append("undeclared untracked paths appeared inside checkout")
    if diagnostic.get("ignored_untracked_paths"):
        errors.append("ignored untracked paths appeared inside checkout")
    raw_artifacts = [
        ("current", diagnostic.get("cargo_lock_raw")),
        ("pretoolchain", diagnostic.get("pretoolchain_cargo_lock_raw")),
    ]
    if before is not None:
        prior_diagnostic = before.get("diagnostics") or {}
        raw_artifacts.extend((
            ("baseline", prior_diagnostic.get("cargo_lock_raw")),
            ("baseline pretoolchain", prior_diagnostic.get("pretoolchain_cargo_lock_raw")),
        ))
    for label, evidence in raw_artifacts:
        if not isinstance(evidence, dict):
            errors.append(f"{label} raw Cargo.lock evidence missing")
            continue
        try:
            if evidence != raw_file_evidence(Path(evidence["artifact"])):
                errors.append(f"{label} raw Cargo.lock artifact changed")
        except (KeyError, OSError, RuntimeError, ValueError) as exc:
            errors.append(f"{label} raw Cargo.lock artifact unavailable: {exc}")
    current_raw = diagnostic.get("cargo_lock_raw")
    pretoolchain_raw = diagnostic.get("pretoolchain_cargo_lock_raw")
    if isinstance(current_raw, dict) and isinstance(pretoolchain_raw, dict):
        if (current_raw["sha256"], current_raw["bytes"]) != (
            pretoolchain_raw["sha256"], pretoolchain_raw["bytes"]
        ):
            errors.append("Cargo.lock raw bytes changed since pretoolchain setup")
    if isinstance(current_raw, dict) and after.get("cargo_lock_sha256") != current_raw["sha256"]:
        errors.append("working Cargo.lock hash differs from saved raw snapshot")
    if before is not None:
        prior = before.get("manifest")
        if prior is None:
            errors.append("baseline strict tracked manifest failed")
        if before["expected_head"] != after["expected_head"]:
            errors.append("expected head changed between boundaries")
        if before["generated_artifact_roots"] != after["generated_artifact_roots"]:
            errors.append("declared generated roots changed between boundaries")
        if prior is not None and current is not None:
            if prior["head"] != current["head"] or prior["tree"] != current["tree"]:
                errors.append("Git commit/tree changed between boundaries")
            if prior["files_sha256"] != current["files_sha256"]:
                errors.append("tracked checkout bytes changed between boundaries")
            if prior.get("git_conversion_config") != current.get("git_conversion_config"):
                errors.append("Git EOL conversion configuration changed between boundaries")
        if before.get("cargo_lock_sha256") != after.get("cargo_lock_sha256"):
            errors.append("Cargo.lock bytes changed between boundaries")
        prior_raw = (before.get("diagnostics") or {}).get("cargo_lock_raw")
        if isinstance(prior_raw, dict) and isinstance(current_raw, dict):
            if (prior_raw["sha256"], prior_raw["bytes"]) != (current_raw["sha256"], current_raw["bytes"]):
                errors.append("Cargo.lock raw artifacts differ between benchmark boundaries")
        else:
            errors.append("benchmark raw Cargo.lock snapshot missing at a boundary")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("snapshot", "verify"))
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--generated-root", action="append", required=True)
    args = parser.parse_args()
    if (args.mode == "verify") != (args.baseline is not None):
        parser.error("--baseline is required only for verify")
    repo = Path(__file__).resolve().parents[1]
    roots = generated_roots(repo, args.generated_root)
    if args.output.resolve().is_relative_to(repo):
        raise RuntimeError("source check artifacts must be outside tracked checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        after = collect(repo, args.expected_head, roots, args.output.parent, args.mode)
    except BaseException as exc:
        after = {
            "utc": utc_now(), "expected_head": args.expected_head,
            "generated_artifact_roots": roots,
            "manifest": None,
            "collection_error": str(exc) or type(exc).__name__,
        }
    args.output.write_text(json.dumps(after, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    before = None
    missing_baseline = args.baseline is not None and not args.baseline.is_file()
    baseline_error = None
    if args.baseline and not missing_baseline:
        try:
            before = json.loads(args.baseline.read_text(encoding="utf-8"))
            if not isinstance(before, dict):
                raise ValueError("benchmark baseline must be a JSON object")
        except BaseException as exc:
            baseline_error = str(exc) or type(exc).__name__
    errors = check(before, after)
    if missing_baseline:
        errors.append("benchmark baseline snapshot missing; no before/after comparison possible")
    if baseline_error:
        errors.append("benchmark baseline snapshot cannot be read: " + baseline_error)
    if errors:
        for error in errors:
            print(f"SOURCE CHECK FAILED: {error}", file=sys.stderr)
        return 1
    print(f"Tracked source and declared generated roots verified at {args.expected_head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
