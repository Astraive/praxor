"""Run frozen-source feature and benchmark CI commands with per-stage receipts."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

from ci_catalog_stage import StageRecorder, install_termination_handler, sha256_file


FEATURE_SETS = (
    "gpu-cuda",
    "gpu-vulkan",
    "gpu-metal",
    "gpu-wgpu",
    "gpu-cuda,gpu-vulkan,gpu-metal,gpu-wgpu",
)
BENCHMARKS = (
    ("05-accel", "accel_gpu_crc"),
    ("06-graph", "graph_adjacency_traversal"),
    ("07-vector", "vector_ivf_search"),
    ("08-search", "search_inverted_index"),
)
COMMON_STAGES = (
    "00-workflow-provenance",
    "01-aux-selftests",
    "02-rustc-version",
    "03-cargo-version",
    "04-vendor",
)
BENCHMARK_IDS = frozenset(
    (
        "gpu_crc32c_fallback/cuda",
        "gpu_crc32c_fallback/vulkan",
        "gpu_crc32c_fallback/metal",
        "gpu_crc32c_fallback/wgpu",
        "adjacency_one_hop",
        "ivf_exact_search",
        "inverted_term_search",
    )
)
BENCHMARK_STAGE_IDS = {
    "05-accel": (
        "gpu_crc32c_fallback/cuda", "gpu_crc32c_fallback/vulkan",
        "gpu_crc32c_fallback/metal", "gpu_crc32c_fallback/wgpu",
    ),
    "06-graph": ("adjacency_one_hop",),
    "07-vector": ("ivf_exact_search",),
    "08-search": ("inverted_term_search",),
}
ANSI_ESCAPE = re.compile(rb"\x1b\[[0-9;]*m")
COLLECTION = re.compile(r"Benchmarking (?P<benchmark>[A-Za-z0-9_/-]+): Collecting (?P<count>\d+) samples")
BENCHMARK_HEADER = re.compile(r"Benchmarking (?P<benchmark>[A-Za-z0-9_/-]+)$")
NUMBER = r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
UNIT = r"(?:ns|µs|us|ms|s)"
TIMING = re.compile(
    rf"time:\s*\[\s*(?P<low>{NUMBER})\s*(?P<low_unit>{UNIT})\s+"
    rf"(?P<mid>{NUMBER})\s*(?P<mid_unit>{UNIT})\s+"
    rf"(?P<high>{NUMBER})\s*(?P<high_unit>{UNIT})\s*\]"
)
SECONDS_PER_UNIT = {"ns": 1e-9, "µs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0}


def expected_stages(kind: str) -> tuple[str, ...]:
    if kind == "feature":
        return (*COMMON_STAGES, "05-feature-check")
    if kind == "benchmark":
        return (*COMMON_STAGES, *(stage for stage, _ in BENCHMARKS))
    raise ValueError(f"unknown auxiliary gate kind: {kind}")


def feature_check_command(features: str) -> list[str]:
    if features not in FEATURE_SETS:
        raise ValueError(f"unsupported CI feature set: {features}")
    return ["cargo", "check", "--locked", "--jobs", "2", "--benches", "--tests", "--features", features]


def benchmark_command(benchmark: str) -> list[str]:
    if benchmark not in {name for _, name in BENCHMARKS}:
        raise ValueError(f"unsupported CI benchmark: {benchmark}")
    return [
        "cargo", "bench", "--locked", "--jobs", "2", "--bench", benchmark,
        "--", "--sample-size", "10", "--warm-up-time", "1", "--measurement-time", "1",
    ]


def assert_rust_version(path: Path, command: str) -> None:
    raw = path.read_bytes().decode("utf-8", errors="replace")
    first = raw.splitlines()[0] if raw else ""
    if not re.match(rf"^{re.escape(command)} 1\.99\.0(?:\s|$)", first):
        raise RuntimeError(f"expected {command} 1.99.0, received: {first!r}")


def criterion_errors(raw: bytes, target: Path) -> list[dict]:
    """Classify all Criterion ERROR lines; none are allowed by this smoke gate.

    The c2 run showed a missing historical base/sample.json and timing output,
    but did not retain a valid current sample artifact. This gate uses a fresh
    external target and refuses that signature as well as all other errors.
    """
    criterion_root = (target / "criterion").resolve().as_posix()
    known_baseline = re.compile(
        r'^Criterion\.rs ERROR: error: Failed to access file "'
        + re.escape(criterion_root)
        + r'/(?P<benchmark>[^"\r\n]+)/base/sample\.json": '
        + r'No such file or directory \(os error 2\)$'
    )
    findings = []
    for number, line in enumerate(raw.splitlines(), start=1):
        clean = ANSI_ESCAPE.sub(b"", line).decode("utf-8", errors="replace").strip()
        if "Criterion.rs ERROR" not in clean:
            continue
        match = known_baseline.fullmatch(clean)
        category = (
            "missing-historical-baseline-sample"
            if match and match.group("benchmark") in BENCHMARK_IDS
            else "other-criterion-error"
        )
        findings.append({"line": number, "category": category, "message": clean})
    return findings


def benchmark_observations(raw: bytes, expected_ids: tuple[str, ...]) -> dict:
    """Reconcile exact 10-sample IDs and positive, ordered timing intervals."""
    collections: Counter[str] = Counter()
    summaries: dict[str, list[dict]] = {}
    headers: Counter[str] = Counter()
    errors: list[str] = []
    current: str | None = None
    decoded = ANSI_ESCAPE.sub(b"", raw).decode("utf-8", errors="replace")
    for segment in decoded.replace("\r", "\n").splitlines():
        line = segment.strip()
        header = BENCHMARK_HEADER.fullmatch(line)
        if header:
            current = header.group("benchmark")
            headers[current] += 1
        collection = COLLECTION.search(line)
        if collection:
            current = collection.group("benchmark")
            collections[current] += 1
            if int(collection.group("count")) != 10:
                errors.append(f"{current}: expected 10 samples, got {collection.group('count')}")
        if "time:" in line:
            match = TIMING.search(line)
            if match is None:
                errors.append(f"unparseable timing line: {line[:200]}")
                continue
            prefix = line[:match.start()].strip()
            benchmark = prefix if prefix in expected_ids else current
            if benchmark is None:
                errors.append("timing interval has no associated benchmark ID")
                continue
            values = [
                float(match.group(key)) * SECONDS_PER_UNIT[match.group(f"{key}_unit")]
                for key in ("low", "mid", "high")
            ]
            if not all(math.isfinite(value) and value > 0 for value in values) or values != sorted(values):
                errors.append(f"{benchmark}: nonpositive, nonfinite, or unordered timing interval")
            summaries.setdefault(benchmark, []).append({"seconds": values, "line": line})
    required = set(expected_ids)
    if set(headers) != required:
        errors.append(f"benchmark header IDs differ: observed={sorted(headers)} required={sorted(required)}")
    if set(collections) != required:
        errors.append(f"collected IDs differ: observed={sorted(collections)} required={sorted(required)}")
    if set(summaries) != required:
        errors.append(f"timing IDs differ: observed={sorted(summaries)} required={sorted(required)}")
    for benchmark in expected_ids:
        if headers[benchmark] != 1:
            errors.append(f"{benchmark}: expected one benchmark header, got {headers[benchmark]}")
        if collections[benchmark] != 1:
            errors.append(f"{benchmark}: expected one 10-sample collection, got {collections[benchmark]}")
        if len(summaries.get(benchmark, [])) != 1:
            errors.append(f"{benchmark}: expected one timing interval, got {len(summaries.get(benchmark, []))}")
    return {
        "expected_ids": list(expected_ids), "headers": dict(headers),
        "collections": dict(collections), "timings": summaries, "errors": errors,
    }


def persisted_samples(target: Path, expected_ids: tuple[str, ...]) -> dict:
    """Require both current and saved Criterion 0.5.1 samples for each ID."""
    samples: dict[str, dict] = {}
    errors: list[str] = []
    for benchmark in expected_ids:
        pair = {}
        for phase in ("new", "base"):
            path = target / "criterion" / benchmark / phase / "sample.json"
            if not path.is_file():
                errors.append(f"{benchmark}: missing {phase}/sample.json")
                continue
            try:
                raw = path.read_bytes()
                saved = json.loads(raw)
                iters, times = saved["iters"], saved["times"]
                valid = (
                    isinstance(iters, list) and isinstance(times, list)
                    and len(iters) == len(times) == 10
                    and all(
                        type(value) in (int, float) and math.isfinite(value) and value > 0
                        for value in (*iters, *times)
                    )
                )
                if not valid:
                    raise ValueError("expected ten positive finite iteration/time pairs")
                pair[phase] = {"sha256": sha256_file(path), "bytes": len(raw), "pairs": len(iters)}
            except (OSError, ValueError, KeyError, TypeError) as exc:
                errors.append(f"{benchmark}: invalid {phase}/sample.json: {exc}")
        if "new" in pair and "base" in pair and pair["new"]["sha256"] != pair["base"]["sha256"]:
            errors.append(f"{benchmark}: saved base sample differs from current sample")
        samples[benchmark] = pair
    return {"samples": samples, "errors": errors}


def classify_benchmark_log(name: str, log: Path, target: Path, output: Path) -> dict:
    if name not in BENCHMARK_STAGE_IDS:
        raise ValueError(f"unknown benchmark stage: {name}")
    raw = log.read_bytes()
    findings = criterion_errors(raw, target)
    observations = benchmark_observations(raw, BENCHMARK_STAGE_IDS[name])
    samples = persisted_samples(target, BENCHMARK_STAGE_IDS[name])
    result = {
        "stage": name,
        "raw_log_sha256": sha256_file(log),
        "raw_log_bytes": len(raw),
        "criterion_error_policy": "reject every Criterion.rs ERROR until current sample and baseline evidence is reviewed",
        "criterion_errors": findings,
        "observations": observations,
        "persisted_samples": samples,
        "passed": not (findings or observations["errors"] or samples["errors"]),
    }
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return result


def declared_root(kind: str, environment: dict[str, str]) -> Path:
    if kind == "feature":
        features = environment["PRAXOR_CI_FEATURES"]
        if features not in FEATURE_SETS:
            raise RuntimeError(f"unsupported CI feature set: {features}")
        label = f"p80-feature-{features}"
    elif kind == "benchmark":
        label = "p80-bench"
    else:
        raise ValueError(f"unknown auxiliary gate kind: {kind}")
    root = Path(environment["RUNNER_TEMP"]) / (
        f"{label}-{environment['GITHUB_RUN_ID']}-{environment['GITHUB_RUN_ATTEMPT']}"
    )
    target = str((root / "target").resolve())
    fixtures = str((root / "fixtures").resolve())
    if str(Path(environment["CARGO_TARGET_DIR"]).resolve()) != target:
        raise RuntimeError("CARGO_TARGET_DIR differs from declared external target")
    if str(Path(environment["PRAXOR_TEST_TMP_ROOT"]).resolve()) != fixtures:
        raise RuntimeError("PRAXOR_TEST_TMP_ROOT differs from declared external fixtures")
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("feature", "benchmark"), required=True)
    args = parser.parse_args()
    if os.name == "nt":
        parser.error("auxiliary gate jobs are native Linux jobs")
    install_termination_handler()

    repo = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    if environment.get("CARGO_BUILD_JOBS") != "2":
        raise RuntimeError("CARGO_BUILD_JOBS must equal 2")
    expected = environment["EXPECTED_HEAD"]
    root = declared_root(args.kind, environment)
    if root.resolve().is_relative_to(repo.resolve()):
        raise RuntimeError("generated artifact root must be outside tracked checkout")
    for path in (root / "target", root / "fixtures", root / "tmp"):
        path.mkdir(parents=True, exist_ok=True)
    environment.update(
        TEMP=str((root / "tmp").resolve()),
        TMP=str((root / "tmp").resolve()),
        TMPDIR=str((root / "tmp").resolve()),
        PYTHONDONTWRITEBYTECODE="1",
    )
    if args.kind == "benchmark":
        environment["CRITERION_HOME"] = str((root / "target" / "criterion").resolve())

    gate = StageRecorder(repo, root, expected, environment, "linux")
    gate.run(
        "00-workflow-provenance",
        [sys.executable, "scripts/ci_catalog_stage.py", "--verify-workflow", expected],
        initial=True,
    )
    gate.run(
        "01-aux-selftests",
        [sys.executable, "-m", "unittest", "-v", "scripts.test_ci_catalog_aux_gate"],
        initial=True,
    )
    assert_rust_version(gate.run("02-rustc-version", ["rustc", "--version", "--verbose"]), "rustc")
    assert_rust_version(gate.run("03-cargo-version", ["cargo", "--version"]), "cargo")
    vendor = [sys.executable, "scripts/verify_zstd_vendor.py"]
    if args.kind == "feature":
        features = environment["PRAXOR_CI_FEATURES"]
        vendor.extend(("--features", features))
    gate.run("04-vendor", vendor)

    if args.kind == "feature":
        features = environment["PRAXOR_CI_FEATURES"]
        gate.run("05-feature-check", feature_check_command(features))
        result = {"kind": args.kind, "features": features, "fixed_feature_sets": list(FEATURE_SETS)}
    else:
        classified = []
        for stage, benchmark in BENCHMARKS:
            log = gate.logs / f"{stage}.raw.log"
            classification_path = gate.logs / f"{stage}.criterion.json"
            try:
                gate.run(stage, benchmark_command(benchmark))
            except BaseException:
                if log.is_file():
                    classify_benchmark_log(stage, log, root / "target", classification_path)
                raise
            classification = classify_benchmark_log(stage, log, root / "target", classification_path)
            classified.append(classification)
            if not classification["passed"]:
                raise RuntimeError(
                    f"{stage} benchmark evidence failed strict output/sample checks; "
                    "see the raw stage receipt and classification artifact"
                )
        result = {
            "kind": args.kind,
            "benchmarks": [name for _, name in BENCHMARKS],
            "fixed_benchmark_ids": {key: list(value) for key, value in BENCHMARK_STAGE_IDS.items()},
            "criterion": classified,
        }

    gate.finish(
        {
            "head": expected,
            "tree": gate.baseline["tree"],
            "stages": gate.stages,
            "qualification": "requires independent current-head raw-artifact review",
            **result,
        },
        expected_stages=expected_stages(args.kind),
    )


if __name__ == "__main__":
    main()
