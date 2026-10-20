"""Synthetic contract checks for hosted auxiliary command evidence."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ci_catalog_aux_gate import (  # noqa: E402
    BENCHMARKS,
    FEATURE_SETS,
    assert_rust_version,
    benchmark_command,
    benchmark_observations,
    classify_benchmark_log,
    criterion_errors,
    declared_root,
    expected_stages,
    feature_check_command,
    persisted_samples,
)


class AuxiliaryGateTests(unittest.TestCase):
    def test_all_five_feature_sets_have_locked_two_job_checks(self) -> None:
        self.assertEqual(len(FEATURE_SETS), 5)
        for features in FEATURE_SETS:
            self.assertEqual(
                feature_check_command(features),
                ["cargo", "check", "--locked", "--jobs", "2", "--benches", "--tests", "--features", features],
            )
        with self.assertRaisesRegex(ValueError, "unsupported CI feature set"):
            feature_check_command("gpu-cuda; echo unexpected")
        self.assertEqual(expected_stages("feature")[-1], "05-feature-check")

    def test_all_four_benchmark_commands_preserve_smoke_arguments(self) -> None:
        self.assertEqual(len(BENCHMARKS), 4)
        for stage, benchmark in BENCHMARKS:
            self.assertIn(stage, expected_stages("benchmark"))
            self.assertEqual(
                benchmark_command(benchmark),
                [
                    "cargo", "bench", "--locked", "--jobs", "2", "--bench", benchmark,
                    "--", "--sample-size", "10", "--warm-up-time", "1", "--measurement-time", "1",
                ],
            )
        with self.assertRaisesRegex(ValueError, "unsupported CI benchmark"):
            benchmark_command("unexpected")

    def test_historical_baseline_error_is_classified_but_never_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            historical = (
                'Criterion.rs ERROR: error: Failed to access file "'
                f'{(target / "criterion" / "ivf_exact_search" / "base" / "sample.json").resolve().as_posix()}"'
                ': No such file or directory (os error 2)'
            )
            raw = ("\x1b[31m" + historical + "\x1b[0m\n" + "time: [1 ns 2 ns 3 ns]\n").encode()
            findings = criterion_errors(raw, target)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "missing-historical-baseline-sample")
            with tempfile.TemporaryDirectory() as logs:
                log = Path(logs) / "benchmark.raw.log"
                output = Path(logs) / "benchmark.criterion.json"
                log.write_bytes(raw)
                result = classify_benchmark_log("07-vector", log, target, output)
                self.assertFalse(result["passed"])
                self.assertEqual(result["raw_log_sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(json.loads(output.read_text(encoding="utf-8")), result)

    def test_unexpected_criterion_error_is_failed_and_clean_log_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            findings = criterion_errors(b"Criterion.rs ERROR: unexpected write failure\n", target)
            self.assertEqual(findings[0]["category"], "other-criterion-error")
            self.assertEqual(criterion_errors(b"Collecting 10 samples\ntime: [1 ns 2 ns 3 ns]\n", target), [])

    def test_valid_exact_id_timing_and_saved_samples_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            sample = json.dumps({"sampling_mode": "Flat", "iters": list(range(1, 11)), "times": list(range(11, 21))})
            for phase in ("new", "base"):
                path = target / "criterion" / "ivf_exact_search" / phase / "sample.json"
                path.parent.mkdir(parents=True)
                path.write_text(sample, encoding="utf-8")
            raw = (
                b"Benchmarking ivf_exact_search\n"
                b"Benchmarking ivf_exact_search: Collecting 10 samples in estimated 1.0 s\n"
                b"ivf_exact_search time: [1 ns 2 ns 3 ns]\n"
            )
            log = root / "vector.raw.log"
            output = root / "vector.criterion.json"
            log.write_bytes(raw)
            self.assertEqual(benchmark_observations(raw, ("ivf_exact_search",))["errors"], [])
            self.assertEqual(persisted_samples(target, ("ivf_exact_search",))["errors"], [])
            result = classify_benchmark_log("07-vector", log, target, output)
            self.assertTrue(result["passed"])
            self.assertEqual(result["persisted_samples"]["samples"]["ivf_exact_search"]["new"]["pairs"], 10)
            (target / "criterion" / "ivf_exact_search" / "base" / "sample.json").write_text("{}", encoding="utf-8")
            self.assertFalse(classify_benchmark_log("07-vector", log, target, output)["passed"])

    def test_benchmark_output_rejects_missing_or_duplicate_ids(self) -> None:
        expected = ("adjacency_one_hop",)
        valid = (
            b"Benchmarking adjacency_one_hop\n"
            b"Benchmarking adjacency_one_hop: Collecting 10 samples\n"
            b"adjacency_one_hop time: [1 ns 2 ns 3 ns]\n"
        )
        self.assertEqual(benchmark_observations(valid, expected)["errors"], [])
        self.assertTrue(benchmark_observations(valid + valid, expected)["errors"])
        self.assertTrue(benchmark_observations(valid.replace(b"10 samples", b"9 samples"), expected)["errors"])
        self.assertTrue(benchmark_observations(valid.replace(b"3 ns", b"0 ns"), expected)["errors"])
        self.assertTrue(benchmark_observations(b"Benchmarking unexpected\n" + valid, expected)["errors"])

    def test_wrong_rust_toolchain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            version = Path(temporary) / "rustc.raw.log"
            version.write_text("rustc 1.99.0 (abcdef 2026-01-01)\n", encoding="utf-8")
            assert_rust_version(version, "rustc")
            version.write_text("rustc 1.98.0 (abcdef 2026-01-01)\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expected rustc 1.99.0"):
                assert_rust_version(version, "rustc")

    def test_declared_roots_must_match_external_job_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "p80-bench-123-2"
            environment = {
                "RUNNER_TEMP": str(base), "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
                "CARGO_TARGET_DIR": str(root / "target"),
                "PRAXOR_TEST_TMP_ROOT": str(root / "fixtures"),
            }
            self.assertEqual(declared_root("benchmark", environment), root)
            wrong = {**environment, "CARGO_TARGET_DIR": str(base / "other")}
            with self.assertRaisesRegex(RuntimeError, "CARGO_TARGET_DIR differs"):
                declared_root("benchmark", wrong)


if __name__ == "__main__":
    unittest.main()
