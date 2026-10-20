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
from ci_catalog_platform_gate import assert_rust_version as assert_platform_rust_version  # noqa: E402

RUSTUP_PRELUDE = (
    "info: syncing channel updates for 1.99.0-x86_64-unknown-linux-gnu\n"
    "info: latest update on 2026-10-01 for version 1.99.0 (b940084d7 2026-09-28)\n"
    "info: downloading 2 components\n"
)
RUSTC_VERSION_OUTPUT = (
    "rustc 1.99.0 (b940084d7 2026-09-28)\n"
    "binary: rustc\n"
    "commit-hash: b940084d7eb6a299eb4bfeb8e34901bc051e7ac4\n"
    "commit-date: 2026-09-28\n"
    "host: x86_64-unknown-linux-gnu\n"
    "release: 1.99.0\n"
    "LLVM version: 23.1.1\n"
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
            version.write_text(RUSTC_VERSION_OUTPUT, encoding="utf-8")
            assert_rust_version(version, "rustc")
            version.write_text(RUSTC_VERSION_OUTPUT.replace("rustc 1.99.0", "rustc 1.98.0"), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expected rustc 1.99.0"):
                assert_rust_version(version, "rustc")

    def test_hosted_rustup_prelude_and_verbose_version_are_accepted_by_both_gates(self) -> None:
        observed = (RUSTUP_PRELUDE + RUSTC_VERSION_OUTPUT).encode()
        self.assertEqual(
            hashlib.sha256(observed).hexdigest(),
            "b6e46279701a7adcb65065bba40161a54102a1da26b4f6a5ee54eafbfa410787",
        )
        with tempfile.TemporaryDirectory() as temporary:
            version = Path(temporary) / "rustc.raw.log"
            version.write_bytes(observed)
            for parser in (assert_rust_version, assert_platform_rust_version):
                with self.subTest(parser=parser.__module__):
                    parser(version, "rustc")
                    self.assertEqual(version.read_bytes(), observed)

    def test_cargo_version_allows_bounded_rustup_prelude(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            version = Path(temporary) / "cargo.raw.log"
            version.write_text(
                "info: syncing channel updates for 1.99.0-x86_64-unknown-linux-gnu\n"
                "cargo 1.99.0 (abcdef123 2026-09-28)\n", encoding="utf-8",
            )
            for parser in (assert_rust_version, assert_platform_rust_version):
                with self.subTest(parser=parser.__module__):
                    parser(version, "cargo")

    def test_rust_version_rejects_unexpected_or_conflicting_output(self) -> None:
        good = RUSTC_VERSION_OUTPUT
        bad_logs = {
            "missing": "info: downloading 2 components\n",
            "wrong version": good.replace("rustc 1.99.0", "rustc 1.98.0"),
            "suffixed version": good.replace("rustc 1.99.0", "rustc 1.99.0-nightly"),
            "wrong command": good.replace("rustc 1.99.0", "cargo 1.99.0"),
            "unanchored": "prefix " + good,
            "malformed info": "info: unexpected rustup message\n" + good,
            "conflicting versions": good + "rustc 1.98.0 (b940084d7 2026-09-28)\n",
            "duplicate versions": good + good,
            "extra output": good + "warning: unexpected output\n",
            "late info": good + "info: downloading 2 components\n",
            "wrong release": good.replace("release: 1.99.0", "release: 1.98.0"),
            "unbounded info": ("info: downloading 2 components\n" * 17) + good,
            "bare rustc": "rustc 1.99.0\n",
            "banner only": good.splitlines(keepends=True)[0],
            "truncated verbose": good.rsplit("LLVM version: 23.1.1\n", 1)[0],
            "arbitrary banner": good.replace("(b940084d7 2026-09-28)", "(anything at all)", 1),
            "conflicting banner hash": good.replace("(b940084d7 2026-09-28)", "(aaaaaaaaa 2026-09-28)", 1),
            "conflicting banner date": good.replace("(b940084d7 2026-09-28)", "(b940084d7 2026-09-27)", 1),
            "invalid banner date": good.replace("(b940084d7 2026-09-28)", "(b940084d7 2026-99-99)", 1),
            "invalid matching dates": good.replace("2026-09-28", "2026-99-99"),
            "rustup hash disagreement": RUSTUP_PRELUDE.replace("(b940084d7 2026-09-28)", "(aaaaaaaaa 2026-09-28)") + good,
            "rustup date disagreement": RUSTUP_PRELUDE.replace("(b940084d7 2026-09-28)", "(b940084d7 2026-09-27)") + good,
            "rustup host disagreement": RUSTUP_PRELUDE.replace("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu") + good,
        }
        with tempfile.TemporaryDirectory() as temporary:
            version = Path(temporary) / "rustc.raw.log"
            for name, raw in bad_logs.items():
                version.write_text(raw, encoding="utf-8")
                for parser in (assert_rust_version, assert_platform_rust_version):
                    with self.subTest(case=name, parser=parser.__module__):
                        with self.assertRaisesRegex(RuntimeError, "expected rustc 1.99.0"):
                            parser(version, "rustc")

    def test_cargo_version_rejects_extra_output_or_invalid_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            version = Path(temporary) / "cargo.raw.log"
            for name, raw in {
                "bare cargo": b"cargo 1.99.0\n",
                "arbitrary banner": b"cargo 1.99.0 (arbitrary garbage)\n",
                "malformed hash": b"cargo 1.99.0 (zzzzzzzzz 2026-09-28)\n",
                "invalid date": b"cargo 1.99.0 (abcdef123 2026-99-99)\n",
                "extra line": b"cargo 1.99.0 (abcdef123 2026-09-28)\nrelease: 1.99.0\n",
                "invalid utf8": b"\xffcargo 1.99.0\n",
                "oversized": b"info: downloading 2 components\n" * 150,
            }.items():
                version.write_bytes(raw)
                for parser in (assert_rust_version, assert_platform_rust_version):
                    with self.subTest(case=name, parser=parser.__module__):
                        with self.assertRaisesRegex(RuntimeError, "expected cargo 1.99.0"):
                            parser(version, "cargo")

    def test_version_parser_never_reads_more_than_4097_bytes(self) -> None:
        reads = []

        class LargeLog:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self, size=-1):
                reads.append(size)
                if size < 0 or size > 4097:
                    raise AssertionError(f"unbounded version-log read: {size}")
                return b"x" * size

        class LogPath:
            def open(self, mode, **_):
                if mode != "rb":
                    raise AssertionError(f"unexpected read mode: {mode}")
                return LargeLog()

            def read_bytes(self):
                raise AssertionError("unbounded Path.read_bytes call")

        for parser in (assert_rust_version, assert_platform_rust_version):
            with self.assertRaisesRegex(RuntimeError, "raw log exceeds 4096 bytes"):
                parser(LogPath(), "rustc")
        self.assertEqual(reads, [4097, 4097])

    def test_version_parser_continues_after_short_reads_without_exceeding_cap(self) -> None:
        first = RUSTC_VERSION_OUTPUT.encode()
        reads = []

        class FragmentedLog:
            def __init__(self):
                self.fragments = [first, b"x" * (4097 - len(first))]

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self, size=-1):
                reads.append(size)
                if size < 0 or size > 4097:
                    raise AssertionError(f"unbounded version-log read: {size}")
                fragment = self.fragments.pop(0) if self.fragments else b""
                if len(fragment) > size:
                    raise AssertionError("read request exceeded remaining budget")
                return fragment

        class LogPath:
            def open(self, mode, **_):
                if mode != "rb":
                    raise AssertionError(f"unexpected read mode: {mode}")
                return FragmentedLog()

        for parser in (assert_rust_version, assert_platform_rust_version):
            with self.assertRaisesRegex(RuntimeError, "raw log exceeds 4096 bytes"):
                parser(LogPath(), "rustc")
        self.assertEqual(reads, [4097, 4097 - len(first)] * 2)

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
