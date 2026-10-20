"""Synthetic checks for source boundaries and byte-preserving stage receipts."""

from __future__ import annotations

import ctypes
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ci_catalog_source_check as source_check  # noqa: E402
from ci_catalog_source_check import MAX_LOCK_DIFF_BYTES, cargo_lock_diff, check, generated_roots  # noqa: E402
from ci_catalog_stage import (  # noqa: E402
    REQUIRED_SOURCE, StageRecorder, assert_unaliased_tracked_path,
    canonical_working_blob, checkout_untracked_paths, effective_environment, git_eol_and_attributes,
    raw_file_evidence, sha256_file, snapshot_cargo_lock, tracked_manifest, utc_now,
)


def synthetic_manifest(head: str = "a" * 40, *, status: str = "", digest: str = "c" * 64) -> dict:
    return {
        "head": head, "tree": "b" * 40, "tracked_status": status,
        "untracked_paths": [], "ignored_untracked_paths": [],
        "git_conversion_config": {"core.autocrlf": "true", "core.eol": None},
        "files_sha256": digest,
        "files": [{"path": name, "sha256": "c" * 64} for name in sorted(REQUIRED_SOURCE)],
    }


def synthetic_resource_sample(self, stage, samples, guard, lock) -> None:
    event = {
        "utc": "2026-10-19T00:00:00+00:00", "stage": stage,
        "disk_total_bytes": 20 * 1024**3,
        "disk_free_bytes": 12 * 1024**3,
        "cargo_home_disk_free_bytes": 11 * 1024**3,
        "rustup_home_disk_free_bytes": 10 * 1024**3,
        "ram_total_bytes": 8 * 1024**3,
        "ram_available_bytes": 4 * 1024**3,
    }
    with lock:
        samples.append(event)
        with (self.logs / f"{stage}.resources.jsonl").open("a", encoding="utf-8") as out:
            out.write(json.dumps(event) + "\n")


def synthetic_lock_repo(repo: Path) -> None:
    """Create a disposable one-file Git fixture; never commit in the project checkout."""
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / "Cargo.lock").write_bytes(b"x\n")
    subprocess.run(["git", "add", "Cargo.lock"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=CI Fixture", "-c", "user.email=ci@example.invalid",
         "commit", "-qm", "synthetic lock fixture"],
        cwd=repo, check=True,
    )


def synthetic_eol_lock_repo(repo: Path) -> tuple[bytes, bytes]:
    """A disposable Git fixture whose raw EOL drift has an empty normalized diff."""
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "core.autocrlf", "true"], cwd=repo, check=True)
    lf = b"version = 3\n"
    crlf = b"version = 3\r\n"
    (repo / "Cargo.lock").write_bytes(lf)
    subprocess.run(["git", "add", "Cargo.lock"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=CI Fixture", "-c", "user.email=ci@example.invalid",
         "commit", "-qm", "synthetic EOL fixture"],
        cwd=repo, check=True,
    )
    (repo / "Cargo.lock").write_bytes(crlf)
    assert subprocess.check_output(["git", "diff", "--", "Cargo.lock"], cwd=repo) == b""
    return crlf, lf


def workflow_run_block(step_name: str) -> str:
    """Extract one plain run block without depending on PyYAML on hosted runners."""
    lines = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(
        encoding="utf-8"
    ).splitlines()
    start = lines.index(f"      - name: {step_name}")
    run = next(index for index in range(start + 1, len(lines)) if lines[index] == "        run: |")
    body = []
    for line in lines[run + 1:]:
        if line.startswith("      - name:") or line.startswith("      - uses:"):
            break
        if line and not line.startswith("          "):
            raise AssertionError(f"unexpected workflow run indentation: {line}")
        body.append(line[10:] if line else "")
    return "\n".join(body) + "\n"


class StageReceiptTests(unittest.TestCase):
    def assert_pid_exited(self, pid: int) -> None:
        if os.name == "nt":
            kernel = ctypes.windll.kernel32
            kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            kernel.OpenProcess.restype = ctypes.c_void_p
            kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            kernel.WaitForSingleObject.restype = ctypes.c_ulong
            handle = kernel.OpenProcess(0x00100000, 0, pid)  # SYNCHRONIZE
            if not handle:
                error = kernel.GetLastError()
                self.assertEqual(error, 87, f"OpenProcess failed without proving PID {pid} exited: {ctypes.WinError(error)}")
                return
            try:
                self.assertEqual(kernel.WaitForSingleObject(ctypes.c_void_p(handle), 1000), 0)
            finally:
                kernel.CloseHandle(ctypes.c_void_p(handle))
        else:
            try:
                raw = (Path("/proc") / str(pid) / "stat").read_bytes()
            except FileNotFoundError:
                return
            end = raw.rfind(b") ")
            self.assertGreaterEqual(end, 0)
            self.assertIn(raw[end + 2:].split()[0], (b"Z", b"X", b"x"))

    def setUp(self) -> None:
        self.soft_env = patch.dict(
            os.environ, {"P80_SOFT_JOB_MINUTES": "70", "P80_SETUP_START_UTC": utc_now()}
        )
        self.soft_env.start()
        self.addCleanup(self.soft_env.stop)
        def empty_lock_diff(_repo: Path, *, staged: bool, artifact: Path | None = None) -> dict:
            if artifact is not None:
                artifact.write_bytes(b"")
            return {
                "sha256": hashlib.sha256(b"").hexdigest(), "bytes": 0,
                "truncated": False, "prefix": "", "artifact": str(artifact) if artifact else None,
            }

        self.lock_diff = patch("ci_catalog_stage.cargo_lock_diff", side_effect=empty_lock_diff)
        self.lock_diff.start()
        self.addCleanup(self.lock_diff.stop)
        self.status = patch("ci_catalog_stage.checkout_status", return_value="")
        self.status.start()
        self.addCleanup(self.status.stop)
        self.untracked = patch(
            "ci_catalog_stage.checkout_untracked_paths",
            return_value={"untracked_paths": [], "ignored_untracked_paths": []},
        )
        self.untracked.start()
        self.addCleanup(self.untracked.stop)
        def synthetic_lock_sha(path: Path) -> str:
            if path.name == "Cargo.lock" and not path.exists():
                return "c" * 64
            return sha256_file(path)

        self.lock_sha = patch("ci_catalog_stage.sha256_file", side_effect=synthetic_lock_sha)
        self.lock_sha.start()
        self.addCleanup(self.lock_sha.stop)

        def synthetic_raw_evidence(path: Path) -> dict:
            return {"artifact": str(path), "sha256": "c" * 64, "bytes": 1}

        def synthetic_raw_snapshot(_repo: Path, artifact: Path) -> dict:
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(b"x")
            return synthetic_raw_evidence(artifact)

        self.raw_evidence = patch("ci_catalog_stage.raw_file_evidence", side_effect=synthetic_raw_evidence)
        self.raw_evidence.start()
        self.addCleanup(self.raw_evidence.stop)
        self.raw_snapshot = patch("ci_catalog_stage.snapshot_cargo_lock", side_effect=synthetic_raw_snapshot)
        self.raw_snapshot.start()
        self.addCleanup(self.raw_snapshot.stop)

    def test_secret_environment_values_are_redacted(self) -> None:
        environment = effective_environment(
            {"PATH": "/bin", "AWS_ACCESS_KEY_ID": "key-value", "GITHUB_TOKEN": "token-value"}
        )
        self.assertEqual(environment["PATH"], "/bin")
        self.assertEqual(environment["AWS_ACCESS_KEY_ID"], "[REDACTED]")
        self.assertEqual(environment["GITHUB_TOKEN"], "[REDACTED]")

    def test_linux_preflight_receipt_precedes_lock_copy(self) -> None:
        for step in (
            "Record pre-gate Linux setup",
            "Record pre-gate feature setup",
            "Record pre-gate benchmark setup",
        ):
            with self.subTest(step=step):
                run = workflow_run_block(step)
                self.assertLess(run.index("setup-pretoolchain.start.json"), run.index("cp -- Cargo.lock"))
                self.assertLess(run.index("trap setup_exit EXIT"), run.index("cp -- Cargo.lock"))
                self.assertIn("setup-pretoolchain.exit.json", run)
                self.assertIn("setup-pretoolchain.error.txt", run)
                self.assertIn('>> "$root/logs/setup-pretoolchain.raw.log" 2>&1', run)

    def test_preflight_resource_and_source_evidence_precedes_env_declaration(self) -> None:
        for step in (
            "Record pre-gate Linux setup",
            "Record pre-gate feature setup",
            "Record pre-gate benchmark setup",
        ):
            with self.subTest(step=step):
                run = workflow_run_block(step)
                self.assertLess(run.index("setup-pretoolchain.start.json"), run.index("setup-pretoolchain.raw.log"))
                self.assertLess(run.index("df -B1"), run.index("git rev-parse HEAD"))
                self.assertLess(run.index("free -b"), run.index("git rev-parse HEAD"))
                self.assertLess(run.index("git ls-files --others"), run.index('>> "$GITHUB_ENV"'))
        windows = workflow_run_block("Record pre-gate Windows setup")
        self.assertLess(windows.index("setup-pretoolchain.start.json"), windows.index("setup-pretoolchain.json"))
        self.assertLess(windows.index("setup-pretoolchain.json"), windows.index("Get-CimInstance"))
        self.assertLess(windows.index("Get-CimInstance"), windows.index("Out-File -FilePath $env:GITHUB_ENV"))
        self.assertIn("$setup['failed_probe'] = $currentProbe", windows)

    def test_core_linux_preflight_faults_keep_source_resource_receipts(self) -> None:
        if os.name == "nt":
            shell = Path("C:/Program Files/Git/bin/bash.exe")
            if not shell.is_file():
                self.skipTest("Git Bash unavailable")
            shell = str(shell)
        else:
            shell = shutil.which("bash")
        if not shell:
            self.skipTest("Bash unavailable")

        def shell_path(path: Path) -> str:
            if os.name != "nt":
                return str(path)
            return subprocess.check_output([shell, "-c", 'cygpath -u "$1"', "_", str(path)], text=True).strip()

        for injection in ("normal", "missing_lock", "env_directory", "git_failure", "non_git_repo", "disk_failure", "memory_failure", "two_probe_failure"):
            with self.subTest(injection=injection), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo = root / "repo"
                if injection == "non_git_repo":
                    repo.mkdir()
                    (repo / "Cargo.lock").write_bytes(b"x\n")
                else:
                    synthetic_lock_repo(repo)
                if injection == "missing_lock":
                    (repo / "Cargo.lock").unlink()
                runner = root / "runner"
                runner.mkdir()
                github_env = root / "github.env"
                if injection == "env_directory":
                    github_env.mkdir()
                prefix = 'free() { printf "synthetic-free\\n"; }\n' if os.name == "nt" else ""
                if injection in ("git_failure", "two_probe_failure"):
                    prefix += 'git() { if [ "$1" = "rev-parse" ]; then return 23; fi; command git "$@"; }\n'
                if injection in ("disk_failure", "two_probe_failure"):
                    prefix += 'df() { printf "synthetic disk probe failed\\n" >&2; return 24; }\n'
                if injection == "memory_failure":
                    prefix += 'free() { printf "synthetic memory probe failed\\n" >&2; return 25; }\n'
                script = root / "preflight.sh"
                script.write_text(prefix + workflow_run_block("Record pre-gate Linux setup"), encoding="utf-8")
                environment = os.environ.copy()
                environment.update(RUNNER_TEMP=shell_path(runner), GITHUB_ENV=shell_path(github_env),
                                   GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1", ImageOS="synthetic",
                                   ImageVersion="fixture")
                result = subprocess.run([shell, shell_path(script)], cwd=repo, env=environment,
                                        capture_output=True, text=True, timeout=20)
                logs = runner / "p80-42-1" / "logs"
                start = json.loads((logs / "setup-pretoolchain.start.json").read_text(encoding="utf-8"))
                end = json.loads((logs / "setup-pretoolchain.exit.json").read_text(encoding="utf-8"))
                raw = (logs / "setup-pretoolchain.raw.log").read_text(encoding="utf-8")
                self.assertEqual(start["event"], "start")
                self.assertIn("setup_started_utc=", raw)
                self.assertIn("runner_image=synthetic/fixture", raw)
                for probe in ("disk", "memory", "head", "tree", "status", "ignored_untracked"):
                    self.assertIn(f"{probe}_probe_status=", raw)
                if injection == "normal":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(end["exit_code"], 0)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotEqual(end["exit_code"], 0)
                    self.assertTrue((logs / "setup-pretoolchain.error.txt").read_text(encoding="utf-8"))
                if injection in ("env_directory", "missing_lock", "git_failure", "non_git_repo"):
                    self.assertIn("synthetic-free", raw) if os.name == "nt" else self.assertIn("Mem:", raw)
                    self.assertIn("Filesystem", raw)
                if injection in ("disk_failure", "memory_failure", "two_probe_failure"):
                    self.assertIn("head_probe_status=" + ("error" if injection == "two_probe_failure" else "ok"), raw)
                    self.assertIn("tree_probe_status=" + ("error" if injection == "two_probe_failure" else "ok"), raw)
                    self.assertIn("status_probe_status=ok", raw)
                    self.assertIn("ignored_untracked_probe_status=ok", raw)
                    self.assertFalse(github_env.exists())
                    self.assertFalse((logs / "setup-pretoolchain.Cargo.lock.raw").exists())
                if injection in ("git_failure", "non_git_repo", "two_probe_failure"):
                    self.assertIn("disk_probe_status=" + ("error" if injection == "two_probe_failure" else "ok"), raw)
                    self.assertIn("memory_probe_status=ok", raw)
                    self.assertFalse(github_env.exists())
                    self.assertFalse((logs / "setup-pretoolchain.Cargo.lock.raw").exists())
                if injection == "two_probe_failure":
                    self.assertIn("disk_probe_status=error", raw)
                    self.assertIn("head_probe_status=error", raw)
                    self.assertIn("required_probe_failure=1", raw)
                if injection == "env_directory":
                    self.assertIn("head=", raw)
                    self.assertIn("directory", raw.lower())

    def test_core_windows_preflight_faults_keep_progressive_json(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows preflight runs on Windows")
        shell = shutil.which("pwsh")
        if not shell:
            self.skipTest("PowerShell unavailable")
        for injection in ("normal", "missing_lock", "env_directory", "git_failure", "non_git_repo", "memory_failure", "drive_failure", "two_probe_failure"):
            with self.subTest(injection=injection), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo = root / "repo"
                if injection == "non_git_repo":
                    repo.mkdir()
                    (repo / "Cargo.lock").write_bytes(b"x\n")
                else:
                    synthetic_lock_repo(repo)
                if injection == "missing_lock":
                    (repo / "Cargo.lock").unlink()
                runner = root / "runner"
                runner.mkdir()
                relative_runner = injection in ("drive_failure", "two_probe_failure")
                runner_env = "relative-runner" if relative_runner else str(runner)
                github_env = root / "github.env"
                if injection == "env_directory":
                    github_env.mkdir()
                prefix = ""
                if injection == "git_failure":
                    prefix = "function git { $global:LASTEXITCODE = 23; 'synthetic git failure' }\n"
                if injection in ("memory_failure", "two_probe_failure"):
                    prefix = "function Get-CimInstance { throw 'synthetic memory probe failure' }\n"
                script = root / "preflight.ps1"
                script.write_text(prefix + workflow_run_block("Record pre-gate Windows setup"), encoding="utf-8")
                environment = os.environ.copy()
                environment.update(RUNNER_TEMP=runner_env, GITHUB_ENV=str(github_env),
                                   GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1", ImageOS="synthetic",
                                   ImageVersion="fixture")
                result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-File", str(script)],
                                        cwd=repo, env=environment, capture_output=True, text=True, timeout=20)
                logs = (repo / runner_env if relative_runner else runner) / "p80-42-1" / "logs"
                start = json.loads((logs / "setup-pretoolchain.start.json").read_text(encoding="utf-8"))
                end = json.loads((logs / "setup-pretoolchain.exit.json").read_text(encoding="utf-8"))
                progress = json.loads((logs / "setup-pretoolchain.json").read_text(encoding="utf-8"))
                self.assertEqual(start["event"], "start")
                self.assertEqual(progress["setup_started_utc"], start["utc"])
                self.assertEqual(progress["runner_image"], "synthetic/fixture")
                self.assertEqual(set(progress["probe_status"]), {"drive", "memory", "git_head", "git_tree", "git_status", "git_ignored_untracked"})
                self.assertNotIn("pending", progress["probe_status"].values())
                if injection == "normal":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(end["exit_code"], 0)
                    self.assertEqual(progress["state"], "complete")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotEqual(end["exit_code"], 0)
                    self.assertEqual(progress["state"], "failed")
                    self.assertEqual(progress["error"], end["error"])
                    self.assertTrue(progress["failed_probe"])
                    if not relative_runner:
                        self.assertIsNotNone(progress["disk_free_bytes"])
                    if injection == "memory_failure":
                        self.assertEqual(progress["failed_probe"], "memory")
                        self.assertEqual(progress["probe_status"]["memory"], "error")
                        self.assertEqual(progress["probe_status"]["git_head"], "ok")
                        self.assertIsNotNone(progress["head"])
                    elif injection in ("git_failure", "non_git_repo"):
                        self.assertEqual(progress["failed_probe"], "git_head")
                        self.assertIsNotNone(progress["ram_available_bytes"])
                        self.assertEqual(progress["probe_status"]["drive"], "ok")
                        self.assertEqual(progress["probe_status"]["memory"], "ok")
                    elif injection in ("drive_failure", "two_probe_failure"):
                        self.assertEqual(progress["failed_probe"], "drive")
                        self.assertEqual(progress["probe_status"]["drive"], "error")
                        self.assertEqual(progress["probe_status"]["git_head"], "ok")
                        self.assertIsNotNone(progress["head"])
                        self.assertFalse(github_env.exists())
                        self.assertFalse((logs / "setup-pretoolchain.Cargo.lock.raw").exists())
                        if injection == "two_probe_failure":
                            self.assertEqual(progress["probe_status"]["memory"], "error")
                            self.assertEqual(set(progress["probe_errors"]), {"drive", "memory"})
                    elif injection == "env_directory":
                        self.assertEqual(progress["failed_probe"], "github_env")
                        self.assertIsNotNone(progress["head"])
                    elif injection == "missing_lock":
                        self.assertEqual(progress["failed_probe"], "cargo_lock_copy")

    def test_generated_root_declarations_are_inside_receipt_protected_setup(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("- name: Declare feature generated roots", workflow)
        self.assertNotIn("- name: Declare benchmark generated roots", workflow)
        for step in ("Record pre-gate feature setup", "Record pre-gate benchmark setup"):
            with self.subTest(step=step):
                run = workflow_run_block(step)
                self.assertLess(run.index("setup-pretoolchain.start.json"), run.index('mkdir -p "$root/target"'))
                self.assertLess(run.index("trap setup_exit EXIT"), run.index('mkdir -p "$root/target"'))
                self.assertLess(run.index("setup-pretoolchain.raw.log"), run.index('mkdir -p "$root/target"'))
                self.assertLess(run.index('mkdir -p "$root/target"'), run.index('echo "CARGO_TARGET_DIR='))
                self.assertLess(run.index('echo "CARGO_TARGET_DIR='), run.index('echo "PRAXOR_TEST_TMP_ROOT='))

    def test_generated_root_and_github_env_failures_leave_receipts(self) -> None:
        if os.name == "nt":
            bash = Path("C:/Program Files/Git/bin/bash.exe")
            if not bash.is_file():
                self.skipTest("Git Bash unavailable for Linux workflow failure probe")
            shell = str(bash)
        else:
            shell = shutil.which("bash")
            if shell is None:
                self.skipTest("Bash unavailable for Linux workflow failure probe")

        def shell_path(path: Path) -> str:
            if os.name != "nt":
                return str(path)
            return subprocess.check_output(
                [shell, "-c", 'cygpath -u "$1"', "_", str(path)], text=True,
            ).strip()

        for step, prefix in (
            ("Record pre-gate feature setup", "p80-feature-gpu-cuda"),
            ("Record pre-gate benchmark setup", "p80-bench"),
        ):
            for injection in ("target_file", "env_directory", "non_git_repo", "disk_failure", "memory_failure", "git_failure", "two_probe_failure", "normal"):
                with self.subTest(step=step, injection=injection), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    repo = root / "repo"
                    if injection == "non_git_repo":
                        repo.mkdir()
                        (repo / "Cargo.lock").write_bytes(b"x\n")
                    else:
                        synthetic_lock_repo(repo)
                    runner = root / "runner"
                    runner.mkdir()
                    owned_root = runner / f"{prefix}-42-1"
                    if injection == "target_file":
                        owned_root.mkdir()
                        (owned_root / "target").write_text("not a directory", encoding="utf-8")
                    github_env = root / "github.env"
                    if injection == "env_directory":
                        github_env.mkdir()
                    script = root / "preflight.sh"
                    prefix_script = 'free() { printf "synthetic-free\\n"; }\n' if os.name == "nt" else ""
                    if injection in ("disk_failure", "two_probe_failure"):
                        prefix_script += 'df() { printf "synthetic disk probe failed\\n" >&2; return 24; }\n'
                    if injection == "memory_failure":
                        prefix_script += 'free() { printf "synthetic memory probe failed\\n" >&2; return 25; }\n'
                    if injection in ("git_failure", "two_probe_failure"):
                        prefix_script += 'git() { if [ "$1" = "rev-parse" ]; then return 23; fi; command git "$@"; }\n'
                    script.write_text(prefix_script + workflow_run_block(step), encoding="utf-8")
                    environment = os.environ.copy()
                    environment.update(
                        RUNNER_TEMP=shell_path(runner), GITHUB_ENV=shell_path(github_env),
                        GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1", FEATURE_SET="gpu-cuda",
                        ImageOS="synthetic", ImageVersion="fixture",
                    )
                    result = subprocess.run(
                        [shell, shell_path(script)], cwd=repo, env=environment,
                        capture_output=True, text=True, timeout=20,
                    )
                    logs = owned_root / "logs"
                    start = json.loads((logs / "setup-pretoolchain.start.json").read_text(encoding="utf-8"))
                    end = json.loads((logs / "setup-pretoolchain.exit.json").read_text(encoding="utf-8"))
                    self.assertEqual(start["event"], "start")
                    self.assertTrue((logs / "setup-pretoolchain.raw.log").is_file())
                    if injection == "normal":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(end["state"], "passed")
                        self.assertEqual(end["exit_code"], 0)
                        self.assertEqual(
                            (logs / "setup-pretoolchain.Cargo.lock.raw").read_bytes(),
                            (repo / "Cargo.lock").read_bytes(),
                        )
                        self.assertIn("CARGO_TARGET_DIR=", github_env.read_text(encoding="utf-8"))
                        self.assertIn("PRAXOR_TEST_TMP_ROOT=", github_env.read_text(encoding="utf-8"))
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(end["state"], "failed")
                        self.assertNotEqual(end["exit_code"], 0)
                        self.assertEqual(end["error"], "pre_gate_setup_failed")
                        self.assertTrue((logs / "setup-pretoolchain.error.txt").read_text(encoding="utf-8"))
                        if injection == "non_git_repo":
                            raw = (logs / "setup-pretoolchain.raw.log").read_text(encoding="utf-8")
                            self.assertIn("Filesystem", raw)
                            self.assertIn("synthetic-free" if os.name == "nt" else "Mem:", raw)
                        if injection in ("disk_failure", "memory_failure", "two_probe_failure"):
                            raw = (logs / "setup-pretoolchain.raw.log").read_text(encoding="utf-8")
                            for probe in ("head", "tree", "status", "ignored_untracked"):
                                expected = "error" if injection == "two_probe_failure" and probe in ("head", "tree") else "ok"
                                self.assertIn(f"{probe}_probe_status={expected}", raw)
                            self.assertFalse(github_env.exists())
                            self.assertFalse((logs / "setup-pretoolchain.Cargo.lock.raw").exists())
                        if injection in ("git_failure", "non_git_repo", "two_probe_failure"):
                            raw = (logs / "setup-pretoolchain.raw.log").read_text(encoding="utf-8")
                            self.assertIn("memory_probe_status=ok", raw)
                            self.assertIn("disk_probe_status=" + ("error" if injection == "two_probe_failure" else "ok"), raw)
                            self.assertFalse(github_env.exists())
                            self.assertFalse((logs / "setup-pretoolchain.Cargo.lock.raw").exists())
                        if injection == "env_directory":
                            self.assertIn(
                                "directory",
                                (logs / "setup-pretoolchain.raw.log").read_text(encoding="utf-8").lower(),
                            )

    def test_missing_lock_setup_emits_failure_receipt(self) -> None:
        if os.name == "nt":
            shell = shutil.which("pwsh")
            step = "Record pre-gate Windows setup"
            suffix = ".ps1"
        else:
            shell = shutil.which("bash")
            step = "Record pre-gate Linux setup"
            suffix = ".sh"
        if shell is None:
            self.skipTest(f"{step} shell unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            (repo / "fixture.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["git", "add", "fixture.txt"], cwd=repo, check=True)
            subprocess.run(
                ["git", "-c", "user.name=CI Fixture", "-c", "user.email=ci@example.invalid",
                 "commit", "-qm", "synthetic preflight fixture"], cwd=repo, check=True,
            )
            runner = root / "runner"
            runner.mkdir()
            script = root / ("preflight" + suffix)
            script.write_text(workflow_run_block(step), encoding="utf-8")
            github_env = root / "github.env"
            environment = os.environ.copy()
            environment.update(
                RUNNER_TEMP=str(runner), GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1",
                GITHUB_ENV=str(github_env), ImageOS="synthetic", ImageVersion="fixture",
            )
            argv = [shell, "-NoProfile", "-NonInteractive", "-File", str(script)] if os.name == "nt" else [shell, str(script)]
            result = subprocess.run(argv, cwd=repo, env=environment, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            logs = runner / "p80-42-1" / "logs"
            start = json.loads((logs / "setup-pretoolchain.start.json").read_text(encoding="utf-8"))
            end = json.loads((logs / "setup-pretoolchain.exit.json").read_text(encoding="utf-8"))
            self.assertEqual(start["event"], "start")
            self.assertEqual(end["event"], "exit")
            self.assertEqual(end["state"], "failed")
            self.assertNotEqual(end["exit_code"], 0)
            if os.name == "nt":
                self.assertIn("Cargo.lock", end["error"])
                pre_copy = json.loads((logs / "setup-pretoolchain.json").read_text(encoding="utf-8"))
                self.assertEqual(pre_copy["state"], "failed")
                self.assertEqual(pre_copy["failed_probe"], "cargo_lock_copy")
                self.assertIn("disk_free_bytes", pre_copy)
                self.assertIn("ram_available_bytes", pre_copy)
            else:
                self.assertGreater(end["failure_line"], 0)
                self.assertEqual(end["error"], "pre_gate_setup_failed")
                self.assertIn("Cargo.lock", (logs / "setup-pretoolchain.error.txt").read_text(encoding="utf-8"))
                self.assertIn("Cargo.lock", (logs / "setup-pretoolchain.raw.log").read_text(encoding="utf-8"))

    def test_first_sigterm_interrupts_stage_and_repeat_does_not_interrupt_cleanup(self) -> None:
        from ci_catalog_stage import install_termination_handler

        with patch("ci_catalog_stage.signal.signal") as install:
            install_termination_handler()
        handler = install.call_args.args[1]
        with self.assertRaisesRegex(InterruptedError, "received runner signal"):
            handler(15, None)
        handler(15, None)

    def test_raw_receipt_preserves_bytes_and_source_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            expected_head = "a" * 40
            manifest = synthetic_manifest(expected_head)
            environment = os.environ.copy()
            environment.update(
                CARGO_TARGET_DIR=str(root / "target"),
                PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"),
                TEMP=str(root / "tmp"),
            )

            with patch("ci_catalog_stage.tracked_manifest", return_value=manifest), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ):
                gate = StageRecorder(repo, root, expected_head, environment, "linux")
                log = gate.run(
                    "synthetic",
                    [
                        sys.executable, "-c",
                        "import sys; sys.stdout.buffer.write(b'\\x00out\\xff'); "
                        "sys.stdout.buffer.flush(); sys.stderr.buffer.write(b'err\\x00')",
                    ],
                )
                gate.finish({"qualification": "synthetic-only"}, expected_stages=("synthetic",))
            raw = log.read_bytes()
            self.assertIn(b"\x00out\xff", raw)
            self.assertIn(b"err\x00", raw)
            receipt = json.loads((gate.logs / "synthetic.receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["raw_log_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(receipt["raw_log_bytes"], len(raw))
            self.assertEqual(receipt["exit_code"], 0)
            self.assertEqual(receipt["source_before_sha256"], manifest["files_sha256"])
            self.assertEqual(receipt["source_after_sha256"], manifest["files_sha256"])
            self.assertEqual(receipt["minimum_disk_free_bytes"], 12 * 1024**3)
            self.assertEqual(receipt["minimum_cargo_home_disk_free_bytes"], 11 * 1024**3)
            self.assertEqual(receipt["minimum_rustup_home_disk_free_bytes"], 10 * 1024**3)
            self.assertEqual(receipt["minimum_ram_available_bytes"], 4 * 1024**3)
            self.assertEqual(sha256_file(log), receipt["raw_log_sha256"])

    def test_benchmark_boundary_fails_on_changed_bytes_or_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw_path = Path(temporary) / "cargo-lock-working.snapshot.raw"
            setup_path = Path(temporary) / "setup-pretoolchain.Cargo.lock.raw"
            raw_path.write_bytes(b"x")
            setup_path.write_bytes(b"x")
            base = {
                "expected_head": "a" * 40,
                "generated_artifact_roots": ["/tmp/target"],
                "cargo_lock_sha256": hashlib.sha256(b"x").hexdigest(),
                "manifest": {
                    "head": "a" * 40, "tree": "b" * 40,
                    "tracked_status": "", "files_sha256": "c" * 64,
                },
                "diagnostics": {
                    "porcelain": [], "unstaged_name_status": [], "staged_name_status": [],
                    "untracked_paths": [], "ignored_untracked_paths": [],
                    "cargo_lock_raw": raw_file_evidence(raw_path),
                    "pretoolchain_cargo_lock_raw": raw_file_evidence(setup_path),
                },
            }
            self.assertEqual(check(base, base), [])
            changed = json.loads(json.dumps(base))
            changed["manifest"]["files_sha256"] = "d" * 64
            changed["diagnostics"]["untracked_paths"] = ["unexpected.dat"]
            errors = check(base, changed)
            self.assertIn("tracked checkout bytes changed between boundaries", errors)
            self.assertIn("undeclared untracked paths appeared inside checkout", errors)

            raw_path.write_bytes(b"tampered")
            self.assertIn("baseline raw Cargo.lock artifact changed", check(base, changed))

    def test_ignored_python_bytecode_is_untracked_checkout_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            (repo / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
            bytecode = repo / "scripts" / "__pycache__" / "gate.pyc"
            bytecode.parent.mkdir(parents=True)
            bytecode.write_bytes(b"synthetic-bytecode")
            (repo / "Cargo.lock").write_bytes(b"x\n")
            setup_raw = root / "source-artifacts" / "logs" / "setup-pretoolchain.Cargo.lock.raw"
            setup_raw.parent.mkdir(parents=True)
            setup_raw.write_bytes(b"x\n")
            untracked = checkout_untracked_paths(repo)
            self.assertIn("scripts/__pycache__/gate.pyc", untracked["ignored_untracked_paths"])
            with patch("ci_catalog_stage.raw_file_evidence", side_effect=raw_file_evidence):
                diagnostic = source_check.diagnostics(repo, root / "source-artifacts", "ignored")
            self.assertIn("scripts/__pycache__/gate.pyc", diagnostic["ignored_untracked_paths"])
            snapshot = {
                "expected_head": "a" * 40,
                "generated_artifact_roots": [str(repo.parent / "target")],
                "manifest": synthetic_manifest(),
                "diagnostics": {
                    "unstaged_name_status": [], "staged_name_status": [],
                    **untracked,
                },
            }
            self.assertIn("ignored untracked paths appeared inside checkout", check(snapshot, snapshot))
            ignored_manifest = synthetic_manifest()
            ignored_manifest["ignored_untracked_paths"] = ["scripts/__pycache__/gate.pyc"]
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(repo.parent / "target"), PRAXOR_TEST_TMP_ROOT=str(repo.parent / "fixtures"), TEMP=str(repo.parent / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=ignored_manifest):
                with self.assertRaisesRegex(RuntimeError, "clean exact event head"):
                    StageRecorder(repo, repo.parent / "gate-artifacts", "a" * 40, environment, "linux")

    def test_benchmark_source_check_collection_failure_still_writes_after_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            output = root / "artifacts" / "source.after.json"
            argv = [
                "ci_catalog_source_check.py", "snapshot", "--expected-head", "a" * 40,
                "--output", str(output), "--generated-root", str(root / "target"),
            ]
            with patch.object(source_check, "__file__", str(repo / "scripts" / "ci_catalog_source_check.py")), patch(
                "ci_catalog_source_check.diagnostics", side_effect=RuntimeError("synthetic source probe failed")
            ), patch.object(sys, "argv", argv):
                self.assertEqual(source_check.main(), 1)
            after = json.loads(output.read_text(encoding="utf-8"))
            self.assertIn("synthetic source probe failed", after["collection_error"])

    def test_stage_lock_mutation_preserves_after_snapshot_and_complete_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            synthetic_lock_repo(repo)
            setup_raw = root / "artifacts" / "logs" / "setup-pretoolchain.Cargo.lock.raw"
            setup_raw.parent.mkdir(parents=True)
            setup_raw.write_bytes((repo / "Cargo.lock").read_bytes())
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))

            def strict_manifest(_repo: Path) -> dict:
                if (repo / "Cargo.lock").read_bytes() != b"x\n":
                    raise RuntimeError("working bytes do not normalize to committed HEAD blob: Cargo.lock")
                result = synthetic_manifest()
                for entry in result["files"]:
                    if entry["path"] == "Cargo.lock":
                        entry["sha256"] = sha256_file(repo / "Cargo.lock")
                return result

            with patch("ci_catalog_stage.tracked_manifest", side_effect=strict_manifest), patch(
                "ci_catalog_stage.cargo_lock_diff", side_effect=cargo_lock_diff
            ), patch("ci_catalog_stage.snapshot_cargo_lock", side_effect=snapshot_cargo_lock), patch(
                "ci_catalog_stage.raw_file_evidence", side_effect=raw_file_evidence
            ), patch.object(StageRecorder, "_sample", synthetic_resource_sample):
                gate = StageRecorder(repo, root / "artifacts", "a" * 40, environment, "linux")
                with self.assertRaisesRegex(RuntimeError, "working bytes do not normalize"):
                    gate.run("mutate", [sys.executable, "-c", "from pathlib import Path; Path('Cargo.lock').write_bytes(b'y\\n')"])
            after = json.loads((gate.logs / "mutate.source.after.json").read_text(encoding="utf-8"))
            patch_path = gate.logs / "mutate.cargo-lock-unstaged.after.patch"
            patch_bytes = patch_path.read_bytes()
            self.assertIn(b"-x", patch_bytes)
            self.assertIn(b"+y", patch_bytes)
            self.assertEqual(after["cargo_lock_unstaged_diff"]["sha256"], hashlib.sha256(patch_bytes).hexdigest())
            self.assertIn("Cargo.lock", after["manifest_error"])
            receipt = json.loads((gate.logs / "mutate.receipt.json").read_text(encoding="utf-8"))
            self.assertIn("Cargo.lock", receipt["error"])
            self.assertIsNone(receipt["source_after_sha256"])

    def test_setup_eol_only_lock_drift_preserves_both_raw_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            crlf, lf = synthetic_eol_lock_repo(repo)
            logs = root / "artifacts" / "logs"
            logs.mkdir(parents=True)
            (logs / "setup-pretoolchain.Cargo.lock.raw").write_bytes(crlf)
            (repo / "Cargo.lock").write_bytes(lf)
            self.assertEqual(subprocess.check_output(["git", "diff", "--", "Cargo.lock"], cwd=repo), b"")
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.snapshot_cargo_lock", side_effect=snapshot_cargo_lock), patch(
                "ci_catalog_stage.raw_file_evidence", side_effect=raw_file_evidence
            ):
                with self.assertRaisesRegex(RuntimeError, "raw bytes changed between pretoolchain setup"):
                    StageRecorder(repo, root / "artifacts", "a" * 40, environment, "linux")
            self.assertEqual((logs / "source-baseline.Cargo.lock.raw").read_bytes(), lf)
            self.assertEqual((logs / "setup-pretoolchain.Cargo.lock.raw").read_bytes(), crlf)
            diagnostic = json.loads((logs / "setup-failure.json").read_text(encoding="utf-8"))
            self.assertNotEqual(
                diagnostic["pretoolchain_cargo_lock_raw"]["sha256"],
                diagnostic["baseline_cargo_lock_raw"]["sha256"],
            )

    def test_stage_eol_only_lock_drift_has_empty_git_patch_but_raw_after_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            crlf, lf = synthetic_eol_lock_repo(repo)
            logs = root / "artifacts" / "logs"
            logs.mkdir(parents=True)
            (logs / "setup-pretoolchain.Cargo.lock.raw").write_bytes(crlf)
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))

            def current_manifest(_repo: Path) -> dict:
                value = synthetic_manifest()
                for entry in value["files"]:
                    if entry["path"] == "Cargo.lock":
                        entry["sha256"] = sha256_file(repo / "Cargo.lock")
                return value

            with patch("ci_catalog_stage.tracked_manifest", side_effect=current_manifest), patch(
                "ci_catalog_stage.cargo_lock_diff", side_effect=cargo_lock_diff
            ), patch("ci_catalog_stage.snapshot_cargo_lock", side_effect=snapshot_cargo_lock), patch(
                "ci_catalog_stage.raw_file_evidence", side_effect=raw_file_evidence
            ), patch.object(StageRecorder, "_sample", synthetic_resource_sample):
                gate = StageRecorder(repo, root / "artifacts", "a" * 40, environment, "linux")
                with self.assertRaisesRegex(RuntimeError, "tracked source drift after"):
                    gate.run("eol", [sys.executable, "-c", "from pathlib import Path; Path('Cargo.lock').write_bytes(b'version = 3\\n')"])
            self.assertEqual((logs / "eol.cargo-lock-working.before.raw").read_bytes(), crlf)
            self.assertEqual((logs / "eol.cargo-lock-working.after.raw").read_bytes(), lf)
            self.assertEqual((logs / "eol.cargo-lock-unstaged.after.patch").read_bytes(), b"")
            receipt = json.loads((logs / "eol.receipt.json").read_text(encoding="utf-8"))
            self.assertNotEqual(
                receipt["cargo_lock_raw_before"]["sha256"],
                receipt["cargo_lock_raw_after"]["sha256"],
            )
            self.assertIn("tracked source drift after", receipt["error"])

    def test_benchmark_eol_only_lock_drift_fails_with_raw_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            crlf, lf = synthetic_eol_lock_repo(repo)
            output = root / "artifacts" / "source.after.json"
            setup_raw = output.parent / "logs" / "setup-pretoolchain.Cargo.lock.raw"
            setup_raw.parent.mkdir(parents=True)
            setup_raw.write_bytes(crlf)
            (repo / "Cargo.lock").write_bytes(lf)
            self.assertEqual(subprocess.check_output(["git", "diff", "--", "Cargo.lock"], cwd=repo), b"")
            manifest = synthetic_manifest()
            for entry in manifest["files"]:
                if entry["path"] == "Cargo.lock":
                    entry["sha256"] = hashlib.sha256(lf).hexdigest()
            argv = ["ci_catalog_source_check.py", "snapshot", "--expected-head", "a" * 40,
                    "--output", str(output), "--generated-root", str(root / "target")]
            with patch.object(source_check, "__file__", str(repo / "scripts" / "ci_catalog_source_check.py")), patch(
                "ci_catalog_stage.raw_file_evidence", side_effect=raw_file_evidence
            ), patch("ci_catalog_source_check.tracked_manifest", return_value=manifest), patch.object(sys, "argv", argv):
                self.assertEqual(source_check.main(), 1)
            after = json.loads(output.read_text(encoding="utf-8"))
            raw_evidence = after["diagnostics"]["cargo_lock_raw"]
            self.assertEqual(Path(raw_evidence["artifact"]).read_bytes(), lf)
            self.assertEqual(after["diagnostics"]["cargo_lock_unstaged_diff"]["bytes"], 0)
            self.assertIn("Cargo.lock raw bytes changed since pretoolchain setup", check(None, after))

    def test_windows_stage_waits_for_job_assignment_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            marker = repo / "stage-started.txt"
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))

            def assign(_process) -> int:
                time.sleep(0.15)
                self.assertFalse(marker.exists(), "stage ran before Job Object assignment")
                return 123

            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ), patch.object(StageRecorder, "_windows_job", side_effect=assign), patch.object(
                StageRecorder, "_close_windows_job"
            ), patch.object(
                StageRecorder, "_owned_tree_alive", return_value=False
            ):
                gate = StageRecorder(repo, root / "artifacts", "a" * 40, environment, "windows")
                gate.run("assigned", [sys.executable, "-c", "from pathlib import Path; Path('stage-started.txt').write_text('ran')"])
            self.assertEqual(marker.read_text(encoding="utf-8"), "ran")
            receipt = json.loads((gate.logs / "assigned.receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["exit_code"], 0)

    def test_windows_job_assignment_failure_never_launches_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            marker = repo / "must-not-start.txt"
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ), patch.object(
                StageRecorder, "_windows_job", side_effect=RuntimeError("synthetic job assignment refused")
            ):
                gate = StageRecorder(repo, root / "artifacts", "a" * 40, environment, "windows")
                with self.assertRaisesRegex(RuntimeError, "synthetic job assignment refused"):
                    gate.run("refused", [sys.executable, "-c", "from pathlib import Path; Path('must-not-start.txt').write_text('bad')"])
            self.assertFalse(marker.exists())
            receipt = json.loads((gate.logs / "refused.receipt.json").read_text(encoding="utf-8"))
            self.assertIn("synthetic job assignment refused", receipt["error"])
            self.assertTrue((gate.logs / "refused.raw.log").is_file())
            self.assertFalse(receipt["raw_log_complete"])

    def test_benchmark_lock_mutation_preserves_after_snapshot_and_complete_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            synthetic_lock_repo(repo)
            (repo / "Cargo.lock").write_bytes(b"y\n")
            output = root / "artifacts" / "source.after.json"
            setup_raw = output.parent / "logs" / "setup-pretoolchain.Cargo.lock.raw"
            setup_raw.parent.mkdir(parents=True)
            setup_raw.write_bytes(b"x\n")
            argv = [
                "ci_catalog_source_check.py", "snapshot", "--expected-head", "a" * 40,
                "--output", str(output), "--generated-root", str(root / "target"),
            ]
            with patch.object(source_check, "__file__", str(repo / "scripts" / "ci_catalog_source_check.py")), patch(
                "ci_catalog_stage.raw_file_evidence", side_effect=raw_file_evidence
            ), patch(
                "ci_catalog_source_check.tracked_manifest",
                side_effect=RuntimeError("working bytes do not normalize to committed HEAD blob: Cargo.lock"),
            ), patch.object(sys, "argv", argv):
                self.assertEqual(source_check.main(), 1)
            after = json.loads(output.read_text(encoding="utf-8"))
            patch_path = output.parent / "cargo-lock-unstaged.snapshot.patch"
            patch_bytes = patch_path.read_bytes()
            self.assertIn(b"-x", patch_bytes)
            self.assertIn(b"+y", patch_bytes)
            self.assertEqual(after["diagnostics"]["cargo_lock_unstaged_diff"]["sha256"], hashlib.sha256(patch_bytes).hexdigest())
            self.assertIn("Cargo.lock", after["manifest_error"])

    def test_benchmark_lockfile_content_diagnostic_is_bounded_and_hashed(self) -> None:
        raw = b"diff --git a/Cargo.lock b/Cargo.lock\n" + b"x" * (MAX_LOCK_DIFF_BYTES + 1)
        with tempfile.TemporaryDirectory() as temporary, patch(
            "ci_catalog_source_check.subprocess.check_output", return_value=raw
        ) as command:
            artifact = Path(temporary) / "cargo-lock.patch"
            diagnostic = cargo_lock_diff(Path("."), staged=False, artifact=artifact)
            self.assertEqual(artifact.read_bytes(), raw)
            self.assertEqual(diagnostic["artifact"], str(artifact))
        self.assertEqual(diagnostic["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(diagnostic["bytes"], len(raw))
        self.assertTrue(diagnostic["truncated"])
        self.assertEqual(len(diagnostic["prefix"]), MAX_LOCK_DIFF_BYTES)
        self.assertEqual(command.call_args.args[0][-2:], ["--", "Cargo.lock"])

    def test_result_requires_exact_stage_roster_before_result_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ):
                gate = StageRecorder(repo, root, "a" * 40, environment, "linux")
                gate.run("first", [sys.executable, "-c", "print('done')"])
                with self.assertRaisesRegex(RuntimeError, "stage roster mismatch"):
                    gate.finish({"stages": ["first"]}, expected_stages=("first", "second"))
            self.assertFalse((gate.logs / "result.json").exists())

    def test_hosted_toolchain_requires_exact_rust_199(self) -> None:
        from ci_catalog_platform_gate import assert_rust_version

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "version.raw.log"
            path.write_text(
                "rustc 1.99.0 (b940084d7 2026-09-28)\n"
                "binary: rustc\n"
                "commit-hash: b940084d7eb6a299eb4bfeb8e34901bc051e7ac4\n"
                "commit-date: 2026-09-28\n"
                "host: x86_64-unknown-linux-gnu\n"
                "release: 1.99.0\n"
                "LLVM version: 23.1.1\n", encoding="utf-8",
            )
            assert_rust_version(path, "rustc")
            path.write_text("rustc 1.99.0 (candidate)\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expected rustc 1.99.0"):
                assert_rust_version(path, "rustc")
            path.write_text("rustc 1.98.2 (old)\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expected rustc 1.99.0"):
                assert_rust_version(path, "rustc")

    def test_resource_guard_samples_separate_cargo_home_volume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()):
                gate = StageRecorder(repo, root, "a" * 40, environment, "linux")
            disk = lambda free: SimpleNamespace(total=20 * 1024**3, free=free)
            guard = {"disk": 1024**3, "toolchain_disk": 1024**3, "ram": 1024**3, "violation": None}
            samples = []
            with patch("ci_catalog_stage.shutil.disk_usage", side_effect=[
                disk(10 * 1024**3), disk(512 * 1024**2), disk(10 * 1024**3),
            ]), patch("ci_catalog_stage.available_memory", return_value=(8 * 1024**3, 4 * 1024**3)):
                gate._sample("volume", samples, guard, threading.Lock())
            self.assertIn("Cargo-home", guard["violation"])
            self.assertEqual(samples[0]["cargo_home_disk_free_bytes"], 512 * 1024**2)

    def test_generated_artifact_roots_cannot_be_inside_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "outside tracked checkout"):
                generated_roots(repo, [str(repo / "target")])
            self.assertEqual(generated_roots(repo, [str(repo.parent / "other-target")]), [
                str((repo.parent / "other-target").resolve())
            ])

    def test_unlisted_environment_variables_are_redacted(self) -> None:
        environment = effective_environment(
            {"CARGO_TARGET_DIR": "/tmp/target", "MY_PAT": "sensitive-one", "DEPLOY_CRED": "sensitive-two"}
        )
        self.assertEqual(environment["CARGO_TARGET_DIR"], "/tmp/target")
        self.assertEqual(environment["MY_PAT"], "[REDACTED]")
        self.assertEqual(environment["DEPLOY_CRED"], "[REDACTED]")

    def test_pre_stage_drift_writes_failure_receipt_and_raw_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            expected_head = "a" * 40
            calls = 0

            def manifest(_repo):
                nonlocal calls
                calls += 1
                return synthetic_manifest(expected_head) if calls == 1 else synthetic_manifest(
                    expected_head, status=" M Cargo.lock", digest="d" * 64
                )

            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", side_effect=manifest):
                gate = StageRecorder(repo, root, expected_head, environment, "linux")
                with self.assertRaisesRegex(RuntimeError, "stage drift failed"):
                    gate.run("drift", [sys.executable, "-c", "print('must not run')"])
            self.assertTrue((gate.logs / "drift.raw.log").is_file())
            receipt = json.loads((gate.logs / "drift.receipt.json").read_text(encoding="utf-8"))
            self.assertIsNone(receipt["exit_code"])
            self.assertIn("tracked source drift before", receipt["error"])

    def test_dirty_setup_writes_diagnostic_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest(status=" M Cargo.lock")):
                with self.assertRaisesRegex(RuntimeError, "clean exact event head"):
                    StageRecorder(repo, root, "a" * 40, environment, "linux")
            diagnostic = json.loads((root / "logs" / "setup-failure.json").read_text(encoding="utf-8"))
            self.assertEqual(diagnostic["expected_head"], "a" * 40)
            self.assertIn("clean exact event head", diagnostic["error"])
            self.assertIn("cargo_lock_unstaged_diff", diagnostic)

    def test_pre_gate_setup_deadline_writes_failure_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            environment = os.environ.copy()
            environment.update(
                P80_SETUP_START_UTC=(datetime.now(timezone.utc) - timedelta(minutes=76)).isoformat(),
                CARGO_TARGET_DIR=str(root / "target"),
                PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"),
            )
            with self.assertRaisesRegex(RuntimeError, "upload margin"):
                StageRecorder(repo, root / "artifacts", "a" * 40, environment, "linux")
            diagnostic = json.loads((root / "artifacts" / "logs" / "setup-failure.json").read_text(encoding="utf-8"))
            self.assertIn("upload margin", diagnostic["error"])

    def test_cleanup_exception_still_writes_receipt(self) -> None:
        class BrokenProcess:
            stdout = io.BufferedReader(io.BytesIO(b""))
            pid = 456789

            def poll(self):
                return 0

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("synthetic", timeout or 1)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            expected_head = "a" * 40
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ), patch("ci_catalog_stage.subprocess.Popen", return_value=BrokenProcess()), patch.object(
                StageRecorder, "_terminate_tree", side_effect=OSError("synthetic cleanup failure")
            ):
                gate = StageRecorder(repo, root, expected_head, environment, "linux")
                with self.assertRaisesRegex(RuntimeError, "stage cleanup failed"):
                    gate.run("cleanup", ["synthetic"])
            receipt = json.loads((gate.logs / "cleanup.receipt.json").read_text(encoding="utf-8"))
            self.assertIn("synthetic cleanup failure", receipt["error"])
            self.assertTrue((gate.logs / "cleanup.raw.log").is_file())

    def test_stage_has_wall_clock_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            marker = root / "timeout-child.pid"
            expected_head = "a" * 40
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ):
                gate = StageRecorder(repo, root, expected_head, environment, "linux")
                start = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "stage timeout failed"):
                    gate.run("timeout", [
                        sys.executable, "-c",
                        "import os,sys,time; from pathlib import Path; "
                        "Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)",
                        str(marker),
                    ], timeout_seconds=2)
                self.assertLess(time.monotonic() - start, 8, "timeout cleanup must remain bounded")
            self.assertTrue(marker.is_file(), "child must start before timeout")
            self.assert_pid_exited(int(marker.read_text(encoding="utf-8")))
            receipt = json.loads((gate.logs / "timeout.receipt.json").read_text(encoding="utf-8"))
            self.assertIn("timeout", receipt["error"])
            self.assertTrue(receipt["raw_log_complete"])
            self.assertFalse(receipt["reader_alive_at_receipt"])

    def test_linux_proc_group_ignores_zombies_but_keeps_live_members(self) -> None:
        def stat(pid: int, group: int, state: str) -> str:
            return f"{pid} (nested ) command) {state} 1 {group} {group} 0 0\n"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for pid, group, state in ((101, 900, "Z"), (102, 900, "X"), (103, 901, "S")):
                child = root / str(pid)
                child.mkdir()
                (child / "stat").write_text(stat(pid, group, state), encoding="ascii")
            unrelated = root / "105"
            unrelated.mkdir()
            (unrelated / "stat").write_bytes(b"105 (non-\xff-ascii) S 1 901 901 0 0\n")
            self.assertEqual(StageRecorder._linux_group_live_pids(900, root), [])
            live = root / "104"
            live.mkdir()
            (live / "stat").write_text(stat(104, 900, "S"), encoding="ascii")
            self.assertEqual(StageRecorder._linux_group_live_pids(900, root), [104])
            (live / "stat").write_text(stat(104, 900, "?"), encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "unknown .* state"):
                StageRecorder._linux_group_live_pids(900, root)
            with patch.object(Path, "read_bytes", side_effect=PermissionError("synthetic inaccessible stat")):
                with self.assertRaises(PermissionError):
                    StageRecorder._linux_group_live_pids(900, root)

    def test_linux_cleanup_reaps_exited_leader_without_zombie_delay(self) -> None:
        if os.name != "posix" or not Path("/proc").is_dir():
            self.skipTest("Linux /proc process groups required")
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        try:
            start = time.monotonic()
            StageRecorder._terminate_tree(process)
            self.assertLess(time.monotonic() - start, 3, "zombie leader must not exhaust both polls")
            self.assertIsNotNone(process.poll())
            self.assertFalse(StageRecorder._owned_tree_alive(process, None))
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)

    def test_windows_transient_descendants_quiesce_with_and_without_pipe(self) -> None:
        if os.name != "nt":
            self.skipTest("native Windows Job Object required")
        for pipe in (True, False):
            with self.subTest(pipe=pipe), tempfile.TemporaryDirectory() as temporary:
                output = "sys.stdout" if pipe else "subprocess.DEVNULL"
                child = (
                    "import subprocess,sys; "
                    "subprocess.Popen([sys.executable,'-c','import time; time.sleep(0.8)'], "
                    f"stdin=subprocess.DEVNULL,stdout={output},stderr={output}); "
                    "print('leader exited', flush=True)"
                )
                root = Path(temporary)
                repo = root / "repo"
                repo.mkdir()
                environment = os.environ.copy()
                environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
                with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                    StageRecorder, "_sample", synthetic_resource_sample
                ):
                    gate = StageRecorder(repo, root / "artifacts", "a" * 40, environment, "windows")
                    gate.run("transient", [sys.executable, "-c", child], timeout_seconds=5)
                receipt = json.loads((gate.logs / "transient.receipt.json").read_text(encoding="utf-8"))
                self.assertEqual(receipt["exit_code"], 0)
                self.assertIsNone(receipt["error"])
                self.assertTrue(receipt["raw_log_complete"])
                self.assertEqual(receipt["post_leader_quiescence_budget_seconds"], 5)
                self.assertIsNotNone(receipt["post_leader_quiescence_seconds"])

    def test_windows_job_pid_query_retries_successful_partial_list(self) -> None:
        class PartialQuery:
            calls = 0

            def __call__(self, _job, _kind, buffer, _size, _returned):
                self.calls += 1
                ctypes.c_ulong.from_buffer(buffer, 0).value = 2
                ctypes.c_ulong.from_buffer(buffer, 4).value = 1 if self.calls == 1 else 2
                ctypes.c_size_t.from_buffer(buffer, 8).value = 1001
                if self.calls > 1:
                    ctypes.c_size_t.from_buffer(buffer, 8 + ctypes.sizeof(ctypes.c_size_t)).value = 1002
                return 1

        query = PartialQuery()
        kernel = SimpleNamespace(QueryInformationJobObject=query, GetLastError=lambda: 0)
        with patch("ci_catalog_stage.ctypes.windll", SimpleNamespace(kernel32=kernel), create=True):
            self.assertEqual(StageRecorder._windows_job_pids(123), [1001, 1002])
        self.assertEqual(query.calls, 2)

    def test_windows_persistent_pipe_holder_fails_and_job_kills_member(self) -> None:
        if os.name != "nt":
            self.skipTest("native Windows Job Object required")
        child = (
            "import subprocess,sys,pathlib; "
            "member=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'], "
            "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr); "
            "pathlib.Path('survivor.pid').write_text(str(member.pid)); "
            "print('leader exited', flush=True)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ):
                gate = StageRecorder(repo, root / "artifacts", "a" * 40, environment, "windows")
                start = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "surviving descendant"):
                    gate.run("persistent", [sys.executable, "-c", child], timeout_seconds=15)
                self.assertLess(time.monotonic() - start, 12, "inherited pipe must not wait for stage deadline")
            member_pid = int((repo / "survivor.pid").read_text(encoding="utf-8"))
            receipt = json.loads((gate.logs / "persistent.receipt.json").read_text(encoding="utf-8"))
            self.assertIn(str(member_pid), receipt["error"])
            self.assertIn(member_pid, receipt["surviving_job_pids"])
            self.assertEqual(receipt["post_leader_quiescence_budget_seconds"], 5)
            details = [item for item in receipt["surviving_job_members"] if item["pid"] == member_pid]
            self.assertEqual(len(details), 1)
            self.assertTrue(details[0]["image_name"] or details[0]["name_lookup_error"])
            self.assertGreaterEqual(receipt["post_leader_quiescence_seconds"], 5)
            self.assertFalse(receipt["reader_alive_at_receipt"])
            self.assertTrue(receipt["raw_log_complete"])
            self.assert_pid_exited(member_pid)

    def test_soft_overall_deadline_interrupts_stage_before_job_hard_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ):
                gate = StageRecorder(repo, root, "a" * 40, environment, "linux")
                gate.soft_job_deadline = time.monotonic() + 0.2
                with self.assertRaisesRegex(RuntimeError, "soft overall job deadline"):
                    gate.run("soft", [sys.executable, "-c", "import time; time.sleep(3)"])
            receipt = json.loads((gate.logs / "soft.receipt.json").read_text(encoding="utf-8"))
            self.assertTrue(receipt["child_started"])
            self.assertIn("soft overall job deadline", receipt["error"])
            self.assertTrue(receipt["raw_log_complete"])

    def test_failed_child_drains_buffered_output_before_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ):
                gate = StageRecorder(repo, root, "a" * 40, environment, "linux")
                with self.assertRaisesRegex(RuntimeError, "command exited 7"):
                    gate.run("failing", [
                        sys.executable, "-c",
                        "import sys; sys.stdout.buffer.write(b'out'); "
                        "sys.stderr.buffer.write(b'err'); sys.exit(7)",
                    ])
            raw = (gate.logs / "failing.raw.log").read_bytes()
            self.assertIn(b"err", raw)
            self.assertIn(b"out", raw)
            receipt = json.loads((gate.logs / "failing.receipt.json").read_text(encoding="utf-8"))
            self.assertTrue(receipt["raw_log_complete"])
            self.assertEqual(receipt["raw_log_sha256"], hashlib.sha256(raw).hexdigest())

    def test_leaderless_descendant_cannot_hold_stage_pipe_forever(self) -> None:
        child = (
            "import subprocess,sys,pathlib; "
            "member=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)'], "
            "stdout=sys.stdout, stderr=sys.stderr); "
            "pathlib.Path(sys.argv[1]).write_text(str(member.pid)); print('leader exited', flush=True)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            marker = root / "descendant-child.pid"
            expected_head = "a" * 40
            environment = os.environ.copy()
            environment.update(CARGO_TARGET_DIR=str(root / "target"), PRAXOR_TEST_TMP_ROOT=str(root / "fixtures"), TEMP=str(root / "tmp"))
            platform = "windows" if os.name == "nt" else "linux"
            with patch("ci_catalog_stage.tracked_manifest", return_value=synthetic_manifest()), patch.object(
                StageRecorder, "_sample", synthetic_resource_sample
            ):
                gate = StageRecorder(repo, root, expected_head, environment, platform)
                start = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "stage descendant failed"):
                    gate.run("descendant", [sys.executable, "-c", child, str(marker)], timeout_seconds=3)
                self.assertLess(time.monotonic() - start, 12, "descendant cleanup must remain bounded")
            self.assert_pid_exited(int(marker.read_text(encoding="utf-8")))
            receipt = json.loads((gate.logs / "descendant.receipt.json").read_text(encoding="utf-8"))
            self.assertIn("wall-clock timeout", receipt["error"])
            self.assertFalse(receipt["reader_alive_at_receipt"])
            self.assertTrue(receipt["raw_log_complete"])

    def test_workflow_provenance_rejects_different_executed_yaml(self) -> None:
        from ci_catalog_stage import verify_workflow_provenance

        expected_head = "a" * 40
        workflow_sha = "d" * 40
        environment = {
            "GITHUB_REPOSITORY": "Astraive/praxor",
            "GITHUB_WORKFLOW_REF": "Astraive/praxor/.github/workflows/ci.yml@refs/pull/87/merge",
            "GITHUB_WORKFLOW_SHA": workflow_sha,
            "GITHUB_EVENT_NAME": "pull_request",
        }

        def git_output(argv, **_kwargs):
            if argv[-1] == "FETCH_HEAD":
                return workflow_sha + "\n"
            if argv[-1] == "HEAD:.github/workflows/ci.yml":
                return "head-blob\n"
            if argv[-1] == f"{workflow_sha}:.github/workflows/ci.yml":
                return "different-blob\n"
            if argv[-1] == "HEAD":
                return expected_head + "\n"
            raise AssertionError(argv)

        with patch("ci_catalog_stage.subprocess.run"), patch(
            "ci_catalog_stage.subprocess.check_output", side_effect=git_output
        ):
            with self.assertRaisesRegex(RuntimeError, "executed workflow blob"):
                verify_workflow_provenance(Path("."), expected_head, environment)

    def test_tracked_manifest_rejects_hidden_index_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "file").write_text("content", encoding="utf-8")
            blob = "b" * 40

            def git_output(argv, **_kwargs):
                if argv[1:3] == ["ls-files", "--cached"]:
                    return b"file\0"
                if argv[1:3] == ["ls-files", "--stage"]:
                    return f"100644 {blob} 0\tfile\0".encode()
                if argv[1:3] == ["ls-files", "-v"]:
                    return b"S file\0"
                if argv[1:3] == ["ls-tree", "-r"]:
                    return f"100644 blob {blob}\tfile\0".encode()
                if argv[1:3] == ["rev-parse", "HEAD"]:
                    return "a" * 40 + "\n"
                if argv[1:3] == ["rev-parse", "HEAD^{tree}"]:
                    return "c" * 40 + "\n"
                if argv[1:3] == ["status", "--porcelain"]:
                    return ""
                raise AssertionError(argv)

            with patch("ci_catalog_stage.REQUIRED_SOURCE", set()), patch(
                "ci_catalog_stage.subprocess.check_output", side_effect=git_output
            ):
                with self.assertRaisesRegex(RuntimeError, "index flag"):
                    tracked_manifest(repo)

    def test_tracked_path_rejects_aliased_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            real = repo / "real"
            real.mkdir()
            (real / "file.txt").write_text("data", encoding="utf-8")
            link = repo / "alias"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "symlink/reparse ancestor"):
                assert_unaliased_tracked_path(repo, "alias/file.txt")
            with self.assertRaisesRegex(RuntimeError, "unsafe tracked path"):
                assert_unaliased_tracked_path(repo, "../outside")

    def test_eol_attribute_inventory_and_blob_normalization(self) -> None:
        eol_raw = (
            b"i/lf    w/crlf  attr/                  \tCargo.lock\0"
            b"i/lf    w/lf    attr/text eol=lf       \tscript.sh\0"
        )
        attrs_raw = b"script.sh\0text\0set\0script.sh\0eol\0lf\0"

        def git_output(argv, **_kwargs):
            if argv[1:3] == ["ls-files", "--eol"]:
                return eol_raw
            if argv[1:3] == ["check-attr", "--stdin"]:
                return attrs_raw
            raise AssertionError(argv)

        with patch("ci_catalog_stage.subprocess.check_output", side_effect=git_output):
            evidence = git_eol_and_attributes(Path("."), ["Cargo.lock", "script.sh"])
        self.assertEqual(evidence["Cargo.lock"]["working_eol"], "crlf")
        self.assertEqual(evidence["script.sh"]["attributes"], {"text": "set", "eol": "lf"})
        raw = b"line one\r\nline two\r\n"
        blob, transform = canonical_working_blob(raw, evidence["Cargo.lock"])
        canonical = b"line one\nline two\n"
        self.assertEqual(blob, hashlib.sha1(b"blob 18\0" + canonical).hexdigest())
        self.assertEqual(transform, "crlf-to-lf")
        binary = {"index_eol": "-text", "working_eol": "-text"}
        binary_blob, binary_transform = canonical_working_blob(raw, binary)
        self.assertEqual(binary_blob, hashlib.sha1(b"blob 20\0" + raw).hexdigest())
        self.assertEqual(binary_transform, "identity")

    def test_content_filter_attribute_is_rejected(self) -> None:
        eol_raw = b"i/lf    w/lf    attr/                  \tCargo.lock\0"
        attrs_raw = b"Cargo.lock\0filter\0custom\0"
        with patch("ci_catalog_stage.subprocess.check_output", side_effect=[eol_raw, attrs_raw]):
            with self.assertRaisesRegex(RuntimeError, "content-transform attribute"):
                git_eol_and_attributes(Path("."), ["Cargo.lock"])


if __name__ == "__main__":
    unittest.main()
