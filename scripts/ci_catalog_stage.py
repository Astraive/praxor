"""Frozen-source, byte-preserving command receipts for hosted catalog gates."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import ntpath
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


GIB = 1024**3
WINDOWS_JOB_QUIESCENCE_SECONDS = 5
WINDOWS_VCTIP_QUIESCENCE_SECONDS = 60
MAX_LOCK_DIFF_BYTES = 16 * 1024
SAFE_ENVIRONMENT_KEYS = frozenset(
    {
        "CARGO_BUILD_JOBS", "CARGO_HOME", "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG",
        "CARGO_PROFILE_TEST_DEBUG", "CARGO_TARGET_DIR", "CARGO_TERM_COLOR", "CI",
        "CRITERION_HOME",
        "EXPECTED_HEAD", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_REPOSITORY",
        "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_ID", "GITHUB_SHA", "GITHUB_WORKFLOW",
        "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "ImageOS", "ImageVersion",
        "PATH", "P80_SETUP_START_UTC", "P80_SOFT_JOB_MINUTES", "PRAXOR_TEST_TMP_ROOT", "PYTHONDONTWRITEBYTECODE", "RUNNER_ARCH",
        "RUNNER_OS", "RUNNER_TEMP", "RUST_BACKTRACE", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN",
        "TEMP", "TMP", "TMPDIR",
    }
)
REQUIRED_SOURCE = {
    "Cargo.lock",
    ".github/workflows/ci.yml",
    "scripts/ci_catalog_evidence.py",
    "scripts/ci_catalog_aux_gate.py",
    "scripts/ci_catalog_platform_gate.py",
    "scripts/ci_catalog_source_check.py",
    "scripts/ci_catalog_stage.py",
    "scripts/ci_catalog_windows_wrapper.py",
    "scripts/test_ci_catalog_evidence.py",
    "scripts/test_ci_catalog_aux_gate.py",
    "scripts/test_ci_catalog_stage.py",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def install_termination_handler() -> None:
    """Turn first runner SIGTERM into a stage failure with bounded cleanup."""
    requested = False

    def on_terminate(signum: int, _frame: object) -> None:
        nonlocal requested
        if requested:
            return
        requested = True
        raise InterruptedError(f"received runner signal {signum}")

    signal.signal(signal.SIGTERM, on_terminate)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def raw_file_evidence(path: Path) -> dict:
    """Record a stable, byte-preserving artifact without Git's EOL conversion."""
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"raw source artifact is missing or aliased: {path}")
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if identity(before) != identity(after):
        raise RuntimeError(f"raw source artifact changed while reading: {path}")
    return {"artifact": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def snapshot_cargo_lock(repo: Path, artifact: Path) -> dict:
    if artifact.resolve().is_relative_to(repo.resolve()):
        raise RuntimeError("Cargo.lock raw snapshot must be outside checkout")
    source = repo / "Cargo.lock"
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("Cargo.lock is missing or aliased")
    before = source.stat()
    raw = source.read_bytes()
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(raw)
    after = source.stat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if identity(before) != identity(after):
        raise RuntimeError("Cargo.lock changed while creating raw snapshot")
    if sha256_file(source) != hashlib.sha256(raw).hexdigest():
        raise RuntimeError("Cargo.lock bytes changed after creating raw snapshot")
    evidence = raw_file_evidence(artifact)
    if evidence["sha256"] != hashlib.sha256(raw).hexdigest() or evidence["bytes"] != len(raw):
        raise RuntimeError("Cargo.lock raw snapshot differs from bytes read")
    return evidence


def cargo_lock_diff(repo: Path, *, staged: bool, artifact: Path | None = None) -> dict:
    argv = ["git", "diff", "--no-ext-diff", "--no-textconv"]
    if staged:
        argv.append("--cached")
    argv.extend(["--", "Cargo.lock"])
    raw = subprocess.check_output(argv, cwd=repo, timeout=15)
    if artifact is not None:
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(raw)
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "truncated": len(raw) > MAX_LOCK_DIFF_BYTES,
        "prefix": raw[:MAX_LOCK_DIFF_BYTES].decode("utf-8", errors="replace"),
        "artifact": str(artifact) if artifact is not None else None,
    }


def checkout_untracked_paths(repo: Path) -> dict[str, list[str]]:
    """Inventory both ordinary and Git-ignored untracked checkout files."""
    result: dict[str, list[str]] = {}
    for label, args in (
        ("untracked_paths", ["git", "ls-files", "--others", "--exclude-standard", "-z"]),
        ("ignored_untracked_paths", ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z"]),
    ):
        raw = subprocess.check_output(args, cwd=repo, timeout=30)
        result[label] = sorted(os.fsdecode(item).replace("\\", "/") for item in raw.split(b"\0") if item)
    return result


def checkout_status(repo: Path) -> str:
    return subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo, text=True, timeout=30,
    )


def assert_unaliased_tracked_path(repo: Path, name: str) -> Path:
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"unsafe tracked path: {name}")
    current = repo
    for part in relative.parts:
        current = current / part
        info = current.lstat()
        if (
            current.is_symlink()
            or getattr(current, "is_junction", lambda: False)()
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise RuntimeError(f"tracked path has symlink/reparse ancestor: {name}")
    return current


def git_eol_and_attributes(repo: Path, names: list[str]) -> dict[str, dict]:
    eol_raw = subprocess.check_output(["git", "ls-files", "--eol", "-z"], cwd=repo, timeout=30)
    eol: dict[str, tuple[str, str, str]] = {}
    pattern = re.compile(r"^i/(?P<index>\S+)\s+w/(?P<work>\S+)\s+attr/(?P<attr>.*?)\s*$")
    for record in eol_raw.split(b"\0"):
        if not record:
            continue
        metadata, tab, filename = record.partition(b"\t")
        match = pattern.fullmatch(os.fsdecode(metadata))
        if not tab or match is None:
            raise RuntimeError("malformed tracked Git EOL record")
        name = os.fsdecode(filename).replace("\\", "/")
        if name in eol:
            raise RuntimeError(f"duplicate tracked Git EOL path: {name}")
        eol[name] = (match["index"], match["work"], match["attr"])
    if set(eol) != set(names):
        raise RuntimeError("Git EOL path inventory differs from tracked index")

    input_bytes = b"\0".join(os.fsencode(name) for name in names) + b"\0"
    attributes_raw = subprocess.check_output(
        ["git", "check-attr", "--stdin", "-z", "-a"], cwd=repo,
        input=input_bytes, timeout=30,
    )
    fields = attributes_raw.split(b"\0")
    if fields[-1:] == [b""]:
        fields.pop()
    if len(fields) % 3:
        raise RuntimeError("malformed Git attribute triplets")
    attributes: dict[str, dict[str, str]] = {name: {} for name in names}
    for offset in range(0, len(fields), 3):
        name, attribute, value = (os.fsdecode(item).replace("\\", "/") for item in fields[offset:offset + 3])
        if name not in attributes or attribute in attributes[name]:
            raise RuntimeError(f"unexpected or duplicate Git attribute: {name}/{attribute}")
        attributes[name][attribute] = value

    evidence = {}
    for name in names:
        index_eol, work_eol, listed_attributes = eol[name]
        current = attributes[name]
        if current.get("filter") is not None or current.get("working-tree-encoding") is not None or current.get("ident") is not None:
            raise RuntimeError(f"unreviewed content-transform attribute: {name}")
        if current.get("eol") not in (None, "lf") or current.get("text") not in (None, "set", "auto"):
            raise RuntimeError(f"unreviewed text/EOL attribute: {name}")
        allowed = (
            (index_eol == "lf" and work_eol in {"lf", "crlf"})
            or (index_eol == "-text" and work_eol == "-text")
            or (index_eol == "none" and work_eol == "none")
        )
        if not allowed or (current.get("eol") == "lf" and work_eol != "lf"):
            raise RuntimeError(f"unreviewed index/working EOL mode: {name}: i/{index_eol} w/{work_eol}")
        evidence[name] = {
            "index_eol": index_eol, "working_eol": work_eol,
            "listed_attribute_eol": listed_attributes, "attributes": current,
        }
    return evidence


def canonical_working_blob(raw: bytes, eol: dict) -> tuple[str, str]:
    index_eol, work_eol = eol["index_eol"], eol["working_eol"]
    if index_eol == "lf" and work_eol == "crlf":
        canonical = raw.replace(b"\r\n", b"\n")
        transform = "crlf-to-lf"
    elif (index_eol, work_eol) in {("lf", "lf"), ("-text", "-text"), ("none", "none")}:
        canonical = raw
        transform = "identity"
    else:
        raise RuntimeError(f"unreviewed working-byte transform: i/{index_eol} w/{work_eol}")
    header = f"blob {len(canonical)}\0".encode("ascii")
    return hashlib.sha1(header + canonical).hexdigest(), transform


def git_conversion_config(repo: Path) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    allowed = {
        "core.autocrlf": {None, "true", "false", "input"},
        "core.eol": {None, "lf", "crlf", "native"},
    }
    for key, accepted in allowed.items():
        command = subprocess.run(
            ["git", "config", "--get", key], cwd=repo,
            capture_output=True, text=True, timeout=15,
        )
        if command.returncode == 0:
            value = command.stdout.strip().lower()
        elif command.returncode == 1:
            value = None
        else:
            raise RuntimeError(f"cannot read {key}: {command.stderr.strip()}")
        if value not in accepted:
            raise RuntimeError(f"unreviewed Git conversion config {key}={value!r}")
        values[key] = value
    return values


def tracked_manifest(repo: Path) -> dict:
    indexed = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=repo)
    committed = subprocess.check_output(["git", "ls-tree", "-r", "-z", "HEAD"], cwd=repo)
    flags = subprocess.check_output(["git", "ls-files", "-v", "-z"], cwd=repo)

    def records(raw: bytes, label: str) -> dict[str, tuple[str, ...]]:
        parsed = {}
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, filename = record.partition(b"\t")
            if not separator:
                raise RuntimeError(f"malformed {label} record")
            path = os.fsdecode(filename).replace("\\", "/")
            if path in parsed:
                raise RuntimeError(f"duplicate {label} path: {path}")
            parsed[path] = tuple(os.fsdecode(part) for part in metadata.split())
        return parsed

    index = records(indexed, "index")
    head = records(committed, "HEAD tree")
    flag_map = {}
    for record in flags.split(b"\0"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" ":
            raise RuntimeError("malformed Git index flag record")
        name = os.fsdecode(record[2:]).replace("\\", "/")
        if name in flag_map:
            raise RuntimeError(f"duplicate index flag path: {name}")
        flag_map[name] = os.fsdecode(record[:1])
    if index.keys() != head.keys() or index.keys() != flag_map.keys():
        raise RuntimeError("tracked index paths differ from committed HEAD tree or index flags")
    for name in index:
        if flag_map[name] != "H":
            raise RuntimeError(f"unsupported index flag for tracked path {name}: {flag_map[name]}")
        index_mode, index_blob, stage = index[name]
        head_mode, kind, head_blob = head[name]
        if stage != "0" or kind != "blob" or index_mode not in {"100644", "100755"}:
            raise RuntimeError(f"unsupported tracked index entry: {name}")
        if (index_mode, index_blob) != (head_mode, head_blob):
            raise RuntimeError(f"index mode/blob differs from committed HEAD: {name}")

    names = sorted(index)
    eol_evidence = git_eol_and_attributes(repo, names)
    files: list[dict] = []
    for name in names:
        path = assert_unaliased_tracked_path(repo, name)
        if not path.is_file():
            raise RuntimeError(f"tracked file is missing or unsupported: {name}")
        before = path.stat()
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        canonical_blob, transform = canonical_working_blob(raw, eol_evidence[name])
        after = path.stat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        if identity(before) != identity(after):
            raise RuntimeError(f"tracked file changed during hash: {name}")
        if len(head[name][2]) != 40 or canonical_blob != head[name][2]:
            raise RuntimeError(f"working bytes do not normalize to committed HEAD blob: {name}")
        files.append(
            {
                "path": name, "kind": "file", "mode": index[name][0],
                "head_blob": head[name][2], "index_blob": index[name][1],
                "index_flag": flag_map[name], "size": after.st_size, "sha256": digest,
                "git_eol": eol_evidence[name],
                "canonical_working_blob": canonical_blob, "canonical_transform": transform,
            }
        )
    actual = {entry["path"] for entry in files}
    missing = sorted(REQUIRED_SOURCE - actual)
    if missing:
        raise RuntimeError(f"committed gate inputs missing from tracked checkout: {missing}")
    digest = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True)
    return {
        "head": head, "tree": tree, "tracked_status": status,
        **checkout_untracked_paths(repo),
        "git_conversion_config": git_conversion_config(repo),
        "files_sha256": digest, "files": files,
    }


def effective_environment(environment: dict[str, str]) -> dict[str, str]:
    return {
        key: value if key in SAFE_ENVIRONMENT_KEYS else "[REDACTED]"
        for key, value in sorted(environment.items())
    }


def verify_workflow_provenance(repo: Path, expected_head: str, environment: dict[str, str]) -> dict:
    """Compare the GitHub-executed workflow commit's blob with checked-out HEAD."""
    repository = environment["GITHUB_REPOSITORY"]
    workflow_ref = environment["GITHUB_WORKFLOW_REF"]
    workflow_sha = environment["GITHUB_WORKFLOW_SHA"]
    expected_prefix = f"{repository}/.github/workflows/ci.yml@"
    if not workflow_ref.startswith(expected_prefix) or not workflow_ref[len(expected_prefix):]:
        raise RuntimeError(f"unexpected executed workflow ref: {workflow_ref}")
    if not re.fullmatch(r"[0-9a-f]{40}", workflow_sha):
        raise RuntimeError("GITHUB_WORKFLOW_SHA must be a full commit SHA")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    if head != expected_head:
        raise RuntimeError("checkout differs from exact event head during workflow provenance")
    if workflow_sha != head:
        subprocess.run(
            ["git", "-c", "protocol.version=2", "fetch", "--no-tags", "--depth=1", "origin", workflow_sha],
            cwd=repo, check=True, capture_output=True, text=True, timeout=60,
        )
        fetched = subprocess.check_output(["git", "rev-parse", "FETCH_HEAD"], cwd=repo, text=True).strip()
        if fetched != workflow_sha:
            raise RuntimeError("fetched workflow commit differs from runner workflow SHA")
    path = ".github/workflows/ci.yml"
    head_blob = subprocess.check_output(["git", "rev-parse", f"HEAD:{path}"], cwd=repo, text=True).strip()
    executed_blob = subprocess.check_output(
        ["git", "rev-parse", f"{workflow_sha}:{path}"], cwd=repo, text=True
    ).strip()
    if executed_blob != head_blob:
        raise RuntimeError(
            f"executed workflow blob {executed_blob} differs from reviewed HEAD blob {head_blob}"
        )
    result = {
        "workflow_ref": workflow_ref, "workflow_sha": workflow_sha,
        "checkout_head": head, "reviewed_head_workflow_blob": head_blob,
        "executed_workflow_blob": executed_blob,
    }
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


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


class JobAccounting(ctypes.Structure):
    _fields_ = [
        ("total_user_time", ctypes.c_longlong),
        ("total_kernel_time", ctypes.c_longlong),
        ("period_user_time", ctypes.c_longlong),
        ("period_kernel_time", ctypes.c_longlong),
        ("page_faults", ctypes.c_ulong),
        ("total_processes", ctypes.c_ulong),
        ("active_processes", ctypes.c_ulong),
        ("terminated_processes", ctypes.c_ulong),
    ]


class WinFileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class JobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", ctypes.c_ulong),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", ctypes.c_ulong),
        ("affinity", ctypes.c_size_t),
        ("priority_class", ctypes.c_ulong),
        ("scheduling_class", ctypes.c_ulong),
    ]


class JobIoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "read_operation_count", "write_operation_count", "other_operation_count",
        "read_transfer_count", "write_transfer_count", "other_transfer_count",
    )]


class JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", JobBasicLimitInformation),
        ("io_info", JobIoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


def available_memory() -> tuple[int, int]:
    if os.name == "nt":
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise OSError("GlobalMemoryStatusEx failed")
        return status.total_physical, status.available_physical
    values: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        match = re.match(r"^(MemTotal|MemAvailable):\s+(\d+) kB$", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    if set(values) != {"MemTotal", "MemAvailable"}:
        raise RuntimeError("Linux /proc/meminfo lacks total/available memory")
    available = values["MemAvailable"]
    cgroup = Path("/sys/fs/cgroup")
    maximum, current = cgroup / "memory.max", cgroup / "memory.current"
    if maximum.is_file() and current.is_file():
        limit = maximum.read_text(encoding="ascii").strip()
        if limit.isdecimal():
            available = min(available, max(0, int(limit) - int(current.read_text(encoding="ascii"))))
    return values["MemTotal"], available


class StageRecorder:
    def __init__(self, repo: Path, root: Path, expected_head: str, environment: dict[str, str], platform: str):
        if sys.version_info[:2] != (3, 12):
            raise RuntimeError(f"hosted gate requires Python 3.12, got {sys.version.split()[0]}")
        self.repo = repo.resolve()
        self.root = root.resolve()
        self.logs = self.root / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.environment = environment
        self.cargo_home = Path(environment.get("CARGO_HOME") or Path.home() / ".cargo").resolve()
        self.rustup_home = Path(environment.get("RUSTUP_HOME") or Path.home() / ".rustup").resolve()
        self.expected_head = expected_head
        self.platform = platform
        try:
            setup_text = environment["P80_SETUP_START_UTC"]
            self.setup_start_utc = datetime.fromisoformat(setup_text.replace("Z", "+00:00"))
            if self.setup_start_utc.tzinfo is None:
                raise RuntimeError("P80_SETUP_START_UTC must include a UTC offset")
            self.gate_start_utc = datetime.now(timezone.utc)
            self.setup_elapsed_seconds = (self.gate_start_utc - self.setup_start_utc).total_seconds()
            if self.setup_elapsed_seconds < -5:
                raise RuntimeError("setup start timestamp is in the future")
            soft_minutes = int(environment["P80_SOFT_JOB_MINUTES"])
            if soft_minutes not in (70, 100):
                raise RuntimeError(f"unreviewed soft job deadline: {soft_minutes} minutes")
            self.soft_job_minutes = soft_minutes
            # Cap elapsed time from recorded setup start as well as from gate init.
            setup_cap_minutes = 75 if soft_minutes == 70 else 105
            if self.setup_elapsed_seconds >= setup_cap_minutes * 60:
                raise RuntimeError("pre-gate setup exhausted the bounded upload margin")
            self.soft_job_deadline = time.monotonic() + min(
                soft_minutes * 60, setup_cap_minutes * 60 - self.setup_elapsed_seconds,
            )
        except BaseException as exc:
            self._write_json(
                self.logs / "setup-failure.json",
                {"utc": utc_now(), "expected_head": expected_head,
                 "error": str(exc) or type(exc).__name__,
                 "environment_redacted": effective_environment(environment)},
            )
            raise
        self.stages: list[str] = []
        self.pretoolchain_raw_lock: dict | None = None
        self.baseline_raw_lock: dict | None = None
        try:
            self.pretoolchain_raw_lock = raw_file_evidence(
                self.logs / "setup-pretoolchain.Cargo.lock.raw"
            )
            self.baseline_raw_lock = snapshot_cargo_lock(
                self.repo, self.logs / "source-baseline.Cargo.lock.raw"
            )
            if (
                self.pretoolchain_raw_lock["sha256"] != self.baseline_raw_lock["sha256"]
                or self.pretoolchain_raw_lock["bytes"] != self.baseline_raw_lock["bytes"]
            ):
                raise RuntimeError("Cargo.lock raw bytes changed between pretoolchain setup and gate admission")
            self.baseline = tracked_manifest(self.repo)
            lock_entries = [item for item in self.baseline["files"] if item["path"] == "Cargo.lock"]
            if len(lock_entries) != 1 or lock_entries[0]["sha256"] != self.baseline_raw_lock["sha256"]:
                raise RuntimeError("Cargo.lock raw baseline differs from tracked manifest")
            if (
                self.baseline["head"] != expected_head
                or self.baseline["tracked_status"]
                or self.baseline.get("untracked_paths")
                or self.baseline.get("ignored_untracked_paths")
            ):
                raise RuntimeError("checkout is not the clean exact event head")
        except BaseException as exc:
            diagnostic = {
                "utc": utc_now(), "expected_head": expected_head,
                "cwd": str(self.repo), "error": str(exc) or type(exc).__name__,
                "environment_redacted": effective_environment(environment),
                "pretoolchain_cargo_lock_raw": self.pretoolchain_raw_lock,
                "baseline_cargo_lock_raw": self.baseline_raw_lock,
            }
            for name, read in (
                ("failure_cargo_lock_raw", lambda: snapshot_cargo_lock(
                    self.repo, self.logs / "setup-failure.Cargo.lock.raw",
                )),
                ("cargo_lock_sha256", lambda: sha256_file(self.repo / "Cargo.lock")),
                ("cargo_lock_unstaged_diff", lambda: cargo_lock_diff(
                    self.repo, staged=False, artifact=self.logs / "setup.cargo-lock-unstaged.patch",
                )),
                ("cargo_lock_staged_diff", lambda: cargo_lock_diff(
                    self.repo, staged=True, artifact=self.logs / "setup.cargo-lock-staged.patch",
                )),
                ("tracked_status", lambda: subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=self.repo, text=True, timeout=15,
                )),
            ):
                try:
                    diagnostic[name] = read()
                except Exception as detail:
                    diagnostic[name] = f"unavailable: {detail}"
            self._write_json(self.logs / "setup-failure.json", diagnostic)
            raise
        self.baseline["pretoolchain_cargo_lock_raw"] = self.pretoolchain_raw_lock
        self.baseline["baseline_cargo_lock_raw"] = self.baseline_raw_lock
        self._write_json(self.logs / "source-baseline.json", self.baseline)
        source = {entry["path"]: entry["sha256"] for entry in self.baseline["files"]}
        self._write_json(
            self.logs / "meta.json",
            {
                "head": expected_head,
                "tree": self.baseline["tree"],
                "source_manifest_sha256": self.baseline["files_sha256"],
                "pretoolchain_cargo_lock_raw": self.pretoolchain_raw_lock,
                "baseline_cargo_lock_raw": self.baseline_raw_lock,
                "committed_gate_inputs_sha256": {key: source[key] for key in sorted(REQUIRED_SOURCE)},
                "platform": platform,
                "runner": {
                    key: os.environ.get(key)
                    for key in (
                        "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion", "GITHUB_RUN_ID",
                        "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_REF", "GITHUB_WORKFLOW",
                        "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_EVENT_NAME",
                    )
                },
                "python_version": sys.version,
                "setup_start_utc": self.setup_start_utc.isoformat(),
                "gate_start_utc": self.gate_start_utc.isoformat(),
                "setup_elapsed_seconds_before_gate": self.setup_elapsed_seconds,
                "setup_cap_minutes_from_setup_start": setup_cap_minutes,
                "soft_job_minutes_from_gate_init": soft_minutes,
                "target": environment["CARGO_TARGET_DIR"],
                "cargo_home": str(self.cargo_home),
                "rustup_home": str(self.rustup_home),
                "fixture_root": environment["PRAXOR_TEST_TMP_ROOT"],
                "temp": environment["TEMP"],
                "utc_created": utc_now(),
            },
        )

    @staticmethod
    def _write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def _source_boundary(self, name: str, phase: str) -> dict:
        snapshot_path = self.logs / f"{name}.source.{phase}.json"
        # Preserve diagnostics before strict normalization can reject a dirty Cargo.lock.
        diagnostic = {"utc": utc_now(), "stage": name, "phase": phase}
        readers = (
            ("cargo_lock_raw", lambda: snapshot_cargo_lock(
                self.repo, self.logs / f"{name}.cargo-lock-working.{phase}.raw",
            )),
            ("cargo_lock_sha256", lambda: sha256_file(self.repo / "Cargo.lock")),
            ("checkout_status", lambda: checkout_status(self.repo)),
            ("checkout_untracked", lambda: checkout_untracked_paths(self.repo)),
            ("cargo_lock_unstaged_diff", lambda: cargo_lock_diff(
                self.repo, staged=False, artifact=self.logs / f"{name}.cargo-lock-unstaged.{phase}.patch",
            )),
            ("cargo_lock_staged_diff", lambda: cargo_lock_diff(
                self.repo, staged=True, artifact=self.logs / f"{name}.cargo-lock-staged.{phase}.patch",
            )),
        )
        diagnostic_errors = []
        for key, read in readers:
            try:
                diagnostic[key] = read()
            except BaseException as exc:
                diagnostic[f"{key}_error"] = str(exc) or type(exc).__name__
                diagnostic_errors.append(key)
        self._write_json(snapshot_path, diagnostic)
        if diagnostic_errors:
            raise RuntimeError(f"stage source diagnostics unavailable {phase} {name}: {diagnostic_errors}")
        if diagnostic["cargo_lock_raw"]["sha256"] != diagnostic["cargo_lock_sha256"]:
            diagnostic["manifest_error"] = "Cargo.lock changed while collecting stage source evidence"
            self._write_json(snapshot_path, diagnostic)
            raise RuntimeError(diagnostic["manifest_error"])
        try:
            manifest = tracked_manifest(self.repo)
            lock_entries = [item for item in manifest["files"] if item["path"] == "Cargo.lock"]
            if len(lock_entries) != 1:
                raise RuntimeError("Cargo.lock missing from stage source manifest")
            if lock_entries[0]["sha256"] != diagnostic["cargo_lock_sha256"]:
                raise RuntimeError("Cargo.lock changed during stage source boundary")
        except BaseException as exc:
            diagnostic["manifest_error"] = str(exc) or type(exc).__name__
            self._write_json(snapshot_path, diagnostic)
            print("Tracked source validation failed: " + json.dumps(diagnostic, sort_keys=True), flush=True)
            raise
        manifest.update(diagnostic)
        self._write_json(snapshot_path, manifest)
        if (
            manifest["head"] != self.expected_head
            or manifest["tree"] != self.baseline["tree"]
            or manifest["tracked_status"]
            or diagnostic["checkout_status"]
            or diagnostic["checkout_untracked"]["untracked_paths"]
            or diagnostic["checkout_untracked"]["ignored_untracked_paths"]
            or manifest.get("untracked_paths")
            or manifest.get("ignored_untracked_paths")
            or diagnostic["cargo_lock_raw"]["sha256"] != self.baseline_raw_lock["sha256"]
            or diagnostic["cargo_lock_raw"]["bytes"] != self.baseline_raw_lock["bytes"]
            or manifest["files_sha256"] != self.baseline["files_sha256"]
            or manifest["git_conversion_config"] != self.baseline["git_conversion_config"]
        ):
            print(
                "Tracked source drift: " + json.dumps(
                    {
                        "stage": name,
                        "phase": phase,
                        "tracked_status": manifest["tracked_status"],
                        "checkout_status": diagnostic["checkout_status"],
                        "checkout_untracked": diagnostic["checkout_untracked"],
                        "cargo_lock_sha256": manifest["cargo_lock_sha256"],
                        "cargo_lock_raw": diagnostic["cargo_lock_raw"],
                        "cargo_lock_unstaged_diff": manifest["cargo_lock_unstaged_diff"],
                        "cargo_lock_staged_diff": manifest["cargo_lock_staged_diff"],
                    }, sort_keys=True,
                ),
                flush=True,
            )
            raise RuntimeError(f"tracked source drift {phase} stage {name}")
        return manifest

    def _sample(self, stage: str, samples: list[dict], guard: dict, lock: threading.Lock) -> None:
        disk = shutil.disk_usage(self.root)
        cargo_disk = shutil.disk_usage(self._existing_ancestor(self.cargo_home))
        rustup_disk = shutil.disk_usage(self._existing_ancestor(self.rustup_home))
        ram_total, ram_free = available_memory()
        event = {
            "utc": utc_now(), "stage": stage, "disk_total_bytes": disk.total,
            "disk_free_bytes": disk.free, "ram_total_bytes": ram_total,
            "ram_available_bytes": ram_free,
            "cargo_home_disk_free_bytes": cargo_disk.free,
            "rustup_home_disk_free_bytes": rustup_disk.free,
        }
        with lock:
            samples.append(event)
            with (self.logs / f"{stage}.resources.jsonl").open("a", encoding="utf-8") as log:
                log.write(json.dumps(event, sort_keys=True) + "\n")
            if (
                disk.free < guard["disk"]
                or cargo_disk.free < guard["toolchain_disk"]
                or rustup_disk.free < guard["toolchain_disk"]
                or ram_free < guard["ram"]
            ):
                guard["violation"] = (
                    f"target/Cargo-home/Rustup-home disk or RAM under stage floor "
                    f"{guard['disk']}/{guard['toolchain_disk']}/{guard['ram']} bytes at {event['utc']}"
                )

    @staticmethod
    def _existing_ancestor(path: Path) -> Path:
        while not path.exists() and path != path.parent:
            path = path.parent
        return path

    @staticmethod
    def _windows_job(process: subprocess.Popen) -> int:
        kernel = ctypes.windll.kernel32
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel.CreateJobObjectW.restype = ctypes.c_void_p
        kernel.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel.AssignProcessToJobObject.restype = ctypes.c_int
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        kernel.SetInformationJobObject.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
        ]
        kernel.SetInformationJobObject.restype = ctypes.c_int
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError()
        limits = JobExtendedLimitInformation()
        limits.basic_limit_information.limit_flags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(
            ctypes.c_void_p(job), 9, ctypes.byref(limits), ctypes.sizeof(limits),
        ):
            error = kernel.GetLastError()
            kernel.CloseHandle(job)
            raise ctypes.WinError(error)
        if not kernel.AssignProcessToJobObject(job, ctypes.c_void_p(process._handle)):
            error = kernel.GetLastError()
            kernel.CloseHandle(job)
            raise ctypes.WinError(error)
        return job

    @staticmethod
    def _close_windows_job(job: int) -> None:
        if not ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(job)):
            raise ctypes.WinError()

    @staticmethod
    def _windows_job_pids(job: int) -> list[int]:
        """Identify members of a live Job Object for the failure receipt."""
        kernel = ctypes.windll.kernel32
        kernel.QueryInformationJobObject.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ]
        kernel.QueryInformationJobObject.restype = ctypes.c_int
        width = ctypes.sizeof(ctypes.c_size_t)
        capacity = 32
        while capacity <= 4096:
            buffer = ctypes.create_string_buffer(8 + width * capacity)
            if kernel.QueryInformationJobObject(
                ctypes.c_void_p(job), 3, buffer, ctypes.sizeof(buffer), None,
            ):
                assigned = ctypes.c_uint32.from_buffer(buffer, 0).value
                count = ctypes.c_uint32.from_buffer(buffer, 4).value
                if count > capacity or count < assigned:
                    capacity = max(capacity * 2, assigned)
                    continue
                return [
                    ctypes.c_size_t.from_buffer(buffer, 8 + width * index).value
                    for index in range(count)
                ]
            error = kernel.GetLastError()
            if error not in (122, 234):  # ERROR_INSUFFICIENT_BUFFER / ERROR_MORE_DATA
                raise ctypes.WinError(error)
            capacity *= 2
        raise RuntimeError("Windows Job Object PID list exceeded 4096 entries")

    @staticmethod
    def _windows_job_member_diagnostics(pids: list[int], job: int | None = None) -> list[dict]:
        """Native image paths are evidence; a lookup failure never clears a live PID."""
        kernel = ctypes.windll.kernel32
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        members: list[dict] = []
        for pid in pids:
            handle = kernel.OpenProcess(0x1000, 0, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                detail = {
                    "pid": pid, "image_name": None, "image_path": None,
                    "name_lookup_error": str(ctypes.WinError(kernel.GetLastError())),
                    "in_job": None, "creation_time_100ns": None,
                    "identity_lookup_error": None,
                }
            else:
                try:
                    detail = StageRecorder._windows_job_member_from_handle(handle, pid, job)
                finally:
                    kernel.CloseHandle(ctypes.c_void_p(handle))
            members.append(detail)
        return members

    @staticmethod
    def _windows_job_member_from_handle(handle: int, pid: int, job: int | None) -> dict:
        """Read image and identity from one retained process handle."""
        kernel = ctypes.windll.kernel32
        kernel.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32),
        ]
        kernel.QueryFullProcessImageNameW.restype = ctypes.c_int
        detail = {
            "pid": pid, "image_name": None, "image_path": None,
            "name_lookup_error": None, "in_job": None,
            "creation_time_100ns": None, "identity_lookup_error": None,
        }
        image = ctypes.create_unicode_buffer(32768)
        length = ctypes.c_uint32(len(image))
        if not kernel.QueryFullProcessImageNameW(
            ctypes.c_void_p(handle), 0, image, ctypes.byref(length),
        ):
            detail["name_lookup_error"] = str(ctypes.WinError(kernel.GetLastError()))
        else:
            detail["image_path"] = image.value
            detail["image_name"] = ntpath.basename(image.value)
        if job is not None:
            kernel.IsProcessInJob.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
            ]
            kernel.IsProcessInJob.restype = ctypes.c_int
            kernel.GetProcessTimes.argtypes = [
                ctypes.c_void_p, *([ctypes.POINTER(WinFileTime)] * 4),
            ]
            kernel.GetProcessTimes.restype = ctypes.c_int
            in_job = ctypes.c_int()
            if not kernel.IsProcessInJob(
                ctypes.c_void_p(handle), ctypes.c_void_p(job), ctypes.byref(in_job),
            ):
                detail["identity_lookup_error"] = str(ctypes.WinError(kernel.GetLastError()))
            else:
                detail["in_job"] = bool(in_job.value)
            created, exited, kernel_time, user_time = (WinFileTime() for _ in range(4))
            if not kernel.GetProcessTimes(
                ctypes.c_void_p(handle), ctypes.byref(created), ctypes.byref(exited),
                ctypes.byref(kernel_time), ctypes.byref(user_time),
            ):
                detail["identity_lookup_error"] = str(ctypes.WinError(kernel.GetLastError()))
            else:
                detail["creation_time_100ns"] = (created.high << 32) | created.low
        return detail

    @staticmethod
    def _windows_dispose_verified_vctip(
        job: int, baseline: list[dict], actions: list[dict], check_limits,
        disposal_deadline: float,
    ) -> None:
        """Terminate only baseline-verified telemetry, after all handles pass fresh checks."""
        if not StageRecorder._windows_vctip_members_verified(baseline):
            raise RuntimeError("VCTIP disposal baseline is not fully verified")
        expected = sorted(item["pid"] for item in baseline)
        baseline_pids = set(expected)
        if sorted(StageRecorder._windows_job_pids(job)) != expected:
            raise RuntimeError("Job PID set changed before VCTIP disposal")
        kernel = ctypes.windll.kernel32
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.TerminateProcess.restype = ctypes.c_int
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.WaitForSingleObject.restype = ctypes.c_uint32
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        retained: list[tuple[int, dict]] = []
        try:
            for member in baseline:
                check_limits()
                action = {
                    "pid": member["pid"], "baseline_member": member,
                    "revalidated_member": None, "pre_termination_wait_result": None,
                    "termination_requested": False, "handle_signaled": False,
                    "termination_request_utc": None, "handle_signaled_utc": None,
                    "post_termination_wait_result": None, "wait_elapsed_seconds": None,
                    "handle_closed": False, "error": None,
                }
                actions.append(action)
                handle = kernel.OpenProcess(0x00101001, 0, member["pid"])
                if not handle:
                    action["error"] = f"OpenProcess failed: {ctypes.WinError(kernel.GetLastError())}"
                    raise RuntimeError(action["error"])
                retained.append((handle, action))
                fresh = StageRecorder._windows_job_member_from_handle(handle, member["pid"], job)
                action["revalidated_member"] = fresh
                if not StageRecorder._windows_vctip_members_verified([fresh], [member]):
                    action["error"] = "same-handle VCTIP identity or Job membership changed"
                    raise RuntimeError(action["error"])
                signal_state = kernel.WaitForSingleObject(ctypes.c_void_p(handle), 0)
                action["pre_termination_wait_result"] = signal_state
                if signal_state != 258:  # WAIT_TIMEOUT: process is still live.
                    action["error"] = f"VCTIP was not confirmed live (wait result {signal_state})"
                    raise RuntimeError(action["error"])
            # All candidates are validated before the first destructive action.
            if sorted(StageRecorder._windows_job_pids(job)) != expected:
                raise RuntimeError("Job PID set changed after VCTIP handle validation")
            for handle, action in retained:
                check_limits()
                current = sorted(StageRecorder._windows_job_pids(job))
                if current != expected:
                    action["error"] = f"Job PID set changed before selective termination: {current}"
                    raise RuntimeError(action["error"])
                signal_state = kernel.WaitForSingleObject(ctypes.c_void_p(handle), 0)
                action["pre_termination_wait_result"] = signal_state
                if signal_state != 258:
                    action["error"] = f"VCTIP exited before selective termination (wait result {signal_state})"
                    raise RuntimeError(action["error"])
                if not kernel.TerminateProcess(ctypes.c_void_p(handle), 0):
                    action["error"] = f"TerminateProcess failed: {ctypes.WinError(kernel.GetLastError())}"
                    raise RuntimeError(action["error"])
                action["termination_requested"] = True
                action["termination_request_utc"] = utc_now()
                wait_started = time.monotonic()
                while True:
                    check_limits()
                    if time.monotonic() >= disposal_deadline:
                        action["error"] = "VCTIP termination wait exceeded disposal budget"
                        raise RuntimeError(action["error"])
                    result = kernel.WaitForSingleObject(ctypes.c_void_p(handle), 100)
                    action["post_termination_wait_result"] = result
                    if result == 0:  # WAIT_OBJECT_0: process exited.
                        action["handle_signaled"] = True
                        action["handle_signaled_utc"] = utc_now()
                        action["wait_elapsed_seconds"] = time.monotonic() - wait_started
                        break
                    if result != 258:
                        action["error"] = f"VCTIP termination wait failed ({result})"
                        raise RuntimeError(action["error"])
                expected.remove(action["pid"])
                while True:
                    check_limits()
                    current = sorted(StageRecorder._windows_job_pids(job))
                    if current == expected:
                        break
                    if any(pid not in expected and pid != action["pid"] for pid in current):
                        raise RuntimeError(f"new Job member after selective termination: {current}")
                    if time.monotonic() >= disposal_deadline:
                        raise RuntimeError(f"Job PID list did not settle after selective termination: {current}")
                    time.sleep(0.1)
            # Retain the process handles until the Job PID list is empty. This
            # prevents a terminated process ID from being reused during the
            # final membership check.
            while True:
                check_limits()
                remaining = StageRecorder._windows_job_pids(job)
                if not remaining:
                    break
                if any(pid not in baseline_pids for pid in remaining):
                    raise RuntimeError(f"new Job member during VCTIP disposal: {remaining}")
                if time.monotonic() >= disposal_deadline:
                    raise RuntimeError(f"Job PID list did not empty after VCTIP disposal: {remaining}")
                time.sleep(0.1)
        finally:
            primary_error = sys.exc_info()[1]
            close_errors: list[str] = []
            for handle, action in reversed(retained):
                if not kernel.CloseHandle(ctypes.c_void_p(handle)):
                    close_error = f"CloseHandle failed: {ctypes.WinError(kernel.GetLastError())}"
                    action["error"] = "; ".join(filter(None, (action["error"], close_error)))
                    close_errors.append(close_error)
                else:
                    action["handle_closed"] = True
            if close_errors:
                if primary_error is not None:
                    raise RuntimeError(
                        f"{primary_error}; process handle close errors: {'; '.join(close_errors)}"
                    ) from primary_error
                raise RuntimeError("; ".join(close_errors))

    @staticmethod
    def _windows_vctip_members_verified(
        members: list[dict], baseline: list[dict] | None = None,
    ) -> bool:
        """Grant extra wait only to native MSVC telemetry images in the VS toolchain tree."""
        if not members:
            return False
        originals = {item.get("pid"): item for item in baseline} if baseline is not None else None
        if originals is not None and len(originals) != len(baseline):
            return False
        seen: set[int] = set()
        for member in members:
            image = member.get("image_path")
            name = member.get("image_name")
            if (
                not isinstance(member.get("pid"), int) or member["pid"] <= 0
                or member["pid"] in seen
                or member.get("name_lookup_error") is not None
                or member.get("identity_lookup_error") is not None
                or member.get("in_job") is not True
                or not isinstance(member.get("creation_time_100ns"), int)
                or member["creation_time_100ns"] <= 0
                or not isinstance(image, str) or not isinstance(name, str)
                or name.casefold() != "vctip.exe"
                or not ntpath.isabs(image)
                or ntpath.normpath(image).casefold() != image.casefold()
            ):
                return False
            seen.add(member["pid"])
            parts = [part.casefold() for part in image.split("\\")]
            if (
                len(parts) != 13
                or not re.fullmatch(r"[a-z]:", parts[0])
                or parts[1] not in {"program files", "program files (x86)"}
                or parts[2] != "microsoft visual studio"
                or not parts[3] or not parts[4] or not parts[8]
                or parts[5:8] != ["vc", "tools", "msvc"]
                or parts[9] != "bin"
                or parts[10] not in {"hostx86", "hostx64", "hostarm64"}
                or parts[11] not in {"x86", "x64", "arm64"}
                or parts[12] != "vctip.exe"
            ):
                return False
            if originals is not None:
                previous = originals.get(member["pid"])
                if (
                    previous is None
                    or previous.get("creation_time_100ns") != member["creation_time_100ns"]
                    or not isinstance(previous.get("image_path"), str)
                    or previous["image_path"].casefold() != image.casefold()
                ):
                    return False
        return True

    @staticmethod
    def _linux_group_live_pids(pgid: int, proc_root: Path = Path("/proc")) -> list[int]:
        """Ignore exited zombies, but fail closed if a group member cannot be classified."""
        live: list[int] = []
        with os.scandir(proc_root) as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    raw = (proc_root / entry.name / "stat").read_bytes()
                except FileNotFoundError:
                    # A process may leave /proc between enumeration and the read.
                    continue
                end = raw.rfind(b") ")
                if end < 0:
                    raise RuntimeError(f"malformed /proc/{entry.name}/stat")
                fields = raw[end + 2:].split()
                if len(fields) < 3:
                    raise RuntimeError(f"incomplete /proc/{entry.name}/stat")
                try:
                    member_group = int(fields[2])
                except ValueError as exc:
                    raise RuntimeError(f"invalid /proc/{entry.name}/stat process group") from exc
                if member_group != pgid:
                    continue
                try:
                    state = fields[0].decode("ascii")
                except UnicodeDecodeError as exc:
                    raise RuntimeError(f"invalid /proc/{entry.name}/stat state") from exc
                if state not in {"R", "S", "D", "Z", "T", "t", "W", "X", "x", "K", "P", "I"}:
                    raise RuntimeError(f"unknown /proc/{entry.name}/stat state {state!r}")
                if state not in {"Z", "X", "x"}:
                    live.append(int(entry.name))
        return live

    @staticmethod
    def _owned_tree_alive(process: subprocess.Popen, job: int | None) -> bool:
        if os.name == "nt":
            if job is None:
                return process.poll() is None
            kernel = ctypes.windll.kernel32
            kernel.QueryInformationJobObject.argtypes = [
                ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
            ]
            kernel.QueryInformationJobObject.restype = ctypes.c_int
            accounting = JobAccounting()
            if not kernel.QueryInformationJobObject(
                ctypes.c_void_p(job), 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None,
            ):
                raise ctypes.WinError()
            return accounting.active_processes != 0
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        return bool(StageRecorder._linux_group_live_pids(process.pid))

    @staticmethod
    def _terminate_tree(process: subprocess.Popen, job: int | None = None) -> None:
        if os.name == "nt":
            if job is not None:
                kernel = ctypes.windll.kernel32
                kernel.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
                kernel.TerminateJobObject.restype = ctypes.c_int
                if not kernel.TerminateJobObject(ctypes.c_void_p(job), 1):
                    raise ctypes.WinError()
                return
            fallback = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5,
            )
            if fallback.returncode != 0 and process.poll() is None:
                raise RuntimeError(f"taskkill failed with exit {fallback.returncode}")
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if not StageRecorder._owned_tree_alive(process, None):
                process.poll()  # Reap the leader after the group has no live members.
                return
            time.sleep(0.1)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if not StageRecorder._owned_tree_alive(process, None):
                process.poll()
                return
            time.sleep(0.1)
        raise RuntimeError("Linux process group remains alive after forced termination")

    def run(
        self, name: str, argv: list[str], *, initial: bool = False,
        timeout_seconds: float = 2700,
    ) -> Path:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", name):
            raise ValueError(f"unsafe stage name: {name!r}")
        if name in self.stages:
            raise ValueError(f"duplicate stage name: {name}")
        self.stages.append(name)
        log_path = self.logs / f"{name}.raw.log"
        log_path.touch()
        (self.logs / f"{name}.resources.jsonl").touch()
        guard = {
            "disk": (8 if initial else 2) * GIB if self.platform == "windows" else (6 if initial else 1) * GIB,
            "ram": (2 if initial else 1) * GIB,
            "toolchain_disk": (2 if initial else 1) * GIB,
            "violation": None,
        }
        samples: list[dict] = []
        lock = threading.Lock()
        start = utc_now()
        deadline = time.monotonic() + timeout_seconds
        code: int | None = None
        before: dict | None = None
        after: dict | None = None
        errors: list[str] = []
        process: subprocess.Popen | None = None
        job: int | None = None
        watcher: threading.Thread | None = None
        reader: threading.Thread | None = None
        stopped = threading.Event()
        stop_writing = threading.Event()
        reader_done = threading.Event()
        reader_errors: list[str] = []
        leader_exit_at: float | None = None
        last_quiescence_sample = 0.0
        quiescence_seconds: float | None = None
        quiescence_budget = WINDOWS_JOB_QUIESCENCE_SECONDS
        vctip_verified_members: list[dict] | None = None
        vctip_first_seen_seconds: float | None = None
        vctip_last_seen_seconds: float | None = None
        vctip_disposal_actions: list[dict] = []
        vctip_disposal_deadline: float | None = None
        vctip_pre_disposal_pids: list[int] | None = None
        vctip_post_disposal_pids: list[int] | None = None
        vctip_post_disposal_pipe_drained: bool | None = None
        quiescence_terminal_reason: str | None = None
        survivor_pids: list[int] | None = None
        survivor_members: list[dict] | None = None

        def watch() -> None:
            while not stopped.wait(2):
                try:
                    self._sample(name, samples, guard, lock)
                except Exception as exc:
                    guard["violation"] = f"resource watcher failed: {exc}"
                    return

        def drain() -> None:
            try:
                assert process is not None and process.stdout is not None
                with process.stdout, log_path.open("ab") as raw:
                    while chunk := process.stdout.read1(65536):
                        if stop_writing.is_set():
                            break
                        raw.write(chunk)
                        raw.flush()
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
            except Exception as exc:
                reader_errors.append(f"raw pipe reader failed: {exc}")
            finally:
                reader_done.set()

        def check_disposal_limits() -> None:
            if guard["violation"]:
                raise RuntimeError(guard["violation"])
            if reader_errors:
                raise RuntimeError(reader_errors[0])
            if time.monotonic() >= self.soft_job_deadline:
                raise RuntimeError(f"soft overall job deadline after {self.soft_job_minutes} minutes")
            if time.monotonic() >= deadline:
                raise RuntimeError(f"wall-clock timeout after {timeout_seconds} seconds")

        try:
            if time.monotonic() >= self.soft_job_deadline:
                raise RuntimeError("soft overall job deadline reached before stage admission")
            before = self._source_boundary(name, "before")
            self._sample(name, samples, guard, lock)
            if guard["violation"]:
                raise RuntimeError(guard["violation"])
            print(f"Stage {name} started", flush=True)
            command = argv
            if self.platform == "windows":
                # The wrapper blocks on stdin before it can launch the requested stage.
                command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).with_name("ci_catalog_windows_wrapper.py")), *argv]
            process = subprocess.Popen(
                command, cwd=self.repo, env=self.environment,
                stdin=subprocess.PIPE if self.platform == "windows" else None,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=(os.name != "nt"),
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
            if self.platform == "windows":
                job = self._windows_job(process)
                assert process.stdin is not None
                process.stdin.write(b"G")
                process.stdin.flush()
                process.stdin.close()
            watcher = threading.Thread(target=watch, daemon=True)
            watcher.start()
            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            while True:
                if guard["violation"]:
                    raise RuntimeError(guard["violation"])
                if reader_errors:
                    raise RuntimeError(reader_errors[0])
                if time.monotonic() >= self.soft_job_deadline:
                    raise RuntimeError(f"soft overall job deadline after {self.soft_job_minutes} minutes")
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"wall-clock timeout after {timeout_seconds} seconds")
                # Keep the Linux session leader unreaped while inherited pipes are
                # open, so its numeric PID/PGID cannot be reused before cleanup.
                observed_code = process.poll() if self.platform == "windows" or reader_done.is_set() else None
                if observed_code is not None:
                    if observed_code != 0:
                        code = observed_code
                        raise RuntimeError(f"command exited {observed_code}")
                    if self.platform == "windows" and job is not None:
                        now = time.monotonic()
                        if leader_exit_at is None:
                            leader_exit_at = now
                        quiescence_seconds = now - leader_exit_at
                        if now - last_quiescence_sample >= 0.25:
                            self._sample(name, samples, guard, lock)
                            last_quiescence_sample = now
                            if guard["violation"]:
                                raise RuntimeError(guard["violation"])
                        alive = self._owned_tree_alive(process, job)
                        if not alive and reader_done.is_set():
                            if vctip_disposal_deadline is not None and now >= vctip_disposal_deadline:
                                vctip_post_disposal_pids = self._windows_job_pids(job)
                                vctip_post_disposal_pipe_drained = True
                                quiescence_terminal_reason = "vctip_disposal_settle_timeout"
                                raise RuntimeError("verified VCTIP disposal exceeded its settle budget")
                            if vctip_verified_members is not None:
                                remaining = self._windows_job_pids(job)
                                if remaining:
                                    survivor_pids = remaining
                                    quiescence_terminal_reason = "job_accounting_pid_disagreement"
                                    raise RuntimeError("Job Object PID list remained nonempty after accounting reached zero")
                            if vctip_disposal_deadline is not None:
                                vctip_post_disposal_pids = self._windows_job_pids(job)
                                vctip_post_disposal_pipe_drained = True
                                if vctip_post_disposal_pids:
                                    quiescence_terminal_reason = "job_accounting_pid_disagreement"
                                    raise RuntimeError("Job Object PID list remained nonempty after VCTIP disposal")
                                quiescence_terminal_reason = "verified_vctip_disposed_job_empty_and_pipe_drained"
                            else:
                                quiescence_terminal_reason = "job_empty_and_pipe_drained"
                            break
                        if vctip_disposal_deadline is not None:
                            vctip_post_disposal_pids = self._windows_job_pids(job)
                            vctip_post_disposal_pipe_drained = reader_done.is_set()
                            if any(pid not in {item["pid"] for item in vctip_verified_members or []}
                                   for pid in vctip_post_disposal_pids):
                                survivor_pids = vctip_post_disposal_pids
                                survivor_members = self._windows_job_member_diagnostics(survivor_pids, job)
                                quiescence_terminal_reason = "new_job_member_after_vctip_disposal"
                                raise RuntimeError("new Job Object member after verified VCTIP disposal")
                            if now >= vctip_disposal_deadline:
                                survivor_pids = vctip_post_disposal_pids
                                if survivor_pids:
                                    survivor_members = self._windows_job_member_diagnostics(survivor_pids, job)
                                quiescence_terminal_reason = "vctip_disposal_settle_timeout"
                                raise RuntimeError("Job Object or raw pipe did not settle after VCTIP disposal")
                            time.sleep(0.1)
                            continue
                        if now - leader_exit_at >= WINDOWS_JOB_QUIESCENCE_SECONDS:
                            if alive:
                                try:
                                    active_pids = self._windows_job_pids(job)
                                except Exception as exc:
                                    detail = f"Job Object PID query failed: {exc}"
                                else:
                                    try:
                                        active_members = self._windows_job_member_diagnostics(active_pids, job)
                                        confirmed_pids = self._windows_job_pids(job)
                                    except Exception as exc:
                                        survivor_pids = active_pids
                                        detail = f"active job PIDs {active_pids}; image lookup failed: {exc}"
                                    else:
                                        if (
                                            sorted(confirmed_pids) == sorted(active_pids)
                                            and self._windows_vctip_members_verified(
                                                active_members, vctip_verified_members,
                                            )
                                        ):
                                            if vctip_verified_members is None:
                                                vctip_verified_members = active_members
                                                vctip_first_seen_seconds = quiescence_seconds
                                            vctip_last_seen_seconds = quiescence_seconds
                                            quiescence_budget = WINDOWS_VCTIP_QUIESCENCE_SECONDS
                                            if quiescence_seconds < quiescence_budget:
                                                time.sleep(0.1)
                                                continue
                                            vctip_pre_disposal_pids = active_pids
                                            vctip_disposal_deadline = time.monotonic() + 3
                                            try:
                                                self._windows_dispose_verified_vctip(
                                                    job, vctip_verified_members,
                                                    vctip_disposal_actions, check_disposal_limits,
                                                    vctip_disposal_deadline,
                                                )
                                            except Exception as exc:
                                                quiescence_terminal_reason = "vctip_disposal_failed"
                                                try:
                                                    survivor_pids = self._windows_job_pids(job)
                                                    survivor_members = self._windows_job_member_diagnostics(
                                                        survivor_pids, job,
                                                    )
                                                except Exception:
                                                    survivor_pids = active_pids
                                                    survivor_members = active_members
                                                vctip_post_disposal_pids = survivor_pids
                                                vctip_post_disposal_pipe_drained = reader_done.is_set()
                                                raise RuntimeError(
                                                    "owned process group has a surviving descendant after "
                                                    f"{quiescence_seconds:.3f}s; verified VCTIP disposal failed: {exc}"
                                                ) from exc
                                            vctip_post_disposal_pids = self._windows_job_pids(job)
                                            vctip_post_disposal_pipe_drained = reader_done.is_set()
                                            time.sleep(0.1)
                                            continue
                                        else:
                                            quiescence_terminal_reason = "unverified_or_changed_job_member"
                                        survivor_pids = active_pids
                                        survivor_members = active_members
                                        detail = (
                                            f"active job members {active_members}; "
                                            f"confirmed job PIDs {confirmed_pids}"
                                        )
                                if quiescence_terminal_reason is None:
                                    quiescence_terminal_reason = "job_member_query_failed"
                                raise RuntimeError(
                                    f"owned process group has unresolved Job Object activity "
                                    f"(possible surviving descendant after {quiescence_seconds:.3f}s; {detail})"
                                )
                            if vctip_verified_members is not None and quiescence_seconds < quiescence_budget:
                                remaining = self._windows_job_pids(job)
                                if remaining:
                                    survivor_pids = remaining
                                    quiescence_terminal_reason = "job_accounting_pid_disagreement"
                                    raise RuntimeError("Job Object PID list remained nonempty after accounting reached zero")
                                time.sleep(0.1)
                                continue
                            quiescence_terminal_reason = "pipe_open_after_job_empty"
                            raise RuntimeError("raw stage pipe remained open after owned Job Object exited")
                    elif reader_done.is_set():
                        break
                time.sleep(0.1)
            code = process.wait(timeout=1)
            self._sample(name, samples, guard, lock)
            if guard["violation"]:
                raise RuntimeError(guard["violation"])
            if self._owned_tree_alive(process, job):
                raise RuntimeError("owned process group has a surviving descendant")
            if code != 0:
                raise RuntimeError(f"command exited {code}")
            stopped.set()
            watcher.join(timeout=5)
            if watcher.is_alive():
                raise RuntimeError("resource watcher did not stop before receipt")
        except BaseException as exc:
            if leader_exit_at is not None and quiescence_terminal_reason not in (
                "job_empty_and_pipe_drained", "verified_vctip_disposed_job_empty_and_pipe_drained",
            ):
                quiescence_seconds = time.monotonic() - leader_exit_at
            if vctip_verified_members is not None and quiescence_terminal_reason is None:
                quiescence_terminal_reason = "interrupted_during_vctip_quiescence"
            errors.append(str(exc) or type(exc).__name__)
        finally:
            if errors:
                if process is not None:
                    release_pipe = getattr(process, "stdin", None)
                    if release_pipe is not None and not release_pipe.closed:
                        try:
                            release_pipe.close()
                        except Exception as exc:
                            errors.append(f"stage release pipe close failed: {exc}")
                    try:
                        self._terminate_tree(process, job)
                    except Exception as exc:
                        errors.append(f"process-tree cleanup failed: {exc}")
            stopped.set()
            if watcher is not None:
                watcher.join(timeout=5)
                if watcher.is_alive():
                    errors.append("resource watcher remained alive after bounded join")
            if process is not None:
                if code is None:
                    try:
                        code = process.wait(timeout=3)
                    except Exception as exc:
                        errors.append(f"child wait failed after cleanup: {exc}")
                        try:
                            code = process.poll()
                        except Exception as poll_error:
                            errors.append(f"child poll failed: {poll_error}")
                try:
                    if self._owned_tree_alive(process, job):
                        errors.append("owned process group remained alive after cleanup")
                except Exception as exc:
                    errors.append(f"process-tree exit verification failed: {exc}")
            if reader is not None:
                reader.join(timeout=3)
                if reader.is_alive():
                    stop_writing.set()
                    errors.append("raw pipe reader remained alive after bounded join")
            elif process is not None and process.stdout is not None:
                try:
                    process.stdout.close()
                except Exception as exc:
                    errors.append(f"unread stage pipe close failed: {exc}")
            if job is not None:
                try:
                    self._close_windows_job(job)
                except Exception as exc:
                    errors.append(f"Windows process job close failed: {exc}")
            if watcher is None or not watcher.is_alive():
                try:
                    self._sample(name, samples, guard, lock)
                except Exception as exc:
                    errors.append(f"final resource sample failed: {exc}")
            try:
                after = self._source_boundary(name, "after")
            except Exception as exc:
                errors.append(str(exc))
        end = utc_now()
        def raw_boundary(phase: str) -> dict | None:
            path = self.logs / f"{name}.source.{phase}.json"
            if not path.is_file():
                return None
            try:
                return json.loads(path.read_text(encoding="utf-8")).get("cargo_lock_raw")
            except Exception:
                return None

        receipt = {
            "stage": name, "argv": argv, "cwd": str(self.repo),
            "effective_environment_redacted": effective_environment(self.environment),
            "utc_start": start, "utc_end": end, "exit_code": code,
            "error": "; ".join(errors) or None, "resource_violation": guard["violation"],
            "child_started": process is not None, "timeout_seconds": timeout_seconds,
            "soft_job_minutes_from_gate_init": self.soft_job_minutes,
            "setup_start_utc": self.setup_start_utc.isoformat(),
            "gate_start_utc": self.gate_start_utc.isoformat(),
            "setup_elapsed_seconds_before_gate": self.setup_elapsed_seconds,
            "watcher_alive_at_receipt": watcher is not None and watcher.is_alive(),
            "reader_alive_at_receipt": reader is not None and reader.is_alive(),
            "post_leader_quiescence_budget_seconds": (
                quiescence_budget if self.platform == "windows" else None
            ),
            "post_leader_effective_budget_seconds": (
                vctip_disposal_deadline - leader_exit_at
                if vctip_disposal_deadline is not None and leader_exit_at is not None
                else (quiescence_budget if self.platform == "windows" else None)
            ),
            "post_leader_quiescence_seconds": quiescence_seconds,
            "post_leader_quiescence_terminal_reason": quiescence_terminal_reason,
            "post_leader_vctip_first_seen_seconds": vctip_first_seen_seconds,
            "post_leader_vctip_last_seen_seconds": vctip_last_seen_seconds,
            "post_leader_vctip_extension_seconds": (
                max(0.0, quiescence_seconds - WINDOWS_JOB_QUIESCENCE_SECONDS)
                if vctip_verified_members is not None and quiescence_seconds is not None else None
            ),
            "post_leader_vctip_verified_members": vctip_verified_members,
            "post_leader_vctip_disposal_budget_seconds": 3 if vctip_disposal_deadline is not None else None,
            "post_leader_vctip_disposal_actions": vctip_disposal_actions,
            "post_leader_vctip_pre_disposal_pids": vctip_pre_disposal_pids,
            "post_leader_vctip_post_disposal_pids": vctip_post_disposal_pids,
            "post_leader_vctip_post_disposal_pipe_drained": vctip_post_disposal_pipe_drained,
            "surviving_job_pids": survivor_pids,
            "surviving_job_members": survivor_members,
            "raw_log_complete": process is None or (
                reader is not None and reader_done.is_set()
                and not reader_errors and not reader.is_alive()
            ),
            "minimum_disk_free_bytes": min((item["disk_free_bytes"] for item in samples), default=None),
            "minimum_cargo_home_disk_free_bytes": min(
                (item["cargo_home_disk_free_bytes"] for item in samples if "cargo_home_disk_free_bytes" in item),
                default=None,
            ),
            "minimum_rustup_home_disk_free_bytes": min(
                (item["rustup_home_disk_free_bytes"] for item in samples if "rustup_home_disk_free_bytes" in item),
                default=None,
            ),
            "minimum_ram_available_bytes": min((item["ram_available_bytes"] for item in samples), default=None),
            "resource_samples": len(samples), "source_before_sha256": before["files_sha256"] if before else None,
            "source_after_sha256": after["files_sha256"] if after else None,
            "cargo_lock_raw_before": raw_boundary("before"),
            "cargo_lock_raw_after": raw_boundary("after"),
            "raw_log_sha256": sha256_file(log_path) if log_path.exists() else None,
            "raw_log_bytes": log_path.stat().st_size if log_path.exists() else None,
        }
        self._write_json(self.logs / f"{name}.receipt.json", receipt)
        if errors or guard["violation"] or code != 0 or before is None or after is None:
            raise RuntimeError(f"stage {name} failed: {receipt['error']}; exit={code}; resource={guard['violation']}")
        return log_path

    def finish(self, result: dict, *, expected_stages: tuple[str, ...]) -> None:
        if not expected_stages or len(set(expected_stages)) != len(expected_stages):
            raise RuntimeError("empty or duplicate required stage roster")
        if self.stages != list(expected_stages):
            raise RuntimeError(f"stage roster mismatch: observed={self.stages}; required={expected_stages}")
        if result.get("stages") is not None and result["stages"] != self.stages:
            raise RuntimeError("result stage roster differs from executed stage roster")
        self._source_boundary("final", "after")

        def verify_lock_artifacts(name: str, phase: str) -> None:
            manifest = json.loads(
                (self.logs / f"{name}.source.{phase}.json").read_text(encoding="utf-8")
            )
            raw_path = self.logs / f"{name}.cargo-lock-working.{phase}.raw"
            if manifest.get("cargo_lock_raw") != raw_file_evidence(raw_path):
                raise RuntimeError(f"Cargo.lock raw artifact changed or missing: {name}/{phase}")
            for mode in ("unstaged", "staged"):
                path = self.logs / f"{name}.cargo-lock-{mode}.{phase}.patch"
                evidence = manifest[f"cargo_lock_{mode}_diff"]
                if (
                    evidence.get("artifact") != str(path)
                    or not path.is_file()
                    or evidence["sha256"] != sha256_file(path)
                    or evidence["bytes"] != path.stat().st_size
                ):
                    raise RuntimeError(f"Cargo.lock diff artifact changed or missing: {name}/{phase}/{mode}")

        for name in self.stages:
            required = (
                f"{name}.source.before.json", f"{name}.source.after.json",
                f"{name}.resources.jsonl", f"{name}.raw.log", f"{name}.receipt.json",
            )
            for file_name in required:
                path = self.logs / file_name
                if not path.is_file():
                    raise RuntimeError(f"missing required stage artifact: {path}")
            receipt = json.loads((self.logs / f"{name}.receipt.json").read_text(encoding="utf-8"))
            verify_lock_artifacts(name, "before")
            verify_lock_artifacts(name, "after")
            before_source = json.loads((self.logs / f"{name}.source.before.json").read_text(encoding="utf-8"))
            after_source = json.loads((self.logs / f"{name}.source.after.json").read_text(encoding="utf-8"))
            if (
                receipt.get("cargo_lock_raw_before") != before_source["cargo_lock_raw"]
                or receipt.get("cargo_lock_raw_after") != after_source["cargo_lock_raw"]
            ):
                raise RuntimeError(f"stage raw Cargo.lock receipt differs from artifacts: {name}")
            if (
                receipt.get("error") is not None
                or receipt.get("exit_code") != 0
                or receipt.get("resource_violation") is not None
                or receipt.get("watcher_alive_at_receipt")
                or receipt.get("reader_alive_at_receipt")
                or not receipt.get("raw_log_complete")
                or receipt.get("source_before_sha256") != self.baseline["files_sha256"]
                or receipt.get("source_after_sha256") != self.baseline["files_sha256"]
            ):
                raise RuntimeError(f"stage receipt is not a successful frozen-source result: {name}")
            if receipt["raw_log_sha256"] != sha256_file(self.logs / f"{name}.raw.log"):
                raise RuntimeError(f"stage raw log changed after receipt: {name}")
        verify_lock_artifacts("final", "after")
        if self.pretoolchain_raw_lock != raw_file_evidence(self.logs / "setup-pretoolchain.Cargo.lock.raw"):
            raise RuntimeError("pretoolchain raw Cargo.lock artifact changed after admission")
        if self.baseline_raw_lock != raw_file_evidence(self.logs / "source-baseline.Cargo.lock.raw"):
            raise RuntimeError("baseline raw Cargo.lock artifact changed after admission")
        self._write_json(self.logs / "result.json", result)
        print(f"Frozen-source {self.platform} catalog gate passed at {self.expected_head}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-workflow", metavar="EXPECTED_HEAD", required=True)
    arguments = parser.parse_args()
    verify_workflow_provenance(Path(__file__).resolve().parents[1], arguments.verify_workflow, os.environ)
