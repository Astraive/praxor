"""Frozen-source, byte-preserving command receipts for hosted catalog gates."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
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
        return True

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
                return
            time.sleep(0.1)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if not StageRecorder._owned_tree_alive(process, None):
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
                if reader_done.is_set() and process.poll() is not None:
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
