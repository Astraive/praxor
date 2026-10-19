"""Fail closed unless Cargo uses the pinned vendored Zstd source and bindings."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tomllib


EXPECTED = {
    "zstd": ("0.13.3", "e91ee311a569c327171651566e07972200e76fcfe2242a4fa446149a3881c08a"),
    "zstd-safe": ("7.2.4", "8f49c4d5f0abb602a93fb8736af2a4f4dd9512e36f7f570d66e65ff867ed3b9d"),
    "zstd-sys": ("2.0.16+zstd.1.5.7", "91e19ebc2adc8f83e43039e79776e3fda8ca919132d68a1fed6a5faca2683748"),
}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
TREE_DIGEST = "62fbd5e70e1e026203cfbaa8be6f4e05cf63e6f3c4331bca8312cc857cfe88ff"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", default=None)
    args = parser.parse_args()

    require(
        "ZSTD_SYS_USE_PKG_CONFIG" not in os.environ,
        "ZSTD_SYS_USE_PKG_CONFIG exists: system Zstd path would be selected",
    )
    root = Path(__file__).resolve().parents[1]
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    command = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if args.features:
        command.extend(["--features", args.features])
    meta = json.loads(
        subprocess.run(command, cwd=root, check=True, capture_output=True, text=True).stdout
    )
    require(meta["resolve"] is not None, "Cargo metadata omitted resolved features")
    nodes = {node["id"]: node for node in meta["resolve"]["nodes"]}

    sys_source = None
    for name, (version, checksum) in EXPECTED.items():
        locked = [package for package in lock["package"] if package["name"] == name]
        require(len(locked) == 1, f"expected one locked package for {name}")
        require(locked[0]["version"] == version, f"unexpected locked {name} version")
        require(locked[0]["source"] == REGISTRY, f"unexpected locked {name} source")
        require(locked[0]["checksum"] == checksum, f"unexpected locked {name} checksum")

        packages = [package for package in meta["packages"] if package["name"] == name]
        require(len(packages) == 1, f"expected one resolved package for {name}")
        package = packages[0]
        require(package["version"] == version, f"unexpected resolved {name} version")
        require(package["source"] == REGISTRY, f"unexpected resolved {name} source")
        require(package["id"] in nodes, f"missing resolved feature node for {name}")
        features = set(nodes[package["id"]]["features"])
        require("experimental" in features, f"{name} experimental binding unavailable: {features}")
        require(
            not (features & {"pkg-config", "bindgen"}),
            f"{name} may select system library or generated bindings: {features}",
        )
        if name == "zstd-sys":
            sys_source = Path(package["manifest_path"]).parent

    require(sys_source is not None, "zstd-sys source directory missing")
    files = [path for path in (sys_source / "zstd" / "lib").rglob("*") if path.is_file()]
    files += [
        sys_source / "build.rs",
        sys_source / "Cargo.toml",
        sys_source / "src" / "lib.rs",
        sys_source / "src" / "bindings_zstd_experimental.rs",
        sys_source / "src" / "bindings_zdict_experimental.rs",
    ]
    require(len(files) == 95, f"unexpected pinned Zstd source file count: {len(files)}")
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda path: path.relative_to(sys_source).as_posix()):
        digest.update(path.relative_to(sys_source).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    require(digest.hexdigest() == TREE_DIGEST, f"pinned Zstd source tree changed: {digest.hexdigest()}")
    binding = (sys_source / "src" / "bindings_zstd_experimental.rs").read_text(encoding="utf-8")
    for symbol in ("ZSTD_estimateDCtxSize", "ZSTD_initStaticDCtx", "ZSTD_decompressDCtx"):
        require(f"pub fn {symbol}" in binding, f"missing static DCtx symbol: {symbol}")
    print("Pinned vendored Zstd 1.5.7 source and static-DCtx feature path verified")


if __name__ == "__main__":
    main()
