#!/usr/bin/env bash
# Untimed Linux syscall evidence. Source and target paths must be isolated.
set -euo pipefail
if [[ $# != 6 ]]; then
    echo "usage: $0 SOURCE TARGET EXT4_DATA OUTPUT LABEL REVISION" >&2
    exit 2
fi
source_root=$1
target=$2
data=$3
output=$4
label=$5
revision=$6
mkdir -p "$data" "$output"
cd "$source_root"
cargo +1.99.0 bench --locked --jobs 2 --target-dir "$target" --bench write_amplification_matrix --no-run --message-format=json > "$output/$label-build.jsonl" 2> "$output/$label-build.log"
binary=$(python3 - "$output/$label-build.jsonl" <<'PY'
import json, sys
artifacts = [json.loads(line) for line in open(sys.argv[1])]
executables = [a['executable'] for a in artifacts if a.get('reason') == 'compiler-artifact' and a['target']['name'] == 'write_amplification_matrix' and a.get('executable')]
assert len(executables) == 1, executables
print(executables[0])
PY
)
harness_hash=$(python3 - "$source_root" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]) / 'benches/durability'
names = ['write_amplification_matrix.rs', 'write_amplification_allocations.rs', 'write_matrix_support.rs']
hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
print(hashlib.sha256(json.dumps(hashes, separators=(',', ':')).encode()).hexdigest())
PY
)
extra=()
if [[ "$label" == candidate ]]; then extra+=(--expect-stable-manifest); fi
strace -f -yy -s 4096 -e trace=write,fsync,fdatasync,rename,renameat,renameat2,openat,close -o "$output/$label.strace" "$binary" --probe --batches 4 --warmup-batches 1 --repetitions 1 --data-dir "$data" --label "$label" --source-revision "$revision" --harness-hash "$harness_hash" "${extra[@]}" > "$output/$label-stdout.log" 2> "$output/$label.jsonl"
python3 - "$source_root" "$binary" "$data" "$revision" "$harness_hash" "$output/$label-provenance.json" <<'PY'
import hashlib, json, pathlib, platform, subprocess, sys
source, binary, data, revision, harness, output = sys.argv[1:]
def command(*args):
    return subprocess.check_output(args, text=True).strip()
record = {
    'source_revision': revision, 'source_root': source, 'executable': binary,
    'executable_sha256': hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
    'cargo_lock_sha256': hashlib.sha256((pathlib.Path(source) / 'Cargo.lock').read_bytes()).hexdigest(),
    'harness_sha256': harness, 'rustc': command('rustc', '+1.99.0', '--version'),
    'cargo': command('cargo', '+1.99.0', '--version'),
    'strace': command('strace', '--version').splitlines()[0],
    'platform': platform.platform(), 'filesystem': command('df', '-T', data),
    'storage_scope': 'WSL2 ext4 virtual disk, separate from native Windows NTFS timing',
    'exit_code': 0,
}
pathlib.Path(output).write_text(json.dumps(record, indent=2) + '\n')
PY
