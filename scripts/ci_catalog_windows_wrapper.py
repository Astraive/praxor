"""Hold a hosted Windows stage until its parent has assigned a kill-on-close Job Object.

The parent sends the single release byte only after AssignProcessToJobObject succeeds.
If assignment fails or the parent exits, EOF keeps the requested stage from starting.
"""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("missing stage argv", file=sys.stderr, flush=True)
        return 125
    if sys.stdin.buffer.read(1) != b"G":
        print("stage job assignment was not confirmed", file=sys.stderr, flush=True)
        return 125
    import subprocess

    return subprocess.run(sys.argv[1:], stdin=subprocess.DEVNULL, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
