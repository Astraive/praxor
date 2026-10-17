import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "matrix_strace", Path(__file__).parents[1] / "parse_write_matrix_strace.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StraceMarkers(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {
                "id": "case-1", "label": "candidate", "data_dir": "/tmp/db",
                "source_revision": "abc", "active_cfs": 1, "batch_ops": 16, "batches": 2,
            }
        ]

    def test_scope_partial_markers_failures_and_directory_classification(self):
        trace = r'''12 fsync(4</tmp/db/wal/1.wal>) = 0
12 write(2</tmp/results>, "PRAXIS_WRITE_MATRIX_BE", 22) = 22
12 write(2</tmp/results>, "GIN case-1\n", 11) = 11
12 fsync(4</tmp/db/wal/1.wal>) = 0
12 fdatasync(4</tmp/db/wal/1.wal>) = -1 EIO (Input/output error)
12 fsync(5</tmp/db/MANIFEST.tmp>) = 0
12 rename("/tmp/db/MANIFEST.tmp", "/tmp/db/MANIFEST") = 0
12 fsync(5</tmp/db>) = 0
12 fsync(5</tmp/db/wal>) = 0
12 write(2</tmp/results>, "PRAXIS_WRITE_MATRIX_END case-1\n", 31) = 31
12 fsync(4</tmp/db/wal/1.wal>) = 0'''
        counts = MODULE.parse_trace(trace, self.rows)[0]["observed_syscalls"]
        self.assertEqual(counts, {
            "fsync.wal_file.success": 1,
            "fdatasync.wal_file.failed": 1,
            "fsync.manifest_temporary_file.success": 1,
            "manifest_rename.success": 1,
            "fsync.database_parent_directory.success": 1,
            "fsync.wal_parent_directory.success": 1,
        })

    def test_missing_or_mismatched_end_is_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.parse_trace('write(2, "PRAXIS_WRITE_MATRIX_BEGIN case-1\\n", 33) = 33', self.rows)
        with self.assertRaises(ValueError):
            MODULE.parse_trace('write(2, "PRAXIS_WRITE_MATRIX_END case-1\\n", 31) = 31', self.rows)

    def test_unparsed_sync_is_rejected_instead_of_undercounting(self):
        trace = r'''write(2, "PRAXIS_WRITE_MATRIX_BEGIN case-1\n", 33) = 33
fsync(4) = 0
write(2, "PRAXIS_WRITE_MATRIX_END case-1\n", 31) = 31'''
        with self.assertRaisesRegex(ValueError, "unparsed sync"):
            MODULE.parse_trace(trace, self.rows)

    def test_actual_short_write_count_and_failed_marker(self):
        trace = r'''write(2, "PRAXIS_WRITE_MATRIX_BEGIN case-1\n", 33) = 20
write(2, "BEGIN case-1\n", 13) = 13
fsync(4</tmp/db/wal/1.wal>) = 0
write(2, "PRAXIS_WRITE_MATRIX_END case-1\n", 31) = 31'''
        counts = MODULE.parse_trace(trace, self.rows)[0]["observed_syscalls"]
        self.assertEqual(counts, {"fsync.wal_file.success": 1})
        with self.assertRaisesRegex(ValueError, "failed or truncated marker"):
            MODULE.parse_trace('write(2, "PRAXIS_WRITE_MATRIX_BEGIN case-1\\n", 33) = -1 EIO', self.rows)


if __name__ == "__main__":
    unittest.main()
