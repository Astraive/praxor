"""Synthetic Cargo harness fixtures for the CI inventory/result evidence contract."""

import unittest

from scripts.ci_catalog_evidence import (
    parse_inventory,
    parse_results,
    verify_exact,
    verify_suite,
)


LIB = "Running unittests src/lib.rs (target/debug/deps/praxor-abc)"
INTEGRATION = "Running tests/empty.rs (target/debug/deps/empty-abc)"
DOCS = "Doc-tests praxor"

LIB_LIST = f"""
Finished `test` profile in 0.1s
{LIB}
core_catalog::segment_witness_tests::native: test
core_catalog::segment_witness_tests::ignored: test
core_catalog::other_tests::other: test
3 tests, 0 benchmarks
"""
EXACT = f"""
{LIB}
running 1 test
test core_catalog::segment_witness_tests::native ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s
"""
FOCUSED_LIST = f"""
{LIB}
core_catalog::segment_witness_tests::native: test
core_catalog::segment_witness_tests::ignored: test
2 tests, 0 benchmarks
"""
FOCUSED_IGNORED = f"""
{LIB}
core_catalog::segment_witness_tests::ignored: test
1 test, 0 benchmarks
"""
FOCUSED_RUN = f"""
{LIB}
running 2 tests
test core_catalog::segment_witness_tests::native ... ok
test core_catalog::segment_witness_tests::ignored ... ignored
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 1 filtered out; finished in 0.01s
"""
FULL_LIST = f"""
{LIB_LIST}
{INTEGRATION}
0 tests, 0 benchmarks
{DOCS}
src/lib.rs - some_example (line 4): test
1 test, 0 benchmarks
"""
FULL_IGNORED = f"""
{LIB}
core_catalog::segment_witness_tests::ignored: test
1 test, 0 benchmarks
{INTEGRATION}
0 tests, 0 benchmarks
{DOCS}
0 tests, 0 benchmarks
"""
FULL_RUN = f"""
{LIB}
running 3 tests
test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s
{INTEGRATION}
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
{DOCS}
running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""


class CatalogEvidenceTests(unittest.TestCase):
    def test_exact_uses_library_count_for_filtered_result(self):
        evidence = verify_exact(
            parse_inventory(LIB_LIST),
            parse_results(EXACT),
            "core_catalog::segment_witness_tests::native",
        )
        self.assertEqual(evidence["library_cases"], 3)
        with self.assertRaisesRegex(ValueError, "differs"):
            verify_exact(
                parse_inventory(LIB_LIST),
                parse_results(EXACT.replace("2 filtered out", "1 filtered out")),
                "core_catalog::segment_witness_tests::native",
            )
        with self.assertRaisesRegex(ValueError, "differs"):
            verify_exact(
                parse_inventory(LIB_LIST),
                parse_results(EXACT.replace("0 measured", "1 measured")),
                "core_catalog::segment_witness_tests::native",
            )

    def test_focused_uses_selected_ignored_and_outside_filter_count(self):
        evidence = verify_suite(
            parse_inventory(FOCUSED_LIST),
            parse_inventory(FOCUSED_IGNORED),
            parse_results(FOCUSED_RUN),
            reference=parse_inventory(LIB_LIST),
            prefix="core_catalog::segment_witness_tests::",
        )
        self.assertEqual((evidence["passed"], evidence["ignored"], evidence["filtered"]), (1, 1, 1))
        with self.assertRaisesRegex(ValueError, "differs"):
            verify_suite(
                parse_inventory(FOCUSED_LIST),
                parse_inventory(FOCUSED_IGNORED),
                parse_results(FOCUSED_RUN.replace("1 filtered out", "0 filtered out")),
                reference=parse_inventory(LIB_LIST),
                prefix="core_catalog::segment_witness_tests::",
            )

    def test_full_reconciles_every_harness_including_explicit_zero(self):
        evidence = verify_suite(
            parse_inventory(FULL_LIST),
            parse_inventory(FULL_IGNORED),
            parse_results(FULL_RUN),
        )
        self.assertEqual(evidence["harnesses"], 3)
        self.assertEqual((evidence["listed_cases"], evidence["passed"], evidence["ignored"]), (4, 3, 1))
        with self.assertRaisesRegex(ValueError, "harness mismatch"):
            verify_suite(
                parse_inventory(FULL_LIST),
                parse_inventory(FULL_IGNORED),
                parse_results(FULL_RUN.split(DOCS)[0]),
            )
        without_zero_harness = FULL_RUN.replace(
            f"{INTEGRATION}\nrunning 0 tests\ntest result: ok. 0 passed; 0 failed; "
            "0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
            "",
        )
        with self.assertRaisesRegex(ValueError, "harness mismatch"):
            verify_suite(
                parse_inventory(FULL_LIST),
                parse_inventory(FULL_IGNORED),
                parse_results(without_zero_harness),
            )
        with self.assertRaisesRegex(ValueError, "differs"):
            verify_suite(
                parse_inventory(FULL_LIST),
                parse_inventory(FULL_IGNORED),
                parse_results(FULL_RUN.replace("0 passed; 0 failed", "1 passed; 0 failed")),
            )
        without_ignored = FULL_IGNORED.replace(
            "core_catalog::segment_witness_tests::ignored: test\n1 test, 0 benchmarks",
            "0 tests, 0 benchmarks",
        )
        with self.assertRaisesRegex(ValueError, "differs"):
            verify_suite(
                parse_inventory(FULL_LIST),
                parse_inventory(without_ignored),
                parse_results(FULL_RUN),
            )

    def test_duplicate_or_bad_inventory_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate inventory harness"):
            parse_inventory(LIB_LIST + LIB_LIST)
        with self.assertRaisesRegex(ValueError, "footer does not match"):
            parse_inventory(LIB_LIST.replace("3 tests, 0 benchmarks", "2 tests, 0 benchmarks"))
        with self.assertRaisesRegex(ValueError, "subset"):
            verify_suite(
                parse_inventory(FOCUSED_LIST),
                parse_inventory(FOCUSED_IGNORED.replace("::ignored", "::unlisted")),
                parse_results(FOCUSED_RUN),
                reference=parse_inventory(LIB_LIST),
                prefix="core_catalog::segment_witness_tests::",
            )

    def test_colored_headers_and_interleaved_cargo_status(self):
        colored = LIB_LIST.replace("Running", "\x1b[1m\x1b[92mRunning\x1b[0m")
        self.assertEqual(len(parse_inventory(colored)), 1)
        interleaved = f"""
{LIB}
{INTEGRATION}
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""
        self.assertEqual(len(parse_results(interleaved)), 2)


if __name__ == "__main__":
    unittest.main()
