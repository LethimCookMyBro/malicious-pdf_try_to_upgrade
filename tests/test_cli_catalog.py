import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from malicious_pdf import generators_advanced
from malicious_pdf.av_safety import av_report
from malicious_pdf.catalog import DEFENDER_OBSERVED_DETECTIONS, selected_test_cases


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "malicious-pdf.py"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


class CatalogCliTests(unittest.TestCase):
    def test_catalog_counts_and_eicar_opt_in(self):
        default = selected_test_cases("https://example.com")
        with_eicar = selected_test_cases("https://example.com", include_eicar=True)

        self.assertEqual(72, len(default))
        self.assertEqual(73, len(with_eicar))
        self.assertNotIn("test11.pdf", [test.filename for test in default])
        self.assertIn("test11.pdf", [test.filename for test in with_eicar])

    def test_list_tests_does_not_write_payload_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_cli("https://example.com", "--output-dir", tmpdir, "--list-tests")

            self.assertEqual(72, len(result.stdout.splitlines()))
            self.assertEqual([], list(Path(tmpdir).iterdir()))

    def test_eicar_is_opt_in(self):
        default = run_cli("https://example.com", "--list-tests").stdout.splitlines()
        with_eicar = run_cli(
            "https://example.com",
            "--list-tests",
            "--include-eicar",
        ).stdout.splitlines()

        self.assertNotIn("test11.pdf", default)
        self.assertIn("test11.pdf", with_eicar)
        self.assertEqual(len(default) + 1, len(with_eicar))

    def test_profiles_filter_catalog(self):
        acrobat = selected_test_cases("https://example.com", profile="acrobat")
        stealth = selected_test_cases("https://example.com", profile="stealth")
        acrobat_names = [test.filename for test in acrobat]
        stealth_names = [test.filename for test in stealth]

        self.assertEqual(29, len(acrobat))
        self.assertEqual(29, len(stealth))
        self.assertIn("test49_1.pdf", acrobat_names)
        self.assertIn("test49_3.pdf", stealth_names)

    def test_fingerprint_generators_have_js_helper(self):
        calls = []
        original = generators_advanced._js_callback_pdf

        def fake_js_callback_pdf(filename, host, js_code, label):
            calls.append((filename, host, js_code, label))

        generators_advanced._js_callback_pdf = fake_js_callback_pdf
        try:
            generators_advanced.create_malpdf49_1("ignored.pdf", "https://example.com")
            generators_advanced.create_malpdf49_2("ignored.pdf", "https://example.com")
            generators_advanced.create_malpdf49_3("ignored.pdf", "https://example.com")
        finally:
            generators_advanced._js_callback_pdf = original

        self.assertEqual(3, len(calls))
        self.assertEqual(
            ["js-collab-readonly", "js-plugins", "js-viewer-fingerprint"],
            [call[3] for call in calls],
        )

    def test_exclude_defender_observed_filters_known_alerts(self):
        selected = selected_test_cases(
            "https://example.com",
            exclude_defender_observed=True,
        )
        selected_keys = {test.key for test in selected}

        self.assertTrue(DEFENDER_OBSERVED_DETECTIONS)
        self.assertFalse(selected_keys & DEFENDER_OBSERVED_DETECTIONS)
        self.assertEqual(62, len(selected))

    def test_av_report_schema(self):
        report = av_report(selected_test_cases("https://example.com"))

        self.assertEqual(
            {"total": 72, "defender_observed": 10, "not_observed": 62},
            report["summary"],
        )
        self.assertEqual(
            {
                "key": "3",
                "filename": "test3.pdf",
                "status": "defender-observed",
                "description": "JavaScript injection - /OpenAction calls app.openDoc() on remote URL",
            },
            report["files"][3],
        )

    def test_av_report_does_not_write_payload_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_cli("https://example.com", "--output-dir", tmpdir, "--av-report")

            self.assertIn("test3.pdf", result.stdout)
            self.assertIn("defender-observed", result.stdout)
            self.assertIn("SUMMARY", result.stdout)
            self.assertIn("defender_observed=10", result.stdout)
            self.assertIn("not_observed=62", result.stdout)
            self.assertEqual([], list(Path(tmpdir).iterdir()))

    def test_av_report_json_writes_report_without_payload_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "av-report.json"
            payload_dir = Path(tmpdir) / "payloads"

            result = run_cli(
                "https://example.com",
                "--output-dir",
                str(payload_dir),
                "--av-report-json",
                str(report_path),
            )
            report = json.loads(report_path.read_text())

            self.assertIn("Wrote AV report JSON", result.stdout)
            self.assertEqual(72, report["summary"]["total"])
            self.assertEqual(10, report["summary"]["defender_observed"])
            self.assertEqual(62, report["summary"]["not_observed"])
            self.assertEqual("test3.pdf", report["files"][3]["filename"])
            self.assertEqual("defender-observed", report["files"][3]["status"])
            self.assertFalse(payload_dir.exists())

    def test_exclude_defender_observed_prints_generation_notice(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_cli(
                "https://example.com",
                "--output-dir",
                tmpdir,
                "--exclude-defender-observed",
            )

            self.assertIn("Skipping 10 Defender-observed test(s)", result.stdout)


if __name__ == "__main__":
    unittest.main()
