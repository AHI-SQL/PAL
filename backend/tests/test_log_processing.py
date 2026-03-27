from pathlib import Path
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "backend" / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pal_backend.log_processing import analyze_blg, analyze_csv, generate_html_report


class LogProcessingTests(unittest.TestCase):
    def test_analyze_csv(self) -> None:
        temp_dir = ROOT / "resources" / "uploads" / f"test_{uuid.uuid4().hex}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        csv_path = temp_dir / "sample.csv"
        try:
            csv_path.write_text("Time,CPU,Memory\n10:00,20,1024\n10:01,45,1000\n", encoding="utf-8")

            result = analyze_csv(csv_path)

            self.assertEqual(result["log_type"], "csv")
            self.assertEqual(result["column_count"], 3)
            self.assertEqual(result["row_count"], 2)
            self.assertEqual(result["preview_columns"], ["Time", "CPU", "Memory"])
        finally:
            if csv_path.exists():
                csv_path.unlink()
            if temp_dir.exists():
                temp_dir.rmdir()

    def test_analyze_blg(self) -> None:
        blg_path = ROOT / "PAL2" / "PALWizard" / "bin" / "Debug" / "SampleLog.blg"
        result = analyze_blg(blg_path)

        self.assertEqual(result["log_type"], "blg")
        self.assertEqual(result["samples"], "11")
        self.assertGreater(result["counter_count"], 0)
        self.assertIn("Memory", result["counter_objects"])

    def test_generate_html_report(self) -> None:
        report_dir = ROOT / "resources" / "reports" / f"test_{uuid.uuid4().hex}"
        report_dir.mkdir(parents=True, exist_ok=True)
        try:
            report = generate_html_report(
                report_dir,
                {
                    "file_name": "sample.blg",
                    "log_type": "blg",
                    "begin": "2026-03-26 10:00:00",
                    "end": "2026-03-26 10:10:00",
                    "samples": "12",
                    "counter_count": 2,
                    "counter_objects": ["Memory", "Processor"],
                    "preview_counters": ["\\\\HOST\\Memory\\Available MBytes"],
                },
            )

            self.assertTrue(report["path"].exists())
            html = report["path"].read_text(encoding="utf-8")
            self.assertIn("PAL Modern Report", html)
            self.assertIn("sample.blg", html)
        finally:
            for child in report_dir.glob("*"):
                child.unlink()
            report_dir.rmdir()


if __name__ == "__main__":
    unittest.main()
