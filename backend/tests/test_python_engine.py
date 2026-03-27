from pathlib import Path
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "backend" / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pal_backend.python_engine import load_perfmon_dataset, run_python_pal_analysis


class PythonEngineTests(unittest.TestCase):
    def test_load_perfmon_dataset(self) -> None:
        csv_path = ROOT / "resources" / "uploads" / "sample_relog.csv"
        dataset = load_perfmon_dataset(csv_path)

        self.assertGreater(len(dataset.timestamps), 0)
        self.assertGreater(len(dataset.series), 0)
        self.assertGreater(dataset.analysis_interval_seconds, 0)
        self.assertTrue(any(series.counter_object == "Memory" for series in dataset.series))

    def test_run_python_pal_analysis(self) -> None:
        csv_path = ROOT / "resources" / "uploads" / "sample_relog.csv"
        threshold_dir = ROOT / "resources" / "thresholds"
        report_dir = ROOT / "resources" / "reports" / f"test_python_{uuid.uuid4().hex}"
        report_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = run_python_pal_analysis(
                threshold_dir=threshold_dir,
                report_root=report_dir,
                log_path=csv_path,
                threshold_file_name="QuickSystemOverview.xml",
                question_answers={
                    "OS": "Windows Server",
                    "PhysicalMemory": "16",
                    "UserVa": "2048",
                },
            )

            report_path = report_dir / result["report_file_name"]
            self.assertEqual(result["engine"], "python")
            self.assertEqual(result["threshold_file_used"], "QuickSystemOverview.xml")
            self.assertGreater(result["analysis_count"], 0)
            self.assertTrue(report_path.exists())
            html = report_path.read_text(encoding="utf-8")
            self.assertIn("PAL Python Engine", html)
            self.assertIn("PAL Analysis Report", html)
            self.assertIn("Time", html)
            self.assertIn("Period:", html)
            self.assertIn("Current value:", html)
            self.assertIn("data-pal-chart", html)
            self.assertIn("new Chart", html)
        finally:
            for path in sorted(report_dir.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()

    def test_run_python_pal_analysis_matches_sql_regex_datasources(self) -> None:
        threshold_dir = ROOT / "resources" / "thresholds"
        report_dir = ROOT / "resources" / "reports" / f"test_python_sql_{uuid.uuid4().hex}"
        report_dir.mkdir(parents=True, exist_ok=True)
        csv_path = report_dir / "sql_sample.csv"
        csv_path.write_text(
            "\n".join(
                [
                    '"PDH-CSV 4.0","\\\\TEST-SQL\\MSSQL$APP:Buffer Manager\\Page life expectancy","\\\\TEST-SQL\\MSSQL$APP:Buffer Manager\\Lazy writes/sec","\\\\TEST-SQL\\MSSQL$APP:SQL Statistics\\Batch Requests/sec","\\\\TEST-SQL\\MSSQL$APP:Memory Manager\\Memory Grants Pending"',
                    '"03/26/2026 10:00:00.000","250","24","1200","2"',
                    '"03/26/2026 10:01:00.000","275","18","1150","1"',
                    '"03/26/2026 10:02:00.000","290","12","1180","0"',
                ]
            ),
            encoding="utf-8",
        )

        try:
            result = run_python_pal_analysis(
                threshold_dir=threshold_dir,
                report_root=report_dir,
                log_path=csv_path,
                threshold_file_name="SQLServer2012.xml",
                question_answers={},
            )

            report_path = report_dir / result["report_file_name"]
            self.assertTrue(report_path.exists())
            self.assertGreater(result["analysis_count"], 0)
            self.assertGreater(result["alert_count"], 0)

            html = report_path.read_text(encoding="utf-8")
            self.assertIn("SQLServer:Buffer Manager Page life expectancy", html)
            self.assertIn("\\\\TEST-SQL\\MSSQL$APP:Buffer Manager\\Page life expectancy", html)
            self.assertIn("\\\\TEST-SQL\\MSSQL$APP:Memory Manager\\Memory Grants Pending", html)
            self.assertIn("IntersectionObserver", html)
            self.assertIn("responsive: false", html)
        finally:
            for path in sorted(report_dir.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()


if __name__ == "__main__":
    unittest.main()
