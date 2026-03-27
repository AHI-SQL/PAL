from __future__ import annotations

import os
from pathlib import Path
import subprocess
from uuid import uuid4


def run_legacy_pal_analysis(
    script_dir: Path,
    report_root: Path,
    log_path: Path,
    threshold_file_name: str,
    question_answers: dict[str, str | bool] | None = None,
    analysis_interval: str = "AUTO",
    number_of_threads: int | None = None,
) -> dict:
    if not log_path.exists():
        raise FileNotFoundError(f"Uploaded log not found: {log_path}")

    threshold_path = script_dir / threshold_file_name
    if not threshold_path.exists():
        raise FileNotFoundError(f"Threshold file not found for legacy PAL: {threshold_file_name}")

    run_id = uuid4().hex
    output_dir = report_root / "legacy" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    report_name = f"{log_path.stem}_PAL_FULL_{run_id}.htm"
    xml_name = f"{log_path.stem}_PAL_FULL_{run_id}.xml"

    command = [
        "powershell.exe",
        "-ExecutionPolicy",
        "Bypass",
        "-NoProfile",
        "-File",
        ".\\PAL.ps1",
        "-Log",
        str(log_path),
        "-ThresholdFile",
        threshold_file_name,
        "-AnalysisInterval",
        analysis_interval,
        "-IsOutputHtml",
        "$True",
        "-HtmlOutputFileName",
        report_name,
        "-IsOutputXml",
        "$False",
        "-XmlOutputFileName",
        xml_name,
        "-OutputDir",
        str(output_dir),
        "-AllCounterStats",
        "$False",
        "-NumberOfThreads",
        str(number_of_threads or max(1, os.cpu_count() or 1)),
        "-IsLowPriority",
        "$True",
        "-DisplayReport",
        "$False",
    ]

    for key, value in sorted((question_answers or {}).items()):
        command.append(f"-{key}")
        if isinstance(value, bool):
            command.append("$True" if value else "$False")
        else:
            command.append(str(value))

    process = subprocess.run(
        command,
        cwd=script_dir,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=1800,
    )

    report_path = output_dir / report_name
    if not report_path.exists():
        raise RuntimeError("Legacy PAL finished without producing the expected HTML report.")

    relative_report = report_path.relative_to(report_root)
    return {
        "report_file_name": report_name,
        "report_path": report_path,
        "report_url": f"/reports/{relative_report.as_posix()}",
        "output_dir": output_dir,
        "stdout_tail": process.stdout[-4000:],
        "threshold_file_used": threshold_file_name,
    }

