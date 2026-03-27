from __future__ import annotations

import csv
from datetime import datetime, UTC
from html import escape
from pathlib import Path
import re
import shutil
import subprocess
from uuid import uuid4


SUPPORTED_LOG_EXTENSIONS = {".csv", ".blg"}


def save_uploaded_file(upload_dir: Path, original_name: str, file_object) -> dict:
    suffix = Path(original_name or "").suffix.lower()
    if suffix not in SUPPORTED_LOG_EXTENSIONS:
        raise ValueError("Unsupported file type. Use .csv or .blg")

    upload_dir.mkdir(parents=True, exist_ok=True)
    sanitized_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(original_name).stem).strip("._") or "upload"
    stored_name = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex}_{sanitized_stem}{suffix}"
    stored_path = upload_dir / stored_name

    with stored_path.open("wb") as handle:
        shutil.copyfileobj(file_object, handle)

    return {
        "original_name": original_name,
        "stored_name": stored_name,
        "path": stored_path,
        "size_bytes": stored_path.stat().st_size,
    }


def analyze_uploaded_log(file_path: Path, original_name: str | None = None) -> dict:
    suffix = file_path.suffix.lower()
    if suffix == ".csv":
        result = analyze_csv(file_path)
    elif suffix == ".blg":
        result = analyze_blg(file_path)
    else:
        raise ValueError("Unsupported file type. Use .csv or .blg")

    result["file_name"] = original_name or file_path.name
    result["stored_path"] = str(file_path)
    result["size_bytes"] = file_path.stat().st_size
    return result


def generate_html_report(report_dir: Path, analysis: dict) -> dict:
    report_dir.mkdir(parents=True, exist_ok=True)
    source_name = analysis.get("file_name", "report")
    sanitized_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(source_name).stem).strip("._") or "report"
    report_name = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex}_{sanitized_stem}.html"
    report_path = report_dir / report_name

    if analysis.get("log_type") == "csv":
        body = _build_csv_report_body(analysis)
    else:
        body = _build_blg_report_body(analysis)

    report_path.write_text(
        _build_report_shell(title=f"PAL Report - {source_name}", body=body),
        encoding="utf-8",
    )

    return {
        "file_name": report_name,
        "path": report_path,
    }


def analyze_csv(file_path: Path) -> dict:
    sample_text = file_path.read_text(encoding="utf-8-sig", errors="replace")
    dialect = csv.excel
    try:
        dialect = csv.Sniffer().sniff(sample_text[:4096])
    except csv.Error:
        pass

    with file_path.open("r", encoding="utf-8-sig", newline="", errors="replace") as handle:
        reader = csv.reader(handle, dialect)
        try:
            columns = next(reader)
        except StopIteration:
            columns = []
            rows = []
        else:
            rows = []
            row_count = 0
            for row in reader:
                row_count += 1
                if len(rows) < 5:
                    rows.append(row[:8])

    preview_columns = columns[:8]
    return {
        "log_type": "csv",
        "column_count": len(columns),
        "row_count": row_count if columns else 0,
        "columns": columns,
        "preview_columns": preview_columns,
        "preview_rows": rows if columns else [],
        "delimiter": getattr(dialect, "delimiter", ","),
    }


def analyze_blg(file_path: Path) -> dict:
    info_output = _run_relog([str(file_path)])
    counter_output = _run_relog([str(file_path), "-q"])

    metadata = {
        "begin": "",
        "end": "",
        "samples": "",
    }
    counters: list[str] = []

    for line in info_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Begin:"):
            metadata["begin"] = stripped.removeprefix("Begin:").strip()
        elif stripped.startswith("End:"):
            metadata["end"] = stripped.removeprefix("End:").strip()
        elif stripped.startswith("Samples:"):
            metadata["samples"] = stripped.removeprefix("Samples:").strip()

    for line in counter_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("\\\\"):
            counters.append(stripped)

    counter_objects = _extract_counter_objects(counters)

    return {
        "log_type": "blg",
        "begin": metadata["begin"],
        "end": metadata["end"],
        "samples": metadata["samples"],
        "counter_count": len(counters),
        "counter_objects": counter_objects,
        "preview_counters": counters[:20],
    }


def _run_relog(arguments: list[str]) -> str:
    process = subprocess.run(
        ["relog.exe", *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    return process.stdout


def _extract_counter_objects(counters: list[str]) -> list[str]:
    objects: list[str] = []
    seen: set[str] = set()
    for counter in counters:
        parts = counter.split("\\")
        if len(parts) < 4:
            continue
        object_name = parts[3].split("(", 1)[0]
        object_key = object_name.lower()
        if object_key not in seen:
            seen.add(object_key)
            objects.append(object_name)
    return objects


def _build_report_shell(title: str, body: str) -> str:
    safe_title = escape(title)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{safe_title}</title>
    <style>
      :root {{
        --bg: #f4efe7;
        --card: #fffaf4;
        --line: #d8cfc2;
        --text: #243246;
        --muted: #5f6d7f;
        --accent: #0d6b78;
        --warm: #b9692d;
      }}
      body {{
        margin: 0;
        font-family: "Segoe UI Variable", "Segoe UI", sans-serif;
        color: var(--text);
        background: linear-gradient(180deg, #faf5ef, var(--bg));
      }}
      main {{
        max-width: 1100px;
        margin: 0 auto;
        padding: 2rem;
      }}
      header {{
        padding: 1.6rem;
        border: 1px solid var(--line);
        border-radius: 24px;
        background: var(--card);
      }}
      h1, h2, h3 {{
        margin-top: 0;
      }}
      .kicker {{
        text-transform: uppercase;
        letter-spacing: 0.12em;
        color: var(--accent);
        font-size: 0.8rem;
        font-weight: 700;
      }}
      .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 1rem;
        margin-top: 1rem;
      }}
      .card {{
        padding: 1rem;
        border: 1px solid var(--line);
        border-radius: 18px;
        background: var(--card);
      }}
      .chip-list {{
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
      }}
      .chip {{
        display: inline-block;
        padding: 0.45rem 0.7rem;
        border-radius: 999px;
        background: #eef6f7;
        border: 1px solid #d3e7ea;
      }}
      .chip.warm {{
        background: #fbefe4;
        border-color: #f0d6bc;
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 1rem;
        background: white;
      }}
      th, td {{
        text-align: left;
        padding: 0.75rem;
        border-bottom: 1px solid var(--line);
        vertical-align: top;
      }}
      ul {{
        margin: 0.75rem 0 0;
      }}
      .muted {{
        color: var(--muted);
      }}
      code {{
        white-space: pre-wrap;
        word-break: break-word;
      }}
    </style>
  </head>
  <body>
    <main>
      {body}
    </main>
  </body>
</html>
"""


def _build_csv_report_body(analysis: dict) -> str:
    columns = analysis.get("preview_columns", [])
    rows = analysis.get("preview_rows", [])
    header_html = "".join(f"<th>{escape(str(column))}</th>" for column in columns)
    rows_html = "".join(
        "<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    if not rows_html:
        rows_html = '<tr><td colspan="8">No rows available.</td></tr>'

    return f"""
      <header>
        <p class="kicker">PAL Modern Report</p>
        <h1>{escape(analysis.get("file_name", "CSV import"))}</h1>
        <p class="muted">HTML report generated automatically after CSV import.</p>
      </header>
      <section class="grid">
        <article class="card"><h2>Type</h2><p>CSV</p></article>
        <article class="card"><h2>Rows</h2><p>{escape(str(analysis.get("row_count", 0)))}</p></article>
        <article class="card"><h2>Columns</h2><p>{escape(str(analysis.get("column_count", 0)))}</p></article>
        <article class="card"><h2>Delimiter</h2><p>{escape(str(analysis.get("delimiter", ",")))}</p></article>
      </section>
      <section class="card">
        <h2>Detected columns</h2>
        <div class="chip-list">
          {''.join(f'<span class="chip warm">{escape(str(column))}</span>' for column in columns) or '<span class="chip">No columns detected</span>'}
        </div>
      </section>
      <section class="card">
        <h2>Preview of the first rows</h2>
        <table>
          <thead><tr>{header_html}</tr></thead>
          <tbody>{rows_html}</tbody>
        </table>
      </section>
    """


def _build_blg_report_body(analysis: dict) -> str:
    objects_html = "".join(f'<span class="chip warm">{escape(str(item))}</span>' for item in analysis.get("counter_objects", []))
    counters_html = "".join(f"<li><code>{escape(str(item))}</code></li>" for item in analysis.get("preview_counters", []))
    if not counters_html:
        counters_html = "<li>No counters detected.</li>"

    return f"""
      <header>
        <p class="kicker">PAL Modern Report</p>
        <h1>{escape(analysis.get("file_name", "BLG import"))}</h1>
        <p class="muted">HTML report generated automatically after BLG import. This is a summary report, not yet the full PAL analysis.</p>
      </header>
      <section class="grid">
        <article class="card"><h2>Type</h2><p>BLG</p></article>
        <article class="card"><h2>Start</h2><p>{escape(str(analysis.get("begin", "n/a")))}</p></article>
        <article class="card"><h2>End</h2><p>{escape(str(analysis.get("end", "n/a")))}</p></article>
        <article class="card"><h2>Samples</h2><p>{escape(str(analysis.get("samples", "n/a")))}</p></article>
      </section>
      <section class="grid">
        <article class="card"><h2>Counters</h2><p>{escape(str(analysis.get("counter_count", 0)))}</p></article>
        <article class="card"><h2>Objects</h2><p>{escape(str(len(analysis.get("counter_objects", []))))}</p></article>
      </section>
      <section class="card">
        <h2>Detected objects</h2>
        <div class="chip-list">
          {objects_html or '<span class="chip">No objects detected</span>'}
        </div>
      </section>
      <section class="card">
        <h2>Counter preview</h2>
        <ul>{counters_html}</ul>
      </section>
    """
