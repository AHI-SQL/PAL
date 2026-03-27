from __future__ import annotations

import cgi
from functools import cached_property
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import unquote, urlparse

from .log_processing import analyze_uploaded_log, generate_html_report, save_uploaded_file
from .python_engine import run_python_pal_analysis
from .thresholds import ThresholdRepository


class PalRequestHandler(SimpleHTTPRequestHandler):
    server_version = "PALModern/0.1"

    @cached_property
    def repo(self) -> ThresholdRepository:
        return ThresholdRepository(self.server.threshold_dir)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self._handle_api(parsed.path)
            return
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/uploads":
            self._handle_upload()
            return
        self._json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def translate_path(self, path: str) -> str:
        parsed = urlparse(path)
        if parsed.path.startswith("/reports/"):
            return self._resolve_static_path(self.server.report_dir, parsed.path.removeprefix("/reports/"))

        relative = parsed.path.lstrip("/")
        if not relative:
            return str(self.server.frontend_dir / "index.html")
        target = Path(self._resolve_static_path(self.server.frontend_dir, relative))
        if target.exists():
            return str(target)
        return str(self.server.frontend_dir / "index.html")

    def _handle_api(self, path: str) -> None:
        try:
            if path == "/api/health":
                self._json({"status": "ok"})
                return

            if path == "/api/threshold-files":
                files = [item.to_dict() for item in self.repo.list_threshold_files()]
                self._json(
                    {
                        "items": files,
                        "overview": {
                            "threshold_file_count": len(files),
                            "analysis_count": sum(item["analysis_count"] for item in files),
                            "question_count": sum(item["question_count"] for item in files),
                        },
                    }
                )
                return

            if path.startswith("/api/threshold-files/"):
                file_name = unquote(path.removeprefix("/api/threshold-files/"))
                detail = self.repo.get_threshold_file(file_name)
                payload = detail.to_dict()
                payload["category_breakdown"] = self.repo.category_breakdown(detail)
                self._json(payload)
                return

            self._json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
        except FileNotFoundError as exc:
            self._json({"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # pragma: no cover
            self._json({"error": f"Unexpected server error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_upload(self) -> None:
        try:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
                },
            )

            if "file" not in form:
                raise ValueError("No file was uploaded.")

            uploaded = form["file"]
            if isinstance(uploaded, list):
                uploaded = uploaded[0]

            if not uploaded.filename or uploaded.file is None:
                raise ValueError("Uploaded file is empty.")

            stored = save_uploaded_file(self.server.upload_dir, uploaded.filename, uploaded.file)
            analysis = analyze_uploaded_log(stored["path"], original_name=stored["original_name"])
            analysis["stored_name"] = stored["stored_name"]

            threshold_file_name = self._get_form_value(form, "threshold_file")
            run_historical = self._coerce_bool(self._get_form_value(form, "run_historical"), default=False)
            question_answers = self._parse_question_answers(self._get_form_value(form, "question_answers"))

            if run_historical:
                threshold_file_name = threshold_file_name or "QuickSystemOverview.xml"
                auto_selected_threshold = ""
                if threshold_file_name == "QuickSystemOverview.xml":
                    suggested_threshold = self._suggest_threshold_file(analysis)
                    if suggested_threshold:
                        threshold_file_name = suggested_threshold
                        auto_selected_threshold = suggested_threshold

                python_report = run_python_pal_analysis(
                    threshold_dir=self.server.threshold_dir,
                    report_root=self.server.report_dir,
                    log_path=stored["path"],
                    threshold_file_name=threshold_file_name,
                    question_answers=question_answers,
                )
                analysis["report_url"] = python_report["report_url"]
                analysis["report_file_name"] = python_report["report_file_name"]
                analysis["report_mode"] = "python_full"
                analysis["threshold_file_used"] = python_report["threshold_file_used"]
                analysis["analysis_count"] = python_report["analysis_count"]
                analysis["triggered_analysis_count"] = python_report["triggered_analysis_count"]
                analysis["alert_count"] = python_report["alert_count"]
                analysis["engine"] = python_report["engine"]
                if auto_selected_threshold:
                    analysis["threshold_auto_selected"] = auto_selected_threshold
                    message = f"File uploaded successfully and PAL Python report generated with auto-selected threshold {auto_selected_threshold}."
                else:
                    message = "File uploaded successfully and PAL Python report generated."
            else:
                report = generate_html_report(self.server.report_dir, analysis)
                analysis["report_url"] = f"/reports/{report['file_name']}"
                analysis["report_file_name"] = report["file_name"]
                analysis["report_mode"] = "summary"
                message = "File uploaded successfully and HTML report generated."

            self._json(
                {
                    "message": message,
                    "file": analysis,
                },
                status=HTTPStatus.CREATED,
            )
        except ValueError as exc:
            self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # pragma: no cover
            self._json({"error": f"Unexpected server error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _resolve_static_path(base_dir: Path, relative_path: str) -> str:
        target = (base_dir / relative_path).resolve()
        try:
            target.relative_to(base_dir.resolve())
        except ValueError:
            return str(base_dir / "index.html")
        return str(target)

    @staticmethod
    def _get_form_value(form: cgi.FieldStorage, key: str) -> str:
        if key not in form:
            return ""
        value = form[key]
        if isinstance(value, list):
            value = value[0]
        return value.value if hasattr(value, "value") and value.value is not None else ""

    @staticmethod
    def _coerce_bool(value: str, default: bool = False) -> bool:
        if value == "":
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _parse_question_answers(raw_value: str) -> dict[str, str | bool]:
        if not raw_value:
            return {}
        parsed = json.loads(raw_value)
        if not isinstance(parsed, dict):
            raise ValueError("question_answers must be a JSON object.")

        normalized: dict[str, str | bool] = {}
        for key, value in parsed.items():
            if isinstance(value, bool):
                normalized[str(key)] = value
            elif value is None:
                normalized[str(key)] = ""
            else:
                normalized[str(key)] = str(value)
        return normalized

    def _suggest_threshold_file(self, analysis: dict) -> str:
        counter_objects = [str(item).lower() for item in analysis.get("counter_objects", [])]
        has_sql_objects = any(item.startswith("mssql$") or item.startswith("sqlserver:") for item in counter_objects)
        if not has_sql_objects:
            return ""

        preferred_files = ["SQLServer2012.xml", "SQLServer2008R2.xml", "SQLServer.xml", "SQLServer2014.xml"]
        if any(
            token in item
            for item in counter_objects
            for token in ("availability replica", "database replica", "buffer node", "memory node")
        ):
            preferred_files = ["SQLServer2014.xml", "SQLServer2012.xml", "SQLServer2008R2.xml", "SQLServer.xml"]

        for candidate in preferred_files:
            if (self.server.threshold_dir / candidate).exists():
                return candidate
        return ""


def build_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    project_root = Path(__file__).resolve().parents[3]
    frontend_dir = project_root / "frontend"
    threshold_dir = project_root / "resources" / "thresholds"
    upload_dir = project_root / "resources" / "uploads"
    report_dir = project_root / "resources" / "reports"
    legacy_pal_dir = project_root / "PAL2" / "PALWizard" / "bin" / "Debug"
    upload_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer((host, port), PalRequestHandler)
    server.frontend_dir = frontend_dir
    server.threshold_dir = threshold_dir
    server.upload_dir = upload_dir
    server.report_dir = report_dir
    server.legacy_pal_dir = legacy_pal_dir
    return server


def main() -> None:
    server = build_server()
    host, port = server.server_address
    print(f"PAL modern dev server running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping PAL modern dev server...")
    finally:
        server.server_close()
