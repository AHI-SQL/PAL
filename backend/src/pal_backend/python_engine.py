from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from html import escape
import json
from pathlib import Path
import re
import subprocess
from uuid import uuid4

from .models import Analysis, DataSource, Question, Threshold
from .thresholds import ThresholdRepository


AUTO_ANALYSIS_TIME_SLICES = 30
BYTES_IN_KB = 1024
BYTES_IN_MB = 1024 * 1024
BYTES_IN_GB = 1024 * 1024 * 1024

PERFMON_HEADER_PATTERN = re.compile(r"PDH-CSV", re.IGNORECASE)
COUNTER_PATH_PATTERN = re.compile(
    r"^(?:\\\\(?P<computer>[^\\]+))?\\(?P<object>[^\\(]+?)(?:\((?P<instance>.*)\))?\\(?P<counter>.+)$"
)
STATIC_THRESHOLD_PATTERN = re.compile(
    r"StaticThreshold\s+"
    r"-CollectionOfCounterInstances\s+\$(?P<collection>[A-Za-z0-9_]+)\s+"
    r"-Operator\s+'(?P<operator>[A-Za-z]+)'\s+"
    r"-Threshold\s+(?P<threshold>[^\r\n]+?)"
    r"(?:\s+-IsTrendOnly\s+\$(?P<trend>True|False))?"
    r"(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(slots=True)
class ParsedCounterPath:
    computer: str
    object_name: str
    instance: str
    counter_name: str
    raw_path: str

    @property
    def canonical_path(self) -> str:
        if self.instance:
            return f"\\\\{self.computer}\\{self.object_name}({self.instance})\\{self.counter_name}"
        return f"\\\\{self.computer}\\{self.object_name}\\{self.counter_name}"


@dataclass(slots=True)
class CounterSeries:
    counter_path: str
    counter_computer: str
    counter_object: str
    counter_instance: str
    counter_name: str
    data_type: str
    timestamps: list[datetime]
    values: list[float | None]
    quantized_times: list[datetime]
    quantized_min: list[float | None]
    quantized_avg: list[float | None]
    quantized_max: list[float | None]
    quantized_trend: list[float | None]
    minimum: float | None
    average: float | None
    maximum: float | None
    trend: float | None


@dataclass(slots=True)
class AlertEvent:
    analysis_name: str
    category: str
    threshold_name: str
    condition: str
    color: str
    priority: int
    counter_path: str
    counter_instance: str
    threshold_value: float | None
    broken_metrics: list[str]
    time_slices: list[int]
    overall_triggered: bool

    def to_summary(self, interval_seconds: int, quantized_times: list[datetime]) -> str:
        parts: list[str] = []
        if self.overall_triggered:
            parts.append("global")
        if self.time_slices:
            slices = ", ".join(_format_time_slice(index, quantized_times, interval_seconds) for index in self.time_slices[:4])
            if len(self.time_slices) > 4:
                slices += f" +{len(self.time_slices) - 4}"
            parts.append(slices)
        if self.broken_metrics:
            parts.append("/".join(self.broken_metrics))
        return " | ".join(parts) if parts else "Triggered"


@dataclass(slots=True)
class AnalysisResult:
    analysis_name: str
    category: str
    description_html: str
    status: str
    primary_datasource: str
    alerts: list[AlertEvent] = field(default_factory=list)
    series: list[CounterSeries] = field(default_factory=list)
    missing_datasources: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PerfmonDataset:
    source_csv: Path
    timestamps: list[datetime]
    quantized_indexes: list[list[int]]
    quantized_times: list[datetime]
    analysis_interval_seconds: int
    series_by_path: dict[str, CounterSeries]

    @property
    def series(self) -> list[CounterSeries]:
        return list(self.series_by_path.values())

    def find_series_for_datasource(self, datasource: DataSource) -> list[CounterSeries]:
        exclude = {item.lower() for item in (datasource.exclude_instances or [])}
        object_expression, instance_expression, counter_expression = _parse_datasource_match_parts(datasource)
        matches: list[CounterSeries] = []
        for series in self.series:
            if not _counter_component_matches(
                actual_value=series.counter_object,
                expected_value=object_expression,
                is_regular_expression=datasource.is_counter_object_regular_expression,
            ):
                continue
            if not _counter_component_matches(
                actual_value=series.counter_name,
                expected_value=counter_expression,
                is_regular_expression=datasource.is_counter_name_regular_expression,
            ):
                continue
            if not _counter_instance_matches(
                actual_value=series.counter_instance,
                expected_value=instance_expression,
                is_regular_expression=datasource.is_counter_instance_regular_expression,
            ):
                continue
            if exclude and series.counter_instance.lower() in exclude:
                continue
            matches.append(_clone_series(series, data_type=datasource.data_type or "double", dataset=self))
        matches.sort(key=lambda item: (item.counter_instance.lower(), item.counter_path.lower()))
        return matches


@dataclass(slots=True)
class ThresholdSpec:
    collection_name: str
    operator: str
    threshold_value: float
    is_trend_only: bool = False


def _parse_datasource_match_parts(datasource: DataSource) -> tuple[str, str, str]:
    source_path = datasource.regular_expression_counter_path or datasource.expression_path
    object_name, instance_name, counter_name = _split_counter_path_components(source_path)
    return object_name.strip(), instance_name.strip(), counter_name.strip()


def _split_counter_path_components(counter_path: str) -> tuple[str, str, str]:
    path = counter_path.strip()
    if not path:
        raise ValueError("Unrecognized counter path: <empty>")

    body = _remove_counter_computer_segment(path).strip("\\")
    last_separator = body.rfind("\\")
    if last_separator < 0:
        raise ValueError(f"Unrecognized counter path: {counter_path}")

    object_with_instance = body[:last_separator]
    counter_name = body[last_separator + 1 :]
    if not object_with_instance:
        raise ValueError(f"Unrecognized counter path: {counter_path}")

    if not object_with_instance.endswith(")"):
        return object_with_instance, "", counter_name

    balance = 0
    instance_start = -1
    for index in range(len(object_with_instance) - 1, -1, -1):
        character = object_with_instance[index]
        if character == ")":
            balance += 1
        elif character == "(":
            balance -= 1
            if balance == 0:
                instance_start = index
                break

    if instance_start <= 0:
        return object_with_instance, "", counter_name

    return (
        object_with_instance[:instance_start],
        object_with_instance[instance_start + 1 : -1],
        counter_name,
    )


def _remove_counter_computer_segment(counter_path: str) -> str:
    if not counter_path.startswith("\\\\"):
        return counter_path
    remainder = counter_path[2:]
    separator_index = remainder.find("\\")
    if separator_index < 0:
        return ""
    return remainder[separator_index + 1 :]


def _counter_component_matches(actual_value: str, expected_value: str, is_regular_expression: bool) -> bool:
    if not expected_value:
        return True
    if is_regular_expression:
        try:
            return re.search(expected_value, actual_value, flags=re.IGNORECASE) is not None
        except re.error:
            return actual_value.lower() == expected_value.lower()
    return actual_value.lower() == expected_value.lower()


def _counter_instance_matches(actual_value: str, expected_value: str, is_regular_expression: bool) -> bool:
    if expected_value in {"", "*"}:
        return True
    if is_regular_expression:
        try:
            return re.search(expected_value, actual_value, flags=re.IGNORECASE) is not None
        except re.error:
            return actual_value.lower() == expected_value.lower()
    return actual_value.lower() == expected_value.lower()


def run_python_pal_analysis(
    threshold_dir: Path,
    report_root: Path,
    log_path: Path,
    threshold_file_name: str,
    question_answers: dict[str, str | bool] | None = None,
) -> dict:
    repository = ThresholdRepository(threshold_dir)
    detail = repository.get_threshold_file(threshold_file_name)
    answers = _merge_question_answers(detail.questions, question_answers or {})

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{timestamp}_{uuid4().hex}"
    run_dir = report_root / "python" / run_id
    work_dir = run_dir / "work"
    run_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    converted_csv = _ensure_perfmon_csv(log_path, work_dir)
    dataset = load_perfmon_dataset(converted_csv)
    results = _evaluate_analyses(detail.analyses, dataset, answers)
    html = _render_report(
        source_log_path=log_path,
        converted_csv_path=converted_csv,
        threshold_file_name=threshold_file_name,
        answers=answers,
        dataset=dataset,
        results=results,
    )

    report_path = run_dir / "index.html"
    report_path.write_text(html, encoding="utf-8")

    alert_count = sum(len(result.alerts) for result in results)
    triggered_count = sum(1 for result in results if result.alerts)
    return {
        "report_url": f"/reports/python/{run_id}/index.html",
        "report_file_name": f"python/{run_id}/index.html",
        "threshold_file_used": threshold_file_name,
        "engine": "python",
        "analysis_count": len(results),
        "triggered_analysis_count": triggered_count,
        "alert_count": alert_count,
        "converted_csv": str(converted_csv),
    }


def load_perfmon_dataset(csv_path: Path) -> PerfmonDataset:
    with csv_path.open("r", encoding="utf-8-sig", newline="", errors="replace") as handle:
        reader = csv.reader(handle)
        try:
            headers = next(reader)
        except StopIteration as exc:  # pragma: no cover
            raise ValueError("The CSV file is empty.") from exc

        if not headers or not PERFMON_HEADER_PATTERN.search(headers[0]):
            raise ValueError("The Python PAL engine expects a PerfMon CSV (PDH-CSV) or a BLG file.")

        counter_headers = headers[1:]
        parsed_paths = [_parse_counter_path(path) for path in counter_headers]
        timestamps: list[datetime] = []
        column_values: list[list[float | None]] = [[] for _ in counter_headers]

        for row in reader:
            if not row:
                continue
            timestamps.append(_parse_perfmon_timestamp(row[0]))
            for index in range(len(counter_headers)):
                value = row[index + 1] if index + 1 < len(row) else ""
                column_values[index].append(_parse_numeric(value))

    interval_seconds = _auto_analysis_interval_seconds(timestamps)
    quantized_indexes, quantized_times = _generate_quantized_indexes(timestamps, interval_seconds)
    series_by_path: dict[str, CounterSeries] = {}

    for parsed_path, values in zip(parsed_paths, column_values):
        series = _build_series(
            parsed_path=parsed_path,
            timestamps=timestamps,
            values=values,
            data_type="double",
            quantized_indexes=quantized_indexes,
            quantized_times=quantized_times,
            analysis_interval_seconds=interval_seconds,
        )
        series_by_path[series.counter_path] = series

    return PerfmonDataset(
        source_csv=csv_path,
        timestamps=timestamps,
        quantized_indexes=quantized_indexes,
        quantized_times=quantized_times,
        analysis_interval_seconds=interval_seconds,
        series_by_path=series_by_path,
    )


def _evaluate_analyses(
    analyses: list[Analysis],
    dataset: PerfmonDataset,
    answers: dict[str, str | bool],
) -> list[AnalysisResult]:
    results: list[AnalysisResult] = []
    for analysis in analyses:
        if not analysis.enabled:
            continue

        variables: dict[str, list[CounterSeries]] = {}
        missing: list[str] = []

        for datasource in analysis.datasources:
            collection = _resolve_datasource_collection(
                datasource=datasource,
                dataset=dataset,
                variables=variables,
                answers=answers,
            )
            variables[datasource.collection_var_name] = collection
            if datasource.source_type == "CounterLog" and not collection:
                missing.append(datasource.name)

        primary_series = _resolve_primary_series(analysis.primary_datasource, analysis.datasources, variables)
        alerts = [] if missing else _evaluate_thresholds_for_analysis(analysis, variables, dataset, answers)
        results.append(
            AnalysisResult(
                analysis_name=analysis.name,
                category=analysis.category,
                description_html=analysis.description_html,
                status=_determine_status(missing, alerts),
                primary_datasource=analysis.primary_datasource,
                alerts=alerts,
                series=primary_series,
                missing_datasources=missing,
            )
        )

    results.sort(key=lambda item: (0 if item.alerts else 1, item.category.lower(), item.analysis_name.lower()))
    return results


def _resolve_datasource_collection(
    datasource: DataSource,
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
) -> list[CounterSeries]:
    if datasource.source_type == "CounterLog":
        return dataset.find_series_for_datasource(datasource)

    generator = _GENERATED_COLLECTION_BUILDERS.get(datasource.collection_var_name)
    if generator is None:
        return []
    return generator(dataset=dataset, variables=variables, answers=answers, datasource=datasource)


def _resolve_primary_series(
    primary_datasource: str,
    datasources: list[DataSource],
    variables: dict[str, list[CounterSeries]],
) -> list[CounterSeries]:
    for datasource in datasources:
        if datasource.name == primary_datasource or datasource.expression_path == primary_datasource:
            return variables.get(datasource.collection_var_name, [])
    for datasource in datasources:
        collection = variables.get(datasource.collection_var_name, [])
        if collection:
            return collection
    return []


def _evaluate_thresholds_for_analysis(
    analysis: Analysis,
    variables: dict[str, list[CounterSeries]],
    dataset: PerfmonDataset,
    answers: dict[str, str | bool],
) -> list[AlertEvent]:
    alerts: list[AlertEvent] = []
    for threshold in analysis.thresholds:
        special_alerts = _evaluate_special_threshold(analysis, threshold, variables, dataset, answers)
        if special_alerts is not None:
            alerts.extend(special_alerts)
            continue

        match = STATIC_THRESHOLD_PATTERN.search(threshold.code)
        if match is None:
            continue

        threshold_value = _resolve_threshold_value(match.group("threshold"), answers)
        if threshold_value is None:
            continue

        spec = ThresholdSpec(
            collection_name=match.group("collection"),
            operator=match.group("operator").lower(),
            threshold_value=threshold_value,
            is_trend_only=(match.group("trend") or "").lower() == "true",
        )
        alerts.extend(_evaluate_static_threshold(analysis, threshold, spec, variables))

    alerts.sort(key=lambda item: (-item.priority, item.analysis_name.lower(), item.counter_path.lower(), item.threshold_name.lower()))
    return alerts


def _evaluate_special_threshold(
    analysis: Analysis,
    threshold: Threshold,
    variables: dict[str, list[CounterSeries]],
    dataset: PerfmonDataset,
    answers: dict[str, str | bool],
) -> list[AlertEvent] | None:
    if analysis.name == "System Context Switching":
        return _evaluate_context_switching_threshold(analysis, threshold, variables)

    spec = _special_threshold_spec((analysis.name, threshold.name), variables, answers)
    if spec is None:
        return None
    return _evaluate_static_threshold(analysis, threshold, spec, variables)


def _special_threshold_spec(
    key: tuple[str, str],
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
) -> ThresholdSpec | None:
    physical_memory_gb = _coerce_float(answers.get("PhysicalMemory"), default=0.0)
    user_va = _coerce_float(answers.get("UserVa"), default=2048.0)
    os_name = str(answers.get("OS", "Windows Server")).upper()

    if key == ("Memory Available MBytes", "Less than 10 percent of RAM is available"):
        return ThresholdSpec("CollectionOfAvailableMBytes", "lt", int(round(physical_memory_gb, 0)) * 1024 * 0.10)

    if key == ("Memory Available MBytes", "Less than 5 percent of RAM is available or less than 64 MB of RAM is available"):
        return ThresholdSpec("CollectionOfAvailableMBytes", "lt", max(int(round(physical_memory_gb, 0)) * 1024 * 0.05, 64))

    if key == ("System Processor Queue Length", "More than 2 ready threads are queued for each processor"):
        logical_processors = max(len(variables.get("CollectionOfProcessorPercentProcessorTime", [])) - 1, 1)
        return ThresholdSpec("SystemProcessorQueueLength", "gt", logical_processors * 2)

    if key == ("System Processor Queue Length", "More than 10 ready threads are queued for each processor"):
        logical_processors = max(len(variables.get("CollectionOfProcessorPercentProcessorTime", [])) - 1, 1)
        return ThresholdSpec("SystemProcessorQueueLength", "gt", logical_processors * 10)

    if key == ("Memory Pool Non-Paged Bytes", "More than 60% of Pool Non-Paged Kernel Memory Used"):
        return ThresholdSpec("MemoryPoolNonpagedBytes", "gt", _nonpaged_pool_maximum(os_name, physical_memory_gb, user_va) * 0.60)

    if key == ("Memory Pool Non-Paged Bytes", "More than 80% of Pool Non-Paged Kernel Memory Used"):
        return ThresholdSpec("MemoryPoolNonpagedBytes", "gt", _nonpaged_pool_maximum(os_name, physical_memory_gb, user_va) * 0.80)

    if key == ("Memory Pool Non-Paged Bytes", "More than 10% of physical memory usage by Pool Paged"):
        physical_memory_bytes = max(int(round(physical_memory_gb, 0)), 1) * BYTES_IN_GB
        return ThresholdSpec("MemoryPoolNonpagedBytes", "gt", physical_memory_bytes * 0.10)

    if key == ("Memory Pool Paged Bytes", "More than 60% of Pool Paged Kernel Memory Used"):
        return ThresholdSpec("MemoryPoolPagedBytes", "gt", _paged_pool_maximum(os_name, physical_memory_gb, user_va) * 0.60)

    if key == ("Memory Pool Paged Bytes", "More than 80% of Pool Paged Kernel Memory Used"):
        return ThresholdSpec("MemoryPoolPagedBytes", "gt", _paged_pool_maximum(os_name, physical_memory_gb, user_va) * 0.80)

    if key == ("Memory System Cache Resident Bytes", "System Cache Resident Bytes is consumsing more than 10 percent of RAM"):
        return ThresholdSpec("CollectionOfMemorySystemCacheResidentBytes", "gt", int(physical_memory_gb) * BYTES_IN_GB * 0.10)

    return None


def _evaluate_static_threshold(
    analysis: Analysis,
    threshold: Threshold,
    spec: ThresholdSpec,
    variables: dict[str, list[CounterSeries]],
) -> list[AlertEvent]:
    collection = variables.get(spec.collection_name, [])
    if not collection:
        return []

    alerts: list[AlertEvent] = []
    for series in collection:
        overall_metrics: list[str] = []
        slice_indexes: set[int] = set()

        if spec.is_trend_only:
            if _compare(series.trend, spec.operator, spec.threshold_value):
                overall_metrics.append("trend")
            for index, value in enumerate(series.quantized_trend):
                if _compare(value, spec.operator, spec.threshold_value):
                    slice_indexes.add(index)
        else:
            metric_pairs = (
                ("min", series.minimum, series.quantized_min),
                ("avg", series.average, series.quantized_avg),
                ("max", series.maximum, series.quantized_max),
            )
            for metric_name, overall_value, slice_values in metric_pairs:
                if _compare(overall_value, spec.operator, spec.threshold_value):
                    overall_metrics.append(metric_name)
                for index, value in enumerate(slice_values):
                    if _compare(value, spec.operator, spec.threshold_value):
                        slice_indexes.add(index)

        if not overall_metrics and not slice_indexes:
            continue

        alerts.append(
            AlertEvent(
                analysis_name=analysis.name,
                category=analysis.category,
                threshold_name=threshold.name,
                condition=threshold.condition,
                color=threshold.color,
                priority=_coerce_int(threshold.priority, 0),
                counter_path=series.counter_path,
                counter_instance=series.counter_instance,
                threshold_value=spec.threshold_value,
                broken_metrics=sorted(set(overall_metrics or (["trend"] if spec.is_trend_only else ["slice"]))),
                time_slices=sorted(slice_indexes),
                overall_triggered=bool(overall_metrics),
            )
        )

    return alerts


def _evaluate_context_switching_threshold(
    analysis: Analysis,
    threshold: Threshold,
    variables: dict[str, list[CounterSeries]],
) -> list[AlertEvent]:
    context_collection = variables.get("SystemContextSwitchessec", [])
    processor_collection = variables.get("CollectionOfProcessorPercentProcessorTime", [])
    privileged_collection = variables.get("CollectionOfProcessorPercentPrivilegedTimeAll", [])
    if not context_collection or not processor_collection or not privileged_collection:
        return []

    logical_processors = max(len(processor_collection) - 1, 1)
    processor_total = _find_total_series(processor_collection)
    privileged_total = _find_total_series(privileged_collection)

    if "2,500" in threshold.name:
        context_threshold = logical_processors * 2500
        ratio_threshold = 20
        processor_threshold = 50
        absolute_threshold = 10000
    else:
        context_threshold = logical_processors * 5000
        ratio_threshold = 30
        processor_threshold = 70
        absolute_threshold = 20000

    alerts: list[AlertEvent] = []
    for series in context_collection:
        metrics: set[str] = set()
        time_slices: set[int] = set()

        for metric_name, context_values, cpu_values, privileged_values in (
            ("min", series.quantized_min, processor_total.quantized_min, privileged_total.quantized_min),
            ("avg", series.quantized_avg, processor_total.quantized_avg, privileged_total.quantized_avg),
            ("max", series.quantized_max, processor_total.quantized_max, privileged_total.quantized_max),
        ):
            for index in range(min(len(context_values), len(cpu_values), len(privileged_values))):
                context_value = context_values[index]
                cpu_value = cpu_values[index]
                privileged_value = privileged_values[index]
                if context_value is None or cpu_value in (None, 0) or privileged_value is None:
                    continue

                privileged_ratio = (privileged_value * 100) / cpu_value
                is_triggered = (
                    (privileged_ratio > ratio_threshold and context_value > context_threshold and cpu_value > processor_threshold)
                    or context_value > absolute_threshold
                )
                if is_triggered:
                    metrics.add(metric_name)
                    time_slices.add(index)

        if time_slices:
            alerts.append(
                AlertEvent(
                    analysis_name=analysis.name,
                    category=analysis.category,
                    threshold_name=threshold.name,
                    condition=threshold.condition,
                    color=threshold.color,
                    priority=_coerce_int(threshold.priority, 0),
                    counter_path=series.counter_path,
                    counter_instance=series.counter_instance,
                    threshold_value=float(context_threshold),
                    broken_metrics=sorted(metrics),
                    time_slices=sorted(time_slices),
                    overall_triggered=False,
                )
            )

    return alerts


def _generate_network_utilization(
    source_collection_name: str,
    target_counter_name: str,
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    datasource: DataSource,
) -> list[CounterSeries]:
    source_collection = variables.get(source_collection_name, [])
    bandwidth_collection = variables.get("CollectionOfNetworkInterfaceCurrentBandwidth", [])
    generated: list[CounterSeries] = []
    for source_series in source_collection:
        bandwidth_series = _match_series_by_instance(source_series.counter_instance, bandwidth_collection)
        if bandwidth_series is None:
            continue
        values: list[float | None] = []
        for source_value, bandwidth_value in zip(source_series.quantized_avg, bandwidth_series.quantized_avg):
            if source_value is None or bandwidth_value in (None, 0) or source_value <= 0 or bandwidth_value <= 0:
                values.append(0)
            else:
                values.append(int(((source_value * 8) / bandwidth_value) * 100))
        generated.append(
            _build_generated_series_from_quantized(
                prototype=source_series,
                counter_name=target_counter_name,
                values=values,
                dataset=dataset,
                data_type=datasource.data_type,
            )
        )
    return generated


def _generate_logical_disk_overwhelmed(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    datasource: DataSource,
) -> list[CounterSeries]:
    queue_collection = variables.get("CollectionOfLogicalDiskAvgDiskQueueLengthAll", [])
    sec_collection = variables.get("CollectionOfLogicalDiskAvgDisksecTransferAll", [])
    bytes_collection = variables.get("CollectionOfLogicalDiskAvgDiskBytesTransferAll", [])
    generated: list[CounterSeries] = []

    for queue_series in queue_collection:
        sec_series = _match_series_by_instance(queue_series.counter_instance, sec_collection)
        bytes_series = _match_series_by_instance(queue_series.counter_instance, bytes_collection)
        if sec_series is None or bytes_series is None:
            continue

        values: list[float | None] = []
        for queue_value, sec_value, bytes_value in zip(queue_series.values, sec_series.values, bytes_series.values):
            if queue_value is None or sec_value is None or bytes_value is None:
                values.append(0)
                continue
            critical_threshold = 0.035 if bytes_value > 65536 else 0.025
            if queue_value >= 1 and sec_value > critical_threshold:
                values.append(2)
            elif queue_value >= 1 and sec_value > 0.015:
                values.append(1)
            else:
                values.append(0)

        generated.append(
            _build_generated_series_from_raw(
                prototype=queue_series,
                counter_name="Disk Overwhelmed",
                values=values,
                dataset=dataset,
                data_type=datasource.data_type,
            )
        )

    return generated


def _generate_read_write_ratio(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    datasource: DataSource,
) -> list[CounterSeries]:
    read_collection = variables.get("CollectionOfLogicalDiskDiskReadsPerSec", [])
    write_collection = variables.get("CollectionOfLogicalDiskDiskWritesPerSec", [])
    generated: list[CounterSeries] = []
    for read_series in read_collection:
        write_series = _match_series_by_instance(read_series.counter_instance, write_collection)
        if write_series is None:
            continue

        values: list[float | None] = []
        for read_value, write_value in zip(read_series.quantized_avg, write_series.quantized_avg):
            if read_value is None or write_value is None or read_value <= 0 or write_value <= 0:
                values.append(0)
            else:
                values.append(int((read_value / (read_value + write_value)) * 100))

        generated.append(
            _build_generated_series_from_quantized(
                prototype=read_series,
                counter_name="Read Write Ratio",
                values=values,
                dataset=dataset,
                data_type=datasource.data_type,
            )
        )

    return generated


def _generate_physical_memory_overwhelmed(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
    datasource: DataSource,
) -> list[CounterSeries]:
    available_collection = variables.get("CollectionOfMemoryAvailableMBytes", [])
    paging_collection = variables.get("CollectionOfPagingFilePercentUsage", [])
    queue_collection = variables.get("CollectionOfLogicalDiskAvgDiskQueueLengthAll", [])
    bytes_collection = variables.get("CollectionOfLogicalDiskAvgDiskBytesTransferAll", [])
    sec_collection = variables.get("CollectionOfLogicalDiskAvgDisksecTransferAll", [])
    physical_memory_gb = max(_coerce_float(answers.get("PhysicalMemory"), default=0.0), 1.0)
    ten_percent = int(physical_memory_gb) * BYTES_IN_KB * 0.10
    five_percent = int(physical_memory_gb) * BYTES_IN_KB * 0.05

    paging_disks = [_normalize_pagefile_instance(series.counter_instance) for series in paging_collection]
    generated: list[CounterSeries] = []

    for available_series in available_collection:
        values: list[float | None] = []
        for index, available_value in enumerate(available_series.values):
            if available_value is None or available_value >= ten_percent:
                values.append(0)
                continue

            if not paging_disks:
                values.append(2 if available_value < five_percent else 1)
                continue

            disk_states: list[int] = []
            for disk_letter in paging_disks:
                queue_series = _match_series_by_instance(disk_letter, queue_collection)
                bytes_series = _match_series_by_instance(disk_letter, bytes_collection)
                sec_series = _match_series_by_instance(disk_letter, sec_collection)
                if queue_series is None or bytes_series is None or sec_series is None:
                    disk_states.append(0)
                    continue

                queue_value = _value_at(queue_series.values, index)
                bytes_value = _value_at(bytes_series.values, index)
                sec_value = _value_at(sec_series.values, index)
                if queue_value is None or bytes_value is None or sec_value is None:
                    disk_states.append(0)
                    continue

                if queue_value >= 1 and sec_value > 0.015:
                    critical_threshold = 0.035 if bytes_value > 65536 else 0.025
                    disk_states.append(2 if sec_value > critical_threshold else 1)
                else:
                    disk_states.append(0)

            result = 2
            for state in disk_states:
                if state == 1:
                    result = 1
                if state == 0:
                    result = 0
            values.append(result)

        generated.append(
            _build_generated_series_from_raw(
                prototype=available_series,
                counter_name="Physical Memory Overwhelmed",
                values=values,
                dataset=dataset,
                data_type=datasource.data_type,
            )
        )

    return generated


def _generated_collection_network_total(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
    datasource: DataSource,
) -> list[CounterSeries]:
    del answers
    return _generate_network_utilization(
        source_collection_name="CollectionOfNetworkInterfaceBytesTotalPerSec",
        target_counter_name="% Network Utilization",
        dataset=dataset,
        variables=variables,
        datasource=datasource,
    )


def _generated_collection_network_sent(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
    datasource: DataSource,
) -> list[CounterSeries]:
    del answers
    return _generate_network_utilization(
        source_collection_name="CollectionOfNetworkInterfaceBytesSentPerSec",
        target_counter_name="% Network Utilization Sent",
        dataset=dataset,
        variables=variables,
        datasource=datasource,
    )


def _generated_collection_network_received(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
    datasource: DataSource,
) -> list[CounterSeries]:
    del answers
    return _generate_network_utilization(
        source_collection_name="CollectionOfNetworkInterfaceBytesReceivedPerSec",
        target_counter_name="% Network Utilization Received",
        dataset=dataset,
        variables=variables,
        datasource=datasource,
    )


def _generated_collection_disk_overwhelmed(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
    datasource: DataSource,
) -> list[CounterSeries]:
    del answers
    return _generate_logical_disk_overwhelmed(dataset=dataset, variables=variables, datasource=datasource)


def _generated_collection_read_write_ratio(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
    datasource: DataSource,
) -> list[CounterSeries]:
    del answers
    return _generate_read_write_ratio(dataset=dataset, variables=variables, datasource=datasource)


def _generated_collection_memory_overwhelmed(
    dataset: PerfmonDataset,
    variables: dict[str, list[CounterSeries]],
    answers: dict[str, str | bool],
    datasource: DataSource,
) -> list[CounterSeries]:
    return _generate_physical_memory_overwhelmed(
        dataset=dataset,
        variables=variables,
        answers=answers,
        datasource=datasource,
    )


_GENERATED_COLLECTION_BUILDERS = {
    "CollectionOfNetworkUtilization": _generated_collection_network_total,
    "CollectionOfSentNetworkUtilization": _generated_collection_network_sent,
    "CollectionOfReceivedNetworkUtilization": _generated_collection_network_received,
    "CollectionOfLogicalDiskDiskOverwhelmedAll": _generated_collection_disk_overwhelmed,
    "CollectionOfPalGeneratedReadWriteRatio": _generated_collection_read_write_ratio,
    "CollectionOfMemoryPhysicalMemoryOverwhelmed": _generated_collection_memory_overwhelmed,
}


def _render_report(
    source_log_path: Path,
    converted_csv_path: Path,
    threshold_file_name: str,
    answers: dict[str, str | bool],
    dataset: PerfmonDataset,
    results: list[AnalysisResult],
) -> str:
    alert_count = sum(len(result.alerts) for result in results)
    critical_count = sum(1 for result in results for alert in result.alerts if alert.condition.lower() == "critical")
    warning_count = sum(1 for result in results for alert in result.alerts if alert.condition.lower() == "warning")
    missing_count = sum(1 for result in results if result.status == "missing")
    triggered_results = [result for result in results if result.alerts]
    healthy_results = [result for result in results if result.status == "ok"]

    findings_rows = []
    for result in triggered_results:
        for alert in result.alerts:
            findings_rows.append(
                f"""
                <tr>
                  <td><span class="severity severity-{escape(alert.condition.lower())}">{escape(alert.condition)}</span></td>
                  <td>{escape(result.analysis_name)}</td>
                  <td>{escape(alert.counter_instance or "(global)")}</td>
                  <td>{escape(alert.threshold_name)}</td>
                  <td>{escape(alert.to_summary(dataset.analysis_interval_seconds, dataset.quantized_times))}</td>
                </tr>
                """
            )

    analysis_sections = []
    chart_counter = 0
    for result in results:
        alerts_markup = "".join(
            f"""
            <li>
              <strong>{escape(alert.condition)}:</strong> {escape(alert.threshold_name)}
              <span class="muted">[{escape(alert.counter_instance or alert.counter_path)}]</span>
              <div class="muted">{escape(alert.to_summary(dataset.analysis_interval_seconds, dataset.quantized_times))}</div>
            </li>
            """
            for alert in result.alerts[:8]
        )
        if len(result.alerts) > 8:
            alerts_markup += f"<li class=\"muted\">+ {len(result.alerts) - 8} additional alerts</li>"

        missing_markup = "".join(f"<span class=\"chip chip-missing\">{escape(item)}</span>" for item in result.missing_datasources)
        series_cards: list[str] = []
        for series in result.series[:6]:
            chart_counter += 1
            series_cards.append(_render_series_card(series, chart_id=f"pal-chart-{chart_counter}"))
        series_markup = "".join(series_cards)
        if not series_markup:
            series_markup = '<p class="muted">No primary series available.</p>'

        analysis_sections.append(
            f"""
            <section class="analysis-card status-{escape(result.status)}">
              <div class="analysis-head">
                <div>
                  <p class="section-kicker">{escape(result.category or "General")}</p>
                  <h2>{escape(result.analysis_name)}</h2>
                </div>
                <div class="chip-list">
                  <span class="chip chip-status">{escape(_status_label(result.status))}</span>
                  <span class="chip chip-accent">{len(result.alerts)} alerts</span>
                </div>
              </div>
              {result.description_html or '<p class="muted">No description available.</p>'}
              {'<div class="chip-list">' + missing_markup + '</div>' if missing_markup else ''}
              <div class="series-grid">{series_markup}</div>
              {'<ul class="alert-list">' + alerts_markup + '</ul>' if alerts_markup else '<p class="muted">No alerts triggered.</p>'}
            </section>
            """
        )

    findings_table = (
        """
        <table class="findings-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Analysis</th>
              <th>Instance</th>
              <th>Threshold</th>
              <th>Trigger</th>
            </tr>
          </thead>
          <tbody>
        """
        + "".join(findings_rows)
        + """
          </tbody>
        </table>
        """
        if findings_rows
        else '<p class="muted">No alerts were triggered for this run.</p>'
    )

    question_chips = "".join(
        f"<span class=\"chip chip-soft\">{escape(key)}: {escape(str(value))}</span>"
        for key, value in sorted(answers.items(), key=lambda item: item[0].lower())
    )

    chart_js_bundle = _load_chart_js_bundle()
    chart_bootstrap = _render_chart_bootstrap_script()

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>PAL Python Report</title>
    <style>
      :root {{
        --bg: #f3efe7; --card: #fffaf2; --line: #d8cebf; --text: #1f2c3a; --muted: #667383;
        --accent: #0f6e7c; --accent-soft: #ebf4f5; --warning: #c07a1a; --critical: #b0302f;
        --ok: #2f6b41; --missing: #8a4b3e;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0; font-family: "Segoe UI Variable", "Segoe UI", sans-serif; color: var(--text);
        background: radial-gradient(circle at top left, rgba(15,110,124,0.12), transparent 32%), linear-gradient(180deg, #fbf7f1 0%, var(--bg) 100%);
      }}
      main {{ max-width: 1680px; margin: 0 auto; padding: 2rem; }}
      h1, h2, h3 {{ margin-top: 0; }}
      .hero, .panel, .analysis-card {{ background: var(--card); border: 1px solid var(--line); border-radius: 26px; }}
      .hero {{ padding: 1.8rem; box-shadow: 0 20px 60px rgba(31,44,58,0.06); }}
      .section-kicker {{ margin: 0 0 0.5rem; text-transform: uppercase; letter-spacing: 0.12em; font-size: 0.78rem; font-weight: 700; color: var(--accent); }}
      .summary-grid, .series-grid {{ display: grid; gap: 1rem; }}
      .summary-grid {{ grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-top: 1rem; }}
      .series-grid {{ grid-template-columns: repeat(auto-fit, minmax(760px, 1fr)); margin-top: 1rem; }}
      .panel {{ padding: 1.35rem; margin-top: 1.25rem; }}
      .analysis-card {{ padding: 1.65rem; margin-top: 1.25rem; }}
      .analysis-head {{ display: flex; justify-content: space-between; gap: 1rem; align-items: start; }}
      .metric-card, .series-card {{ padding: 1.5rem; border-radius: 24px; border: 1px solid #d9e5eb; background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(240,248,252,0.94)); box-shadow: 0 18px 48px rgba(26,52,66,0.10); }}
      .metric-value {{ font-size: 1.8rem; font-weight: 700; }}
      .muted {{ color: var(--muted); }}
      .chip-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
      .chip {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 0.4rem 0.7rem; border: 1px solid var(--line); background: #fff; font-size: 0.9rem; }}
      .chip-accent, .chip-status {{ background: var(--accent-soft); border-color: #c8dde0; }}
      .chip-soft {{ background: #f6f2eb; }}
      .chip-missing {{ background: #f7e5de; border-color: #e3b9a9; }}
      .findings-table {{ width: 100%; border-collapse: collapse; }}
      .findings-table th, .findings-table td {{ padding: 0.8rem; border-bottom: 1px solid var(--line); vertical-align: top; text-align: left; }}
      .severity {{ display: inline-block; padding: 0.3rem 0.55rem; border-radius: 999px; font-weight: 700; }}
      .severity-warning {{ color: #6b450d; background: #fbecd7; }}
      .severity-critical {{ color: white; background: var(--critical); }}
      .status-ok {{ border-left: 6px solid var(--ok); }}
      .status-warning {{ border-left: 6px solid var(--warning); }}
      .status-critical {{ border-left: 6px solid var(--critical); }}
      .status-missing {{ border-left: 6px solid var(--missing); }}
      .series-head {{ display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; }}
      .series-card h3 {{ margin-bottom: 0.35rem; font-size: 1.65rem; letter-spacing: 0.01em; }}
      .series-path {{ margin: 0; min-height: 2.8rem; line-height: 1.45; word-break: break-word; max-width: 70ch; }}
      .series-badge {{ display: inline-flex; align-items: center; padding: 0.5rem 0.9rem; border-radius: 999px; background: rgba(15,110,124,0.08); color: #0f6e7c; border: 1px solid rgba(15,110,124,0.12); font-weight: 700; white-space: nowrap; }}
      .chart-shell {{ margin-top: 1.15rem; padding: 0.95rem 0.95rem 0.75rem; border-radius: 24px; background:
        linear-gradient(180deg, rgba(255,255,255,0.99), rgba(244,249,252,0.96)); border: 1px solid #dce9f0; }}
      .chart-caption {{ margin: 0.8rem 0 0; font-size: 0.96rem; color: var(--muted); }}
      .sparkline {{ width: 100%; height: 386px; display: block; }}
      .chart-band {{ fill: rgba(107, 185, 232, 0.06); }}
      .chart-grid-line {{ stroke: #dbe7ec; stroke-width: 1; }}
      .chart-axis {{ stroke: #8aa0ad; stroke-width: 1.3; }}
      .chart-axis-label {{ fill: #526574; font-size: 13px; font-weight: 700; letter-spacing: 0.01em; }}
      .chart-value-label {{ fill: #4d5f6e; font-size: 12px; font-weight: 600; }}
      .chart-line {{ fill: none; stroke: #1d88e5; stroke-width: 4.8; stroke-linecap: round; stroke-linejoin: round; }}
      .chart-fill {{ fill-opacity: 1; }}
      .chart-point {{ fill: #ffffff; stroke: #1d88e5; stroke-width: 2.5; }}
      .chart-point-strong {{ fill: #1d88e5; stroke: #ffffff; stroke-width: 3; }}
      .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.85rem 1rem; margin-top: 1.15rem; font-size: 1rem; }}
      .stats span {{ display: flex; justify-content: space-between; gap: 0.75rem; }}
      .alert-list {{ margin: 1rem 0 0; padding-left: 1.2rem; }}
      @media (max-width: 980px) {{ .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} .series-head {{ flex-direction: column; }} }}
      @media (max-width: 820px) {{ main {{ padding: 1rem; }} .analysis-head {{ flex-direction: column; }} .series-grid {{ grid-template-columns: 1fr; }} .sparkline {{ height: 290px; }} .chart-shell {{ padding: 0.75rem 0.6rem 0.5rem; }} }}
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <p class="section-kicker">PAL Python Engine</p>
        <h1>PAL Analysis Report</h1>
        <p class="muted">Native Python engine with BLG conversion preserved through relog.exe.</p>
        <div class="summary-grid">
          <article class="metric-card"><div class="metric-value">{alert_count}</div><div>Alerts</div></article>
          <article class="metric-card"><div class="metric-value">{critical_count}</div><div>Critical</div></article>
          <article class="metric-card"><div class="metric-value">{warning_count}</div><div>Warnings</div></article>
          <article class="metric-card"><div class="metric-value">{len(triggered_results)}</div><div>Triggered Analyses</div></article>
          <article class="metric-card"><div class="metric-value">{len(healthy_results)}</div><div>Healthy Analyses</div></article>
          <article class="metric-card"><div class="metric-value">{missing_count}</div><div>Incomplete Analyses</div></article>
        </div>
      </section>
      <section class="panel">
        <p class="section-kicker">Context</p>
        <div class="chip-list">
          <span class="chip chip-accent">source: {escape(source_log_path.name)}</span>
          <span class="chip chip-accent">csv: {escape(converted_csv_path.name)}</span>
          <span class="chip chip-accent">threshold: {escape(threshold_file_name)}</span>
          <span class="chip chip-soft">series: {len(dataset.series)}</span>
          <span class="chip chip-soft">interval: {dataset.analysis_interval_seconds}s</span>
          <span class="chip chip-soft">start: {escape(dataset.timestamps[0].isoformat(sep=' ')) if dataset.timestamps else 'n/a'}</span>
          <span class="chip chip-soft">end: {escape(dataset.timestamps[-1].isoformat(sep=' ')) if dataset.timestamps else 'n/a'}</span>
        </div>
        <div class="chip-list" style="margin-top: 1rem;">{question_chips}</div>
      </section>
      <section class="panel">
        <p class="section-kicker">Findings</p>
        <h2>Triggered Alerts</h2>
        {findings_table}
      </section>
      {"".join(analysis_sections)}
    </main>
    <script>{chart_js_bundle}</script>
    <script>{chart_bootstrap}</script>
  </body>
</html>"""


def _render_series_card(series: CounterSeries, chart_id: str) -> str:
    payload = json.dumps(_build_chart_payload(series), ensure_ascii=False).replace("</", "<\\/")
    return f"""
    <article class="series-card">
      <div class="series-head">
        <div>
          <h3>{escape(series.counter_instance or series.counter_name)}</h3>
          <p class="muted series-path">{escape(series.counter_path)}</p>
        </div>
        <span class="series-badge">{len([value for value in series.quantized_avg if value is not None])} points</span>
      </div>
      <div class="chart-shell">
        <canvas class="sparkline" id="{chart_id}" data-pal-chart="true" width="864" height="386"></canvas>
        <script type="application/json" id="{chart_id}-payload">{payload}</script>
        <p class="chart-caption">{escape(_describe_time_window(series))}</p>
      </div>
      <div class="stats">
        <span><strong>Min</strong><em>{_format_number(series.minimum)}</em></span>
        <span><strong>Avg</strong><em>{_format_number(series.average)}</em></span>
        <span><strong>Max</strong><em>{_format_number(series.maximum)}</em></span>
        <span><strong>Trend</strong><em>{_format_number(series.trend)}</em></span>
      </div>
    </article>
    """


def _build_chart_payload(series: CounterSeries) -> dict:
    interval_seconds = _estimate_series_interval_seconds(series.quantized_times)
    include_date = len({item.date() for item in series.quantized_times}) > 1 if series.quantized_times else False
    labels = [_format_time_label(item, interval_seconds=interval_seconds, include_date=include_date) for item in series.quantized_times]
    values = [round(value, 6) if value is not None else None for value in series.quantized_avg]
    valid_values = [(index, value) for index, value in enumerate(values) if value is not None]
    max_index = max(valid_values, key=lambda item: item[1])[0] if valid_values else -1
    return {
        "labels": labels,
        "values": values,
        "datasetLabel": series.counter_instance or series.counter_name,
        "metricLabel": series.counter_name,
        "maxIndex": max_index,
        "maxValueLabel": _format_chart_axis_value(values[max_index]) if max_index >= 0 else "",
    }


@lru_cache(maxsize=1)
def _load_chart_js_bundle() -> str:
    bundle_path = Path(__file__).resolve().parents[3] / "frontend" / "vendor" / "chart.umd.min.js"
    return bundle_path.read_text(encoding="utf-8").replace("</script", "<\\/script")


def _render_chart_bootstrap_script() -> str:
    return """
(() => {
  const formatNumber = (value) => {
    if (value === null || value === undefined || Number.isNaN(value)) {
      return 'n/a';
    }
    const absolute = Math.abs(value);
    if (absolute >= 1000) {
      return new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 }).format(value);
    }
    if (absolute >= 100) {
      return new Intl.NumberFormat('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(value);
    }
    if (absolute >= 1) {
      return new Intl.NumberFormat('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(value);
    }
    return new Intl.NumberFormat('en-US', { minimumFractionDigits: 4, maximumFractionDigits: 4 }).format(value);
  };

  const drawRoundedRect = (ctx, x, y, width, height, radius) => {
    const r = Math.min(radius, width / 2, height / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + width, y, x + width, y + height, r);
    ctx.arcTo(x + width, y + height, x, y + height, r);
    ctx.arcTo(x, y + height, x, y, r);
    ctx.arcTo(x, y, x + width, y, r);
    ctx.closePath();
  };

  const palPointBadgePlugin = {
    id: 'palPointBadgePlugin',
    afterDatasetsDraw(chart) {
      const payload = chart.options?.plugins?.palPointBadgePlugin?.payload || chart.$palPayload;
      if (!payload || payload.maxIndex < 0) {
        return;
      }

      const point = chart.getDatasetMeta(0).data[payload.maxIndex];
      if (!point) {
        return;
      }

      const ctx = chart.ctx;
      const label = payload.maxValueLabel;
      ctx.save();
      ctx.font = '700 13px "Segoe UI Variable", "Segoe UI", sans-serif';
      const paddingX = 10;
      const paddingY = 7;
      const textWidth = ctx.measureText(label).width;
      const boxWidth = textWidth + (paddingX * 2);
      const boxHeight = 30;
      let x = point.x - (boxWidth / 2);
      x = Math.max(chart.chartArea.left, Math.min(x, chart.chartArea.right - boxWidth));
      const y = Math.max(chart.chartArea.top + 10, point.y - 48);

      drawRoundedRect(ctx, x, y, boxWidth, boxHeight, 12);
      ctx.fillStyle = 'rgba(255,255,255,0.96)';
      ctx.strokeStyle = 'rgba(29,136,229,0.28)';
      ctx.lineWidth = 2;
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = '#24506d';
      ctx.fillText(label, x + paddingX, y + paddingY + 9);
      ctx.restore();
    },
  };

  Chart.register(palPointBadgePlugin);

  const renderChart = (canvas) => {
    if (!canvas || canvas.dataset.palRendered === 'true') {
      return;
    }

    const payloadNode = document.getElementById(`${canvas.id}-payload`);
    if (!payloadNode) {
      return;
    }

    const payload = JSON.parse(payloadNode.textContent);
    const host = canvas.parentElement || canvas;
    const width = Math.max(420, Math.floor(host.clientWidth - 6));
    const height = Math.max(290, Math.floor(canvas.clientHeight || 386));
    canvas.width = width;
    canvas.height = height;

    const context = canvas.getContext('2d');
    const maxIndex = payload.maxIndex;
    const pointRadius = payload.values.map((value, index) => {
      if (value === null || value === undefined) {
        return 0;
      }
      return index === maxIndex ? 3.2 : 2.2;
    });
    const pointHoverRadius = pointRadius.map((value) => value + 2.4);
    const pointBackgroundColor = payload.values.map((value, index) => {
      if (value === null || value === undefined) {
        return 'rgba(0,0,0,0)';
      }
      return index === maxIndex ? '#2d7fd1' : '#2d7fd1';
    });

    const chart = new Chart(context, {
      type: 'line',
      data: {
        labels: payload.labels,
        datasets: [
          {
            label: payload.datasetLabel,
            data: payload.values,
            borderColor: '#2d7fd1',
            backgroundColor: 'rgba(45,127,209,0.06)',
            fill: false,
            tension: 0.12,
            borderWidth: 2,
            spanGaps: true,
            pointStyle: 'circle',
            pointRadius,
            pointHoverRadius,
            pointBackgroundColor,
            pointBorderColor: '#2d7fd1',
            pointBorderWidth: 1,
            pointHoverBorderWidth: 1.5,
            pointHitRadius: 10,
            clip: 16,
          },
        ],
      },
      options: {
        responsive: false,
        maintainAspectRatio: false,
        animation: false,
        events: ['mousemove', 'mouseout', 'touchstart', 'touchmove'],
        interaction: {
          mode: 'nearest',
          intersect: true,
        },
        layout: {
          padding: {
            top: 26,
            right: 22,
            bottom: 14,
            left: 12,
          },
        },
        plugins: {
          palPointBadgePlugin: {
            payload,
          },
          legend: {
            display: true,
            position: 'bottom',
            align: 'center',
            labels: {
              color: '#385468',
              usePointStyle: true,
              pointStyle: 'circle',
              boxWidth: 8,
              boxHeight: 8,
              padding: 14,
              font: {
                size: 12,
                weight: '600',
              },
            },
          },
          tooltip: {
            enabled: true,
            displayColors: false,
            backgroundColor: 'rgba(17, 26, 38, 0.94)',
            titleColor: '#ffffff',
            bodyColor: '#e8f0f7',
            borderColor: 'rgba(45,127,209,0.18)',
            borderWidth: 1,
            padding: 10,
            callbacks: {
              title(items) {
                return items?.[0]?.label || '';
              },
              label(context) {
                return `Current value: ${formatNumber(context.parsed.y)}`;
              },
            },
          },
        },
        scales: {
          x: {
            grid: {
              color: 'rgba(120, 152, 176, 0.10)',
              drawBorder: false,
            },
            ticks: {
              color: '#526574',
              maxTicksLimit: 10,
              autoSkip: true,
              maxRotation: 0,
              font: {
                size: 12,
                weight: '500',
              },
            },
            title: {
              display: true,
              text: 'Time',
              color: '#4d6272',
              font: {
                size: 12,
                weight: '600',
              },
              padding: {
                top: 10,
              },
            },
          },
          y: {
            grace: '10%',
            grid: {
              color: 'rgba(120, 152, 176, 0.10)',
              drawBorder: false,
            },
            ticks: {
              color: '#526574',
              padding: 10,
              font: {
                size: 12,
                weight: '500',
              },
              callback(value) {
                return formatNumber(value);
              },
            },
            title: {
              display: true,
              text: payload.metricLabel,
              color: '#4d6272',
              font: {
                size: 12,
                weight: '600',
              },
              padding: {
                bottom: 8,
              },
            },
          },
        },
      },
    });

    chart.$palPayload = payload;
    canvas.dataset.palRendered = 'true';
  };

  const charts = Array.from(document.querySelectorAll('canvas[data-pal-chart="true"]'));
  if (!charts.length) {
    return;
  }

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) {
          return;
        }
        renderChart(entry.target);
        observer.unobserve(entry.target);
      });
    }, {
      rootMargin: '240px 0px',
      threshold: 0.01,
    });

    charts.forEach((canvas, index) => {
      if (index < 4) {
        renderChart(canvas);
        return;
      }
      observer.observe(canvas);
    });
    return;
  }

  charts.forEach(renderChart);
})();
    """.replace("</script", "<\\/script")


def _ensure_perfmon_csv(log_path: Path, work_dir: Path) -> Path:
    if log_path.suffix.lower() == ".csv":
        return log_path

    output_path = work_dir / f"{log_path.stem}_{uuid4().hex}.csv"
    subprocess.run(
        ["relog.exe", str(log_path), "-f", "CSV", "-o", str(output_path)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    return output_path


def _build_series(
    parsed_path: ParsedCounterPath,
    timestamps: list[datetime],
    values: list[float | None],
    data_type: str,
    quantized_indexes: list[list[int]],
    quantized_times: list[datetime],
    analysis_interval_seconds: int,
) -> CounterSeries:
    quantized_avg = [_aggregate_bucket(values, bucket, "avg", data_type) for bucket in quantized_indexes]
    quantized_min = [_aggregate_bucket(values, bucket, "min", data_type) for bucket in quantized_indexes]
    quantized_max = [_aggregate_bucket(values, bucket, "max", data_type) for bucket in quantized_indexes]
    quantized_trend = _generate_quantized_trend(quantized_avg, analysis_interval_seconds, data_type)

    numeric_values = [value for value in values if value is not None]
    minimum = _convert_to_data_type(min(numeric_values), data_type) if numeric_values else None
    average = _convert_to_data_type(sum(numeric_values) / len(numeric_values), data_type) if numeric_values else None
    maximum = _convert_to_data_type(max(numeric_values), data_type) if numeric_values else None
    trend = quantized_trend[-1] if quantized_trend else None

    return CounterSeries(
        counter_path=parsed_path.canonical_path,
        counter_computer=parsed_path.computer,
        counter_object=parsed_path.object_name,
        counter_instance=parsed_path.instance,
        counter_name=parsed_path.counter_name,
        data_type=data_type,
        timestamps=list(timestamps),
        values=list(values),
        quantized_times=list(quantized_times),
        quantized_min=quantized_min,
        quantized_avg=quantized_avg,
        quantized_max=quantized_max,
        quantized_trend=quantized_trend,
        minimum=minimum,
        average=average,
        maximum=maximum,
        trend=trend,
    )


def _build_generated_series_from_raw(
    prototype: CounterSeries,
    counter_name: str,
    values: list[float | None],
    dataset: PerfmonDataset,
    data_type: str,
) -> CounterSeries:
    parsed = _parse_counter_path(_make_generated_path(prototype.counter_computer, prototype.counter_object, prototype.counter_instance, counter_name))
    return _build_series(
        parsed_path=parsed,
        timestamps=prototype.timestamps,
        values=values,
        data_type=data_type,
        quantized_indexes=dataset.quantized_indexes,
        quantized_times=dataset.quantized_times,
        analysis_interval_seconds=dataset.analysis_interval_seconds,
    )


def _build_generated_series_from_quantized(
    prototype: CounterSeries,
    counter_name: str,
    values: list[float | None],
    dataset: PerfmonDataset,
    data_type: str,
) -> CounterSeries:
    parsed = _parse_counter_path(_make_generated_path(prototype.counter_computer, prototype.counter_object, prototype.counter_instance, counter_name))
    quantized_avg = [_convert_to_data_type(value, data_type) if value is not None else None for value in values]
    quantized_trend = _generate_quantized_trend(quantized_avg, dataset.analysis_interval_seconds, data_type)
    numeric_values = [value for value in quantized_avg if value is not None]
    return CounterSeries(
        counter_path=parsed.canonical_path,
        counter_computer=parsed.computer,
        counter_object=parsed.object_name,
        counter_instance=parsed.instance,
        counter_name=parsed.counter_name,
        data_type=data_type,
        timestamps=list(dataset.quantized_times),
        values=list(quantized_avg),
        quantized_times=list(dataset.quantized_times),
        quantized_min=list(quantized_avg),
        quantized_avg=quantized_avg,
        quantized_max=list(quantized_avg),
        quantized_trend=quantized_trend,
        minimum=_convert_to_data_type(min(numeric_values), data_type) if numeric_values else None,
        average=_convert_to_data_type(sum(numeric_values) / len(numeric_values), data_type) if numeric_values else None,
        maximum=_convert_to_data_type(max(numeric_values), data_type) if numeric_values else None,
        trend=quantized_trend[-1] if quantized_trend else None,
    )


def _clone_series(series: CounterSeries, data_type: str, dataset: PerfmonDataset) -> CounterSeries:
    return _build_series(
        parsed_path=_parse_counter_path(series.counter_path),
        timestamps=series.timestamps,
        values=series.values,
        data_type=data_type,
        quantized_indexes=dataset.quantized_indexes,
        quantized_times=dataset.quantized_times,
        analysis_interval_seconds=dataset.analysis_interval_seconds,
    )


def _parse_counter_path(path: str) -> ParsedCounterPath:
    match = COUNTER_PATH_PATTERN.match(path.strip())
    if match is None:
        raise ValueError(f"Counter path non reconnu: {path}")

    return ParsedCounterPath(
        computer=(match.group("computer") or "LOCALHOST").strip(),
        object_name=(match.group("object") or "").strip(),
        instance=(match.group("instance") or "").strip(),
        counter_name=(match.group("counter") or "").strip(),
        raw_path=path,
    )


def _parse_perfmon_timestamp(raw_value: str) -> datetime:
    value = raw_value.strip().strip('"')
    formats = (
        "%m/%d/%Y %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    )
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:  # pragma: no cover
        raise ValueError(f"Unrecognized PerfMon timestamp: {raw_value}") from exc


def _parse_numeric(raw_value: str) -> float | None:
    value = raw_value.strip().strip('"')
    if not value or value == "-":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _auto_analysis_interval_seconds(timestamps: list[datetime]) -> int:
    if len(timestamps) < 2:
        return 60
    total_seconds = int((timestamps[-1] - timestamps[0]).total_seconds())
    return max(int(total_seconds / AUTO_ANALYSIS_TIME_SLICES), 1)


def _generate_quantized_indexes(timestamps: list[datetime], interval_seconds: int) -> tuple[list[list[int]], list[datetime]]:
    if not timestamps:
        return [[]], []

    cursor = timestamps[0]
    indexes: list[list[int]] = []
    starts: list[datetime] = []
    current: list[int] = []

    for index, timestamp in enumerate(timestamps):
        while timestamp >= cursor + timedelta(seconds=interval_seconds) and current:
            indexes.append(current)
            starts.append(cursor)
            current = []
            cursor = cursor + timedelta(seconds=interval_seconds)
        while timestamp >= cursor + timedelta(seconds=interval_seconds) and not current:
            indexes.append([])
            starts.append(cursor)
            cursor = cursor + timedelta(seconds=interval_seconds)
        current.append(index)

    indexes.append(current)
    starts.append(cursor)
    return indexes, starts


def _aggregate_bucket(values: list[float | None], bucket: list[int], mode: str, data_type: str) -> float | None:
    bucket_values = [values[index] for index in bucket if index < len(values) and values[index] is not None]
    if not bucket_values:
        return None
    if mode == "min":
        return _convert_to_data_type(min(bucket_values), data_type)
    if mode == "max":
        return _convert_to_data_type(max(bucket_values), data_type)
    return _convert_to_data_type(sum(bucket_values) / len(bucket_values), data_type)


def _generate_quantized_trend(values: list[float | None], analysis_interval_seconds: int, data_type: str) -> list[float | None]:
    if not values:
        return []
    trends: list[float | None] = [0]
    for upper_bound in range(1, len(values)):
        trends.append(_calculate_trend(values[: upper_bound + 1], analysis_interval_seconds, data_type))
    return trends


def _calculate_trend(values: list[float | None], analysis_interval_seconds: int, data_type: str) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return _convert_to_data_type(values[0] or 0, data_type)

    diffs: list[float] = []
    for current, previous in zip(values[1:], values[:-1]):
        if current is None or previous is None:
            diffs.append(0)
        else:
            diffs.append(current - previous)
    if not diffs:
        return 0
    average_diff = sum(diffs) / len(diffs)
    return _convert_to_data_type(_calculate_hourly_trend(average_diff, analysis_interval_seconds), data_type)


def _calculate_hourly_trend(value: float, analysis_interval_seconds: int) -> float:
    if analysis_interval_seconds < 3600:
        return value * (3600 / analysis_interval_seconds)
    if analysis_interval_seconds > 3600:
        return value / (analysis_interval_seconds / 3600)
    return value


def _convert_to_data_type(value: float | None, data_type: str) -> float | None:
    if value is None:
        return None
    normalized = (data_type or "double").lower()
    if normalized == "integer":
        return float(round(value, 0))
    if normalized.startswith("round"):
        return round(value, _coerce_int(normalized.removeprefix("round"), 0))
    return float(value)


def _compare(value: float | None, operator: str, threshold: float) -> bool:
    if value is None:
        return False
    if operator == "gt":
        return value > threshold
    if operator == "ge":
        return value >= threshold
    if operator == "lt":
        return value < threshold
    if operator == "le":
        return value <= threshold
    if operator == "eq":
        return value == threshold
    return value > threshold


def _resolve_threshold_value(expression: str, answers: dict[str, str | bool]) -> float | None:
    expr = expression.strip()
    if not expr:
        return None

    if expr.startswith("$"):
        return _coerce_float(answers.get(expr.removeprefix("$").strip()))

    match = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*(KB|MB|GB)?", expr, flags=re.IGNORECASE)
    if match is None:
        return None

    value = float(match.group(1))
    unit = (match.group(2) or "").upper()
    if unit == "KB":
        value *= BYTES_IN_KB
    elif unit == "MB":
        value *= BYTES_IN_MB
    elif unit == "GB":
        value *= BYTES_IN_GB
    return value


def _merge_question_answers(questions: list[Question], provided_answers: dict[str, str | bool]) -> dict[str, str | bool]:
    merged: dict[str, str | bool] = {question.var_name: question.default_value for question in questions}
    for key, value in provided_answers.items():
        merged[str(key)] = value
    return merged


def _status_label(status: str) -> str:
    return {
        "critical": "Critical",
        "warning": "Warning",
        "ok": "OK",
        "missing": "Incomplete",
    }.get(status, status)


def _determine_status(missing_datasources: list[str], alerts: list[AlertEvent]) -> str:
    if missing_datasources:
        return "missing"
    if any(alert.condition.lower() == "critical" for alert in alerts):
        return "critical"
    if alerts:
        return "warning"
    return "ok"


def _make_generated_path(computer: str, object_name: str, instance: str, counter_name: str) -> str:
    if instance:
        return f"\\\\{computer}\\{object_name}({instance})\\{counter_name}"
    return f"\\\\{computer}\\{object_name}\\{counter_name}"


def _match_series_by_instance(instance: str, collection: list[CounterSeries]) -> CounterSeries | None:
    for series in collection:
        if series.counter_instance.lower() == (instance or "").lower():
            return series
    return None


def _find_total_series(collection: list[CounterSeries]) -> CounterSeries:
    for series in collection:
        if series.counter_instance.lower() == "_total":
            return series
    return collection[0]


def _normalize_pagefile_instance(instance: str) -> str:
    return instance.replace("\\??\\", "").replace("\\pagefile.sys", "").strip()


def _format_time_slice(index: int, quantized_times: list[datetime], interval_seconds: int) -> str:
    if not quantized_times or index >= len(quantized_times):
        return f"slice {index}"
    start = quantized_times[index]
    end = start + timedelta(seconds=interval_seconds)
    return f"{start.strftime('%Y-%m-%d %H:%M:%S')} -> {end.strftime('%H:%M:%S')}"


def _describe_time_window(series: CounterSeries) -> str:
    if not series.quantized_times:
        return "Time range unavailable."
    start = series.quantized_times[0]
    end = series.quantized_times[-1]
    same_day = start.date() == end.date()
    if same_day:
        return f"Period: {start.strftime('%Y-%m-%d %H:%M:%S')} -> {end.strftime('%H:%M:%S')} ({len(series.quantized_avg)} points)"
    return f"Period: {start.strftime('%Y-%m-%d %H:%M:%S')} -> {end.strftime('%Y-%m-%d %H:%M:%S')} ({len(series.quantized_avg)} points)"


def _build_time_tick_indexes(length: int, tick_count: int = 5) -> list[int]:
    if length <= 1:
        return [0]
    indexes = {0, length - 1}
    for step in range(1, max(tick_count - 1, 1)):
        indexes.add(round((length - 1) * step / (tick_count - 1)))
    return sorted(indexes)


def _estimate_series_interval_seconds(times: list[datetime]) -> int:
    if len(times) < 2:
        return 60
    deltas = [(current - previous).total_seconds() for previous, current in zip(times[:-1], times[1:]) if current > previous]
    if not deltas:
        return 60
    return max(int(sum(deltas) / len(deltas)), 1)


def _format_time_label(value: datetime, interval_seconds: int, include_date: bool = False) -> str:
    if include_date:
        return value.strftime("%m-%d %H:%M")
    if interval_seconds < 60:
        return value.strftime("%H:%M:%S")
    return value.strftime("%H:%M")


def _build_smooth_svg_path(points: list[tuple[float, float]]) -> str:
    if not points:
        return ""
    if len(points) == 1:
        x, y = points[0]
        return f"M {x:.2f},{y:.2f}"

    path = f"M {points[0][0]:.2f},{points[0][1]:.2f}"
    for index in range(1, len(points)):
        previous_point = points[index - 2] if index > 1 else points[index - 1]
        current_point = points[index - 1]
        next_point = points[index]
        following_point = points[index + 1] if index + 1 < len(points) else points[index]

        control_1_x = current_point[0] + (next_point[0] - previous_point[0]) / 6
        control_1_y = current_point[1] + (next_point[1] - previous_point[1]) / 6
        control_2_x = next_point[0] - (following_point[0] - current_point[0]) / 6
        control_2_y = next_point[1] - (following_point[1] - current_point[1]) / 6
        path += (
            f" C {control_1_x:.2f},{control_1_y:.2f}"
            f" {control_2_x:.2f},{control_2_y:.2f}"
            f" {next_point[0]:.2f},{next_point[1]:.2f}"
        )
    return path


def _build_area_path(points: list[tuple[float, float]], chart_bottom: float) -> str:
    if not points:
        return ""
    line_path = _build_smooth_svg_path(points)
    first_x = points[0][0]
    last_x = points[-1][0]
    return f"{line_path} L {last_x:.2f},{chart_bottom:.2f} L {first_x:.2f},{chart_bottom:.2f} Z"


def _format_chart_axis_value(value: float) -> str:
    if abs(value) >= 1000:
        return f"{value:,.0f}".replace(",", " ")
    if abs(value) >= 100:
        return f"{value:.1f}"
    if abs(value) >= 1:
        return f"{value:.2f}"
    return f"{value:.4f}"


def _format_number(value: float | None) -> str:
    if value is None:
        return "n/a"
    if abs(value) >= 1000:
        return f"{value:,.0f}".replace(",", " ")
    if abs(value) >= 100:
        return f"{value:.1f}"
    if abs(value) >= 1:
        return f"{value:.2f}"
    return f"{value:.4f}"


def _coerce_float(value: str | bool | None, default: float | None = None) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if value is None:
        return default
    try:
        return float(str(value).strip())
    except ValueError:
        return default


def _coerce_int(value: str | int | float | None, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _value_at(values: list[float | None], index: int) -> float | None:
    if index >= len(values):
        return None
    return values[index]


def _nonpaged_pool_maximum(os_name: str, physical_memory_gb: float, user_va: float) -> float:
    physical_memory_bytes = max(int(round(physical_memory_gb, 0)), 1) * BYTES_IN_GB

    if os_name in {"WINDOWS XP 32-BIT", "WINDOWS SERVER 2003 32-BIT"}:
        if user_va > 2048:
            return 128 * BYTES_IN_MB
        return 208 * BYTES_IN_MB if physical_memory_bytes <= BYTES_IN_GB else 256 * BYTES_IN_MB

    if os_name in {"WINDOWS XP 64-BIT", "WINDOWS SERVER 2003 64-BIT"}:
        return physical_memory_bytes * 0.75

    if os_name in {"WINDOWS VISTA 32-BIT", "WINDOWS SERVER 2008 32-BIT", "WINDOWS 7 32-BIT", "WINDOWS 8 32-BIT"}:
        if user_va > 2048:
            return min(physical_memory_bytes * 0.75, (4096 - user_va) * BYTES_IN_MB)
        return min(physical_memory_bytes * 0.75, 2 * BYTES_IN_GB)

    return min(physical_memory_bytes * 0.75, 128 * BYTES_IN_GB)


def _paged_pool_maximum(os_name: str, physical_memory_gb: float, user_va: float) -> float:
    physical_memory_rounded = max(int(round(physical_memory_gb, 0)), 1)
    physical_memory_bytes = physical_memory_rounded * BYTES_IN_GB

    if os_name in {"WINDOWS XP 32-BIT", "WINDOWS SERVER 2003 32-BIT"}:
        if user_va > 2048:
            return 158 * BYTES_IN_MB
        return 168 * BYTES_IN_MB if physical_memory_bytes <= BYTES_IN_GB else 354 * BYTES_IN_MB

    if os_name in {"WINDOWS XP 64-BIT", "WINDOWS SERVER 2003 64-BIT"}:
        thresholds = {
            1: 3564, 2: 3564, 3: 3564, 4: 5837, 5: 5837, 6: 5837, 7: 5837,
            8: 12657, 9: 12657, 10: 12657, 11: 12657, 12: 19364, 13: 19364, 14: 19364, 15: 19364,
            16: 39496, 17: 39496, 18: 39496, 19: 39496, 20: 39496, 21: 39496, 22: 39496, 23: 39496,
            24: 39496, 25: 39496, 26: 39496, 27: 39496, 28: 39496, 29: 39496, 30: 39496, 31: 39496, 32: 54180,
        }
        return thresholds.get(physical_memory_rounded, 54180) * BYTES_IN_MB

    if os_name in {"WINDOWS VISTA 32-BIT", "WINDOWS SERVER 2008 32-BIT", "WINDOWS 7 32-BIT", "WINDOWS 8 32-BIT"}:
        if user_va > 2048:
            return min(2 * BYTES_IN_GB, (4096 - user_va) * BYTES_IN_MB)
        return 2 * BYTES_IN_GB

    return 128 * BYTES_IN_GB
