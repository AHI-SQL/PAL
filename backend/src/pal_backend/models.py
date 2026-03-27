from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class Question:
    var_name: str
    text: str
    data_type: str
    default_value: str
    options: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class DataSource:
    source_type: str
    name: str
    expression_path: str
    data_type: str
    collection_var_name: str
    code: str = ""
    exclude_instances: list[str] = field(default_factory=list)
    is_counter_object_regular_expression: bool = False
    is_counter_name_regular_expression: bool = False
    is_counter_instance_regular_expression: bool = False
    regular_expression_counter_path: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Threshold:
    name: str
    condition: str
    color: str
    priority: str
    description_html: str
    code: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class ChartSeries:
    name: str
    code: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Chart:
    title: str
    datasource: str
    labels: str
    background_style: str
    max_limit: str = ""
    series: list[ChartSeries] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Analysis:
    identifier: str
    name: str
    category: str
    enabled: bool
    primary_datasource: str
    description_html: str
    datasources: list[DataSource] = field(default_factory=list)
    thresholds: list[Threshold] = field(default_factory=list)
    charts: list[Chart] = field(default_factory=list)
    source_file: str = ""

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "name": self.name,
            "category": self.category,
            "enabled": self.enabled,
            "primary_datasource": self.primary_datasource,
            "description_html": self.description_html,
            "datasources": [item.to_dict() for item in self.datasources],
            "thresholds": [item.to_dict() for item in self.thresholds],
            "charts": [item.to_dict() for item in self.charts],
            "source_file": self.source_file,
        }


@dataclass(slots=True)
class ThresholdFileSummary:
    file_name: str
    display_name: str
    description: str
    version: str
    content_owners: str
    question_count: int
    analysis_count: int
    category_count: int
    inherited_file_count: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class ThresholdFileDetail:
    file_name: str
    display_name: str
    description: str
    version: str
    language: str
    owners: str
    feedback_email: str
    inheritances: list[str]
    questions: list[Question]
    analyses: list[Analysis]

    def to_dict(self) -> dict:
        return {
            "file_name": self.file_name,
            "display_name": self.display_name,
            "description": self.description,
            "version": self.version,
            "language": self.language,
            "owners": self.owners,
            "feedback_email": self.feedback_email,
            "inheritances": list(self.inheritances),
            "questions": [item.to_dict() for item in self.questions],
            "analyses": [item.to_dict() for item in self.analyses],
        }
