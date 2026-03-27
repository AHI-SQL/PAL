from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET

from .models import Analysis, Chart, ChartSeries, DataSource, Question, Threshold, ThresholdFileDetail, ThresholdFileSummary


PUBLIC_THRESHOLD_FILES = (
    "QuickSystemOverview.xml",
    "SystemOverview.xml",
    "SQLServer.xml",
    "SQLServer2008R2.xml",
    "SQLServer2012.xml",
    "SQLServer2014.xml",
)


class ThresholdRepository:
    def __init__(self, threshold_dir: Path) -> None:
        self.threshold_dir = threshold_dir

    def list_threshold_files(self) -> list[ThresholdFileSummary]:
        summaries: list[ThresholdFileSummary] = []
        for file_path in self._iter_public_threshold_paths():
            detail = self.get_threshold_file(file_path.name)
            summaries.append(
                ThresholdFileSummary(
                    file_name=detail.file_name,
                    display_name=detail.display_name,
                    description=detail.description,
                    version=detail.version,
                    content_owners=detail.owners,
                    question_count=len(detail.questions),
                    analysis_count=len(detail.analyses),
                    category_count=len({analysis.category for analysis in detail.analyses if analysis.category}),
                    inherited_file_count=len(detail.inheritances),
                )
            )
        return summaries

    def get_threshold_file(self, file_name: str) -> ThresholdFileDetail:
        if not self.is_public_threshold_file(file_name):
            raise FileNotFoundError(f"Threshold file not available in the PAL library: {file_name}")

        xml_root = self._parse_root(file_name)
        inheritances = [node.attrib.get("FILEPATH", "") for node in xml_root.findall("INHERITANCE") if node.attrib.get("FILEPATH")]
        questions = self._load_questions(file_name=file_name, root=xml_root, visited=[])
        analyses = self._load_analyses(file_name=file_name, root=xml_root, visited=[])

        return ThresholdFileDetail(
            file_name=file_name,
            display_name=xml_root.attrib.get("NAME", file_name),
            description=xml_root.attrib.get("DESCRIPTION", ""),
            version=xml_root.attrib.get("VERSION", ""),
            language=xml_root.attrib.get("LANGUAGE", ""),
            owners=xml_root.attrib.get("CONTENTOWNERS", ""),
            feedback_email=xml_root.attrib.get("FEEDBACKEMAILADDRESS", ""),
            inheritances=inheritances,
            questions=questions,
            analyses=analyses,
        )

    def category_breakdown(self, detail: ThresholdFileDetail) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for analysis in detail.analyses:
            counts[analysis.category or "Uncategorized"] += 1
        return dict(sorted(counts.items(), key=lambda item: item[0].lower()))

    @staticmethod
    def is_public_threshold_file(file_name: str) -> bool:
        return file_name in PUBLIC_THRESHOLD_FILES

    def _iter_public_threshold_paths(self) -> list[Path]:
        paths = [self.threshold_dir / file_name for file_name in PUBLIC_THRESHOLD_FILES if (self.threshold_dir / file_name).exists()]
        return sorted(paths, key=lambda item: item.name.lower())

    def _load_analyses(self, file_name: str, root: ET.Element, visited: list[str]) -> list[Analysis]:
        visit_key = file_name.lower()
        if visit_key in visited:
            raise ValueError(f"Circular inheritance detected while loading {file_name}")

        analyses = [self._parse_analysis(node, file_name) for node in root.findall("ANALYSIS")]
        seen_keys = {self._analysis_key(item.identifier, item.name) for item in analyses}

        next_visited = [*visited, visit_key]
        for inheritance in root.findall("INHERITANCE"):
            inherited_file = inheritance.attrib.get("FILEPATH", "").strip()
            if not inherited_file:
                continue
            inherited_root = self._parse_root(inherited_file)
            for analysis in self._load_analyses(inherited_file, inherited_root, next_visited):
                key = self._analysis_key(analysis.identifier, analysis.name)
                if key not in seen_keys:
                    analyses.append(analysis)
                    seen_keys.add(key)
        return analyses

    def _load_questions(self, file_name: str, root: ET.Element, visited: list[str]) -> list[Question]:
        visit_key = file_name.lower()
        if visit_key in visited:
            raise ValueError(f"Circular inheritance detected while loading {file_name}")

        questions = [self._parse_question(node) for node in root.findall("QUESTION")]
        seen_keys = {question.var_name.lower() for question in questions}

        next_visited = [*visited, visit_key]
        for inheritance in root.findall("INHERITANCE"):
            inherited_file = inheritance.attrib.get("FILEPATH", "").strip()
            if not inherited_file:
                continue
            inherited_root = self._parse_root(inherited_file)
            for question in self._load_questions(inherited_file, inherited_root, next_visited):
                key = question.var_name.lower()
                if key not in seen_keys:
                    questions.append(question)
                    seen_keys.add(key)
        return questions

    def _parse_root(self, file_name: str) -> ET.Element:
        target = self.threshold_dir / file_name
        if not target.exists():
            raise FileNotFoundError(f"Threshold file not found: {file_name}")
        return ET.parse(target).getroot()

    @staticmethod
    def _analysis_key(identifier: str, name: str) -> str:
        if identifier:
            return f"id:{identifier.strip().lower()}"
        return f"name:{name.strip().lower()}"

    def _parse_question(self, node: ET.Element) -> Question:
        options = [item.strip() for item in node.attrib.get("OPTIONS", "").split(",") if item.strip()]
        return Question(
            var_name=node.attrib.get("QUESTIONVARNAME", ""),
            text=(node.text or "").strip(),
            data_type=node.attrib.get("DATATYPE", ""),
            default_value=node.attrib.get("DEFAULTVALUE", ""),
            options=options,
        )

    def _parse_analysis(self, node: ET.Element, source_file: str) -> Analysis:
        datasources = [self._parse_datasource(item) for item in node.findall("DATASOURCE")]
        thresholds = [self._parse_threshold(item) for item in node.findall("THRESHOLD")]
        charts = [self._parse_chart(item) for item in node.findall("CHART")]
        description_node = node.find("DESCRIPTION")

        return Analysis(
            identifier=node.attrib.get("ID", ""),
            name=node.attrib.get("NAME", ""),
            category=node.attrib.get("CATEGORY", ""),
            enabled=node.attrib.get("ENABLED", "False").lower() == "true",
            primary_datasource=node.attrib.get("PRIMARYDATASOURCE", ""),
            description_html=(description_node.text or "").strip() if description_node is not None and description_node.text else "",
            datasources=datasources,
            thresholds=thresholds,
            charts=charts,
            source_file=source_file,
        )

    def _parse_datasource(self, node: ET.Element) -> DataSource:
        code_node = node.find("CODE")
        return DataSource(
            source_type=node.attrib.get("TYPE", ""),
            name=node.attrib.get("NAME", ""),
            expression_path=node.attrib.get("EXPRESSIONPATH", ""),
            data_type=node.attrib.get("DATATYPE", ""),
            collection_var_name=node.attrib.get("COLLECTIONVARNAME", ""),
            code=(code_node.text or "").strip() if code_node is not None and code_node.text else "",
            exclude_instances=[item.attrib.get("INSTANCE", "").strip() for item in node.findall("EXCLUDE") if item.attrib.get("INSTANCE", "").strip()],
            is_counter_object_regular_expression=node.attrib.get("ISCOUNTEROBJECTREGULAREXPRESSION", "False").lower() == "true",
            is_counter_name_regular_expression=node.attrib.get("ISCOUNTERNAMEREGULAREXPRESSION", "False").lower() == "true",
            is_counter_instance_regular_expression=node.attrib.get("ISCOUNTERINSTANCEREGULAREXPRESSION", "False").lower() == "true",
            regular_expression_counter_path=node.attrib.get("REGULAREXPRESSIONCOUNTERPATH", ""),
        )

    def _parse_threshold(self, node: ET.Element) -> Threshold:
        description_node = node.find("DESCRIPTION")
        code_node = node.find("CODE")
        return Threshold(
            name=node.attrib.get("NAME", ""),
            condition=node.attrib.get("CONDITION", ""),
            color=node.attrib.get("COLOR", ""),
            priority=node.attrib.get("PRIORITY", ""),
            description_html=(description_node.text or "").strip() if description_node is not None and description_node.text else "",
            code=(code_node.text or "").strip() if code_node is not None and code_node.text else "",
        )

    def _parse_chart(self, node: ET.Element) -> Chart:
        series = []
        for series_node in node.findall("SERIES"):
            code_node = series_node.find("CODE")
            series.append(
                ChartSeries(
                    name=series_node.attrib.get("NAME", ""),
                    code=(code_node.text or "").strip() if code_node is not None and code_node.text else "",
                )
            )

        return Chart(
            title=node.attrib.get("CHARTTITLE", ""),
            datasource=node.attrib.get("DATASOURCE", ""),
            labels=node.attrib.get("CHARTLABELS", ""),
            background_style=node.attrib.get("BACKGRADIENTSTYLE", ""),
            max_limit=node.attrib.get("MAXLIMIT", ""),
            series=series,
        )
