const state = {
  items: [],
  filteredItems: [],
  selectedFile: null,
  selectedDetail: null,
  questionAnswers: {},
};

const elements = {
  statThresholdFiles: document.querySelector("#stat-threshold-files"),
  statAnalyses: document.querySelector("#stat-analyses"),
  statQuestions: document.querySelector("#stat-questions"),
  uploadForm: document.querySelector("#upload-form"),
  logFileInput: document.querySelector("#log-file"),
  uploadButton: document.querySelector("#upload-button"),
  uploadStatus: document.querySelector("#upload-status"),
  analysisConfig: document.querySelector("#analysis-config"),
  uploadResult: document.querySelector("#upload-result"),
  searchInput: document.querySelector("#search-input"),
  thresholdList: document.querySelector("#threshold-list"),
  detailEmpty: document.querySelector("#detail-empty"),
  detailPanel: document.querySelector("#detail-panel"),
  detailFileName: document.querySelector("#detail-file-name"),
  detailDisplayName: document.querySelector("#detail-display-name"),
  detailDescription: document.querySelector("#detail-description"),
  detailVersion: document.querySelector("#detail-version"),
  detailLanguage: document.querySelector("#detail-language"),
  detailOwner: document.querySelector("#detail-owner"),
  detailInheritances: document.querySelector("#detail-inheritances"),
  detailCategories: document.querySelector("#detail-categories"),
  detailQuestions: document.querySelector("#detail-questions"),
  detailAnalyses: document.querySelector("#detail-analyses"),
  detailAnalysisCount: document.querySelector("#detail-analysis-count"),
};

const api = {
  async listThresholdFiles() {
    const response = await fetch("/api/threshold-files");
    if (!response.ok) {
      throw new Error("Unable to load threshold files.");
    }
    return response.json();
  },
  async getThresholdFile(fileName) {
    const response = await fetch(`/api/threshold-files/${encodeURIComponent(fileName)}`);
    if (!response.ok) {
      throw new Error(`Unable to load ${fileName}.`);
    }
    return response.json();
  },
};

function createChip(text, tone = "neutral") {
  const chip = document.createElement("span");
  chip.className = `chip chip-${tone}`;
  chip.textContent = text;
  return chip;
}

function renderThresholdList() {
  elements.thresholdList.innerHTML = "";

  if (!state.filteredItems.length) {
    const empty = document.createElement("p");
    empty.className = "list-empty";
    empty.textContent = "No files match the current search.";
    elements.thresholdList.append(empty);
    return;
  }

  for (const item of state.filteredItems) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "threshold-card";
    if (state.selectedFile === item.file_name) {
      button.classList.add("is-active");
    }

    button.innerHTML = `
      <div class="threshold-card-head">
        <strong>${item.display_name}</strong>
        <span>${item.version || "n/a"}</span>
      </div>
      <p>${item.description || "No description available."}</p>
      <div class="threshold-card-meta">
        <span>${item.analysis_count} analyses</span>
        <span>${item.category_count} categories</span>
        <span>${item.question_count} questions</span>
      </div>
    `;

    button.addEventListener("click", () => {
      state.selectedFile = item.file_name;
      renderThresholdList();
      loadDetails(item.file_name);
    });

    elements.thresholdList.append(button);
  }
}

function renderQuestions(questions) {
  elements.detailQuestions.innerHTML = "";
  if (!questions.length) {
    elements.detailQuestions.append(createChip("No questions", "soft"));
    return;
  }

  for (const question of questions) {
    const article = document.createElement("article");
    article.className = "stack-item";
    article.innerHTML = `
      <h4>${question.var_name || "Question"}</h4>
      <p>${question.text || "No label available."}</p>
      <div class="stack-item-meta">
        <span>${question.data_type || "n/a"}</span>
        <span>default: ${question.default_value || "n/a"}</span>
        <span>${question.options.length} options</span>
      </div>
    `;
    elements.detailQuestions.append(article);
  }
}

function renderAnalysisConfig() {
  if (!state.selectedDetail) {
    elements.analysisConfig.innerHTML = "";
    return;
  }

  const questionMarkup = (state.selectedDetail.questions || [])
    .map((question) => {
      const fieldId = `question-${question.var_name}`;
      const currentValue = state.questionAnswers[question.var_name] ?? question.default_value ?? "";

      if (question.data_type === "boolean") {
        return `
          <div class="config-field">
            <label for="${fieldId}">${question.var_name}</label>
            <select id="${fieldId}" data-question-key="${question.var_name}">
              <option value="True" ${String(currentValue) === "True" ? "selected" : ""}>True</option>
              <option value="False" ${String(currentValue) === "False" ? "selected" : ""}>False</option>
            </select>
            <small>${question.text || "PAL boolean value."}</small>
          </div>
        `;
      }

      if (question.data_type === "options") {
        const options = (question.options || [])
          .map(
            (option) =>
              `<option value="${option}" ${String(currentValue) === String(option) ? "selected" : ""}>${option}</option>`
          )
          .join("");
        return `
          <div class="config-field">
            <label for="${fieldId}">${question.var_name}</label>
            <select id="${fieldId}" data-question-key="${question.var_name}">
              ${options}
            </select>
            <small>${question.text || "PAL question."}</small>
          </div>
        `;
      }

      return `
        <div class="config-field">
          <label for="${fieldId}">${question.var_name}</label>
          <input id="${fieldId}" data-question-key="${question.var_name}" type="text" value="${String(currentValue)}" />
          <small>${question.text || "PAL question."}</small>
        </div>
      `;
    })
    .join("");

  elements.analysisConfig.innerHTML = `
    <div class="analysis-config-grid">
      <article class="mini-card">
        <p class="section-kicker">Historical analysis</p>
        <h3>Active threshold</h3>
        <p><strong>${state.selectedDetail.display_name}</strong></p>
        <p class="muted">${state.selectedDetail.file_name}</p>
        <p class="muted">
          Upload runs the full PAL analysis flow with this threshold file and these answers.
        </p>
      </article>
      <article class="mini-card">
        <p class="section-kicker">PAL questions</p>
        <h3>Configuration sent to the engine</h3>
        <div class="config-form">
          ${questionMarkup || "<p class='muted'>No questions for this threshold file.</p>"}
        </div>
      </article>
    </div>
  `;

  elements.analysisConfig.querySelectorAll("[data-question-key]").forEach((field) => {
    const updateValue = () => {
      state.questionAnswers[field.dataset.questionKey] = field.value;
    };
    field.addEventListener("input", updateValue);
    field.addEventListener("change", updateValue);
  });
}

function renderAnalyses(analyses) {
  elements.detailAnalyses.innerHTML = "";
  elements.detailAnalysisCount.textContent = `${analyses.length} analyses`;

  for (const analysis of analyses) {
    const details = document.createElement("details");
    details.className = "analysis-item";

    const thresholdCount = analysis.thresholds.length;
    const datasourceCount = analysis.datasources.length;
    const chartCount = analysis.charts.length;

    const thresholdPreview = analysis.thresholds
      .slice(0, 2)
      .map((threshold) => `<li>${threshold.name || threshold.condition || "Threshold"}</li>`)
      .join("");

    const datasourcePreview = analysis.datasources
      .slice(0, 3)
      .map((source) => `<li>${source.expression_path || source.name}</li>`)
      .join("");

    details.innerHTML = `
      <summary>
        <div>
          <p>${analysis.category || "Uncategorized"}</p>
          <h4>${analysis.name}</h4>
        </div>
        <div class="analysis-summary">
          <span>${datasourceCount} datasources</span>
          <span>${thresholdCount} thresholds</span>
          <span>${chartCount} charts</span>
        </div>
      </summary>
      <div class="analysis-body">
        <div class="analysis-meta">
          <span>${analysis.enabled ? "Enabled" : "Disabled"}</span>
          <span>Source: ${analysis.source_file}</span>
          <span>Primary: ${analysis.primary_datasource || "n/a"}</span>
        </div>
        <div class="analysis-columns">
          <article>
            <h5>Description</h5>
            <div class="rich-html">${analysis.description_html || "<p>No description available yet.</p>"}</div>
          </article>
          <article>
            <h5>Datasources</h5>
            <ul>${datasourcePreview || "<li>No datasource</li>"}</ul>
          </article>
          <article>
            <h5>Thresholds</h5>
            <ul>${thresholdPreview || "<li>No threshold</li>"}</ul>
          </article>
        </div>
      </div>
    `;

    elements.detailAnalyses.append(details);
  }
}

function renderDetail(detail) {
  state.selectedDetail = detail;
  state.questionAnswers = {};
  for (const question of detail.questions || []) {
    if (question.data_type === "boolean") {
      state.questionAnswers[question.var_name] = String(question.default_value) === "True" ? "True" : "False";
    } else {
      state.questionAnswers[question.var_name] = question.default_value ?? "";
    }
  }

  elements.detailEmpty.classList.add("hidden");
  elements.detailPanel.classList.remove("hidden");

  elements.detailFileName.textContent = detail.file_name;
  elements.detailDisplayName.textContent = detail.display_name;
  elements.detailDescription.textContent = detail.description || "No description available.";
  elements.detailVersion.textContent = detail.version || "n/a";
  elements.detailLanguage.textContent = detail.language || "n/a";
  elements.detailOwner.textContent = detail.owners || "n/a";

  elements.detailInheritances.innerHTML = "";
  if (detail.inheritances.length) {
    detail.inheritances.forEach((item) => {
      elements.detailInheritances.append(createChip(item, "accent"));
    });
  } else {
    elements.detailInheritances.append(createChip("No inheritance", "soft"));
  }

  elements.detailCategories.innerHTML = "";
  const categories = Object.entries(detail.category_breakdown || {});
  if (categories.length) {
    categories.forEach(([name, count]) => {
      elements.detailCategories.append(createChip(`${name} - ${count}`, "warm"));
    });
  } else {
    elements.detailCategories.append(createChip("No categories", "soft"));
  }

  renderQuestions(detail.questions);
  renderAnalyses(detail.analyses);
  renderAnalysisConfig();
}

function renderUploadResult(file) {
  elements.uploadResult.classList.remove("hidden");
  const isFullPalReport = file.report_mode === "legacy_full" || file.report_mode === "python_full";
  const reportModeLabel =
    file.report_mode === "legacy_full"
      ? "Full legacy PAL"
      : file.report_mode === "python_full"
        ? "Full Python PAL"
        : "Modern summary";
  const reportLink = file.report_url
    ? `
      <a class="report-link" href="${file.report_url}" target="_blank" rel="noreferrer">
        Open HTML report${isFullPalReport ? " (full PAL)" : ""}
      </a>
    `
    : "";

  const baseMeta = `
    <div class="upload-meta">
      <span>${file.file_name}</span>
      <span>${file.log_type.toUpperCase()}</span>
      <span>${Math.max(1, Math.round(file.size_bytes / 1024))} KB</span>
    </div>
  `;

  if (file.log_type === "csv") {
    const headerCells = (file.preview_columns || [])
      .map((column) => `<th>${column}</th>`)
      .join("");

    const rowMarkup = (file.preview_rows || [])
      .map(
        (row) => `
          <tr>${row.map((cell) => `<td>${cell ?? ""}</td>`).join("")}</tr>
        `
      )
      .join("");

    elements.uploadResult.innerHTML = `
      <div class="upload-result-head">
        <div>
          <p class="section-kicker">Uploaded file</p>
          <h3>CSV preview</h3>
        </div>
        ${baseMeta}
      </div>
      ${reportLink}
      <div class="chip-list">
        <span class="chip chip-accent">mode: ${reportModeLabel}</span>
        <span class="chip chip-warm">threshold: ${file.threshold_file_used || "n/a"}</span>
      </div>
      <div class="upload-summary-grid">
        <article class="mini-card">
          <h3>Structure</h3>
          <div class="chip-list">
            <span class="chip chip-accent">${file.column_count} columns</span>
            <span class="chip chip-accent">${file.row_count} rows</span>
            <span class="chip chip-soft">delimiter: ${file.delimiter}</span>
          </div>
        </article>
        <article class="mini-card">
          <h3>Columns</h3>
          <div class="chip-list">
            ${(file.preview_columns || []).map((column) => `<span class="chip chip-warm">${column}</span>`).join("")}
          </div>
        </article>
      </div>
      <div class="preview-table-shell">
        <table class="preview-table">
          <thead><tr>${headerCells}</tr></thead>
          <tbody>${rowMarkup || '<tr><td colspan="8">No rows to display.</td></tr>'}</tbody>
        </table>
      </div>
    `;
    return;
  }

  elements.uploadResult.innerHTML = `
    <div class="upload-result-head">
      <div>
        <p class="section-kicker">Uploaded file</p>
        <h3>BLG preview</h3>
      </div>
      ${baseMeta}
    </div>
    ${reportLink}
    <div class="chip-list">
      <span class="chip chip-accent">mode: ${reportModeLabel}</span>
      <span class="chip chip-warm">threshold: ${file.threshold_file_used || "n/a"}</span>
      ${file.threshold_auto_selected ? `<span class="chip chip-accent">auto: ${file.threshold_auto_selected}</span>` : ""}
      ${typeof file.alert_count === "number" ? `<span class="chip chip-soft">alerts: ${file.alert_count}</span>` : ""}
      ${typeof file.triggered_analysis_count === "number" ? `<span class="chip chip-soft">triggered analyses: ${file.triggered_analysis_count}</span>` : ""}
    </div>
    <div class="upload-summary-grid">
      <article class="mini-card">
        <h3>Capture</h3>
        <div class="chip-list">
          <span class="chip chip-accent">start: ${file.begin || "n/a"}</span>
          <span class="chip chip-accent">end: ${file.end || "n/a"}</span>
          <span class="chip chip-soft">samples: ${file.samples || "n/a"}</span>
        </div>
      </article>
      <article class="mini-card">
        <h3>Counters</h3>
        <div class="chip-list">
          <span class="chip chip-warm">${file.counter_count} counters</span>
          <span class="chip chip-warm">${(file.counter_objects || []).length} objects</span>
        </div>
      </article>
    </div>
    <div class="mini-card">
      <h3>Detected objects</h3>
      <div class="chip-list">
        ${(file.counter_objects || []).slice(0, 20).map((item) => `<span class="chip chip-accent">${item}</span>`).join("")}
      </div>
    </div>
    <div class="mini-card">
      <h3>Detected counters</h3>
      <ul class="counter-preview-list">
        ${(file.preview_counters || []).map((item) => `<li>${item}</li>`).join("")}
      </ul>
    </div>
  `;
}

async function loadDetails(fileName) {
  try {
    const detail = await api.getThresholdFile(fileName);
    renderDetail(detail);
  } catch (error) {
    elements.detailEmpty.classList.remove("hidden");
    elements.detailPanel.classList.add("hidden");
    elements.detailEmpty.innerHTML = `
      <p class="section-kicker">Error</p>
      <h2>Unable to load details</h2>
      <p>${error.message}</p>
    `;
  }
}

function applySearch(query) {
  const value = query.trim().toLowerCase();
  state.filteredItems = state.items.filter((item) => {
    const haystack = `${item.display_name} ${item.file_name} ${item.description}`.toLowerCase();
    return haystack.includes(value);
  });
  renderThresholdList();
}

async function boot() {
  try {
    const payload = await api.listThresholdFiles();
    state.items = payload.items;
    state.filteredItems = payload.items;

    elements.statThresholdFiles.textContent = payload.overview.threshold_file_count;
    elements.statAnalyses.textContent = payload.overview.analysis_count;
    elements.statQuestions.textContent = payload.overview.question_count;

    renderThresholdList();

    const defaultItem =
      payload.items.find((item) => item.file_name === "QuickSystemOverview.xml") || payload.items[0];

    if (defaultItem) {
      state.selectedFile = defaultItem.file_name;
      renderThresholdList();
      loadDetails(defaultItem.file_name);
    }
  } catch (error) {
    elements.thresholdList.innerHTML = `<p class="list-empty">${error.message}</p>`;
  }
}

elements.searchInput.addEventListener("input", (event) => {
  applySearch(event.target.value);
});

elements.uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const file = elements.logFileInput.files?.[0];
  if (!file) {
    elements.uploadStatus.textContent = "Select a .csv or .blg file before starting the upload.";
    return;
  }

  elements.uploadButton.disabled = true;
  elements.uploadStatus.textContent = `Uploading ${file.name} and generating the full PAL report...`;

  try {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("run_historical", "true");
    formData.append("threshold_file", state.selectedFile || "QuickSystemOverview.xml");
    formData.append("question_answers", JSON.stringify(state.questionAnswers));

    const response = await fetch("/api/uploads", {
      method: "POST",
      body: formData,
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Upload failed.");
    }
    elements.uploadStatus.textContent = payload.message;
    renderUploadResult(payload.file);
  } catch (error) {
    elements.uploadStatus.textContent = error.message;
    elements.uploadResult.classList.add("hidden");
  } finally {
    elements.uploadButton.disabled = false;
  }
});

boot();
