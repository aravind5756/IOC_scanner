const scanForm = document.querySelector("form");
const scanButton = document.querySelector("#scan-button");
const scanStatus = document.querySelector("#scan-status");
const scanError = document.querySelector("#scan-error");
const scanResults = document.querySelector("#scan-results");
const findingsTableWrapper = document.querySelector("#findings-table-wrapper");
const noFindings = document.querySelector("#no-findings");
const securityAlerts = document.querySelector("#security-alerts");
const alertsList = document.querySelector("#alerts-list");
const allowlistedSummary = document.querySelector("#allowlisted-summary");
const allowlistedByType = document.querySelector("#allowlisted-by-type");

function addTableCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value;
  if (className) {
    cell.classList.add(className);
  }
  row.appendChild(cell);
}

function addAlertDetail(card, label, value) {
  const detail = document.createElement("p");
  const labelElement = document.createElement("strong");
  labelElement.textContent = `${label}: `;
  detail.append(labelElement, document.createTextNode(value));
  card.appendChild(detail);
}

function displayReport(report) {
  document.querySelector("#result-file").textContent = report.file;
  document.querySelector("#lines-scanned").textContent = report.summary.lines_scanned;
  document.querySelector("#total-findings").textContent = report.summary.total_findings;
  document.querySelector("#allowlisted-findings").textContent =
    report.summary.allowlisted_findings;
  document.querySelector("#failed-login-threshold-used").textContent =
    report.summary.failed_login_threshold;
  document.querySelector("#failed-login-window-used").textContent =
    report.summary.failed_login_window_minutes;
  document.querySelector("#evidence-size").textContent =
    `${report.metadata.size_bytes.toLocaleString()} bytes`;
  document.querySelector("#evidence-sha256").textContent = report.metadata.sha256;
  document.querySelector("#evidence-scanned-at").textContent =
    report.metadata.scanned_at_utc;

  const alerts = report.alerts || [];
  document.querySelector("#total-alerts").textContent =
    report.summary.total_alerts ?? alerts.length;
  alertsList.replaceChildren();

  for (const alert of alerts) {
    const card = document.createElement("article");
    card.classList.add("security-alert", `severity-${alert.severity}`);

    const heading = document.createElement("h4");
    heading.textContent = `[${alert.severity.toUpperCase()}] ${alert.rule_id}: ${alert.title}`;
    card.appendChild(heading);
    addAlertDetail(card, "Source IP", alert.source_ip);
    addAlertDetail(card, "Occurrences", alert.occurrences.toString());
    addAlertDetail(card, "Evidence lines", alert.evidence_lines.join(", "));
    if (alert.window_minutes !== null) {
      addAlertDetail(card, "Detection window", `${alert.window_minutes} minutes`);
    }
    alertsList.appendChild(card);
  }

  securityAlerts.hidden = alerts.length === 0;

  const typeList = document.querySelector("#findings-by-type");
  typeList.replaceChildren();

  for (const [type, count] of Object.entries(report.summary.findings_by_type)) {
    const item = document.createElement("li");
    item.textContent = `${type}: ${count}`;
    typeList.appendChild(item);
  }

  allowlistedByType.replaceChildren();
  for (const [type, count] of Object.entries(report.summary.allowlisted_by_type)) {
    const item = document.createElement("li");
    item.textContent = `${type}: ${count}`;
    allowlistedByType.appendChild(item);
  }
  allowlistedSummary.hidden = report.summary.allowlisted_findings === 0;

  const findingsBody = document.querySelector("#findings-body");
  findingsBody.replaceChildren();

  for (const finding of report.findings) {
    const row = document.createElement("tr");
    addTableCell(row, finding.type);
    addTableCell(row, finding.value);
    addTableCell(
      row,
      finding.network_scope || "—",
      finding.network_scope ? "network-scope" : "not-applicable",
    );
    addTableCell(row, finding.line_number);
    addTableCell(row, finding.context);
    findingsBody.appendChild(row);
  }

  const hasFindings = report.findings.length > 0;
  findingsTableWrapper.hidden = !hasFindings;
  noFindings.hidden = hasFindings;
  scanResults.hidden = false;
}

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  scanButton.disabled = true;
  scanStatus.textContent = "Scanning file...";
  scanError.hidden = true;
  scanResults.hidden = true;

  try {
    const response = await fetch(scanForm.action, {
      method: "POST",
      body: new FormData(scanForm),
    });
    const report = await response.json();

    if (!response.ok) {
      throw new Error(report.error || "The file could not be scanned.");
    }

    displayReport(report);
    scanStatus.textContent = "Scan complete.";
  } catch (error) {
    scanStatus.textContent = "";
    scanError.textContent = error.message;
    scanError.hidden = false;
  } finally {
    scanButton.disabled = false;
  }
});
