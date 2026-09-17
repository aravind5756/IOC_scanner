const scanForm = document.querySelector("form");
const scanButton = document.querySelector("#scan-button");
const scanStatus = document.querySelector("#scan-status");
const scanError = document.querySelector("#scan-error");
const scanResults = document.querySelector("#scan-results");
const findingsTableWrapper = document.querySelector("#findings-table-wrapper");
const noFindings = document.querySelector("#no-findings");

function addTableCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value;
  if (className) {
    cell.classList.add(className);
  }
  row.appendChild(cell);
}

function displayReport(report) {
  document.querySelector("#result-file").textContent = report.file;
  document.querySelector("#lines-scanned").textContent = report.summary.lines_scanned;
  document.querySelector("#total-findings").textContent = report.summary.total_findings;

  const typeList = document.querySelector("#findings-by-type");
  typeList.replaceChildren();

  for (const [type, count] of Object.entries(report.summary.findings_by_type)) {
    const item = document.createElement("li");
    item.textContent = `${type}: ${count}`;
    typeList.appendChild(item);
  }

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
