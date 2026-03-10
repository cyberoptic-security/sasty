import type { Finding, Scan, Severity } from "../types";
import type { ExportField, SortOrder } from "../components/ExportModal";

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#2563eb",
  INFO: "#6b7280",
};

const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "#fef2f2",
  HIGH: "#fff7ed",
  MEDIUM: "#fefce8",
  LOW: "#eff6ff",
  INFO: "#f9fafb",
};

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function esc(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function sortFindings(findings: Finding[], sortOrder: SortOrder): Finding[] {
  const sorted = [...findings];
  switch (sortOrder) {
    case "severity":
      return sorted.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    case "tool":
      return sorted.sort((a, b) => a.tool.localeCompare(b.tool));
    case "both":
      return sorted.sort((a, b) => {
        const toolCmp = a.tool.localeCompare(b.tool);
        if (toolCmp !== 0) return toolCmp;
        return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      });
  }
}

const FIELD_LABELS: Record<ExportField, string> = {
  severity: "Severity",
  tool: "Tool",
  rule_id: "Rule ID",
  rule_name: "Rule Name",
  category: "Category",
  message: "Message",
  file_path: "File Path",
  line_start: "Line Start",
  line_end: "Line End",
  col_start: "Col Start",
  col_end: "Col End",
  matched_code: "Matched Code",
  cwe: "CWE",
  owasp: "OWASP",
  references: "References",
  fingerprint: "Fingerprint",
  commit_hash: "Commit Hash",
  triage_state: "Triage State",
};

function getFieldValue(f: Finding, field: ExportField): string {
  switch (field) {
    case "cwe": return f.cwe?.join(", ") ?? "";
    case "owasp": return f.owasp?.join(", ") ?? "";
    case "references": return f.references?.join(", ") ?? "";
    case "triage_state": return f.triage_state ?? "Open";
    default: {
      const val = f[field as keyof Finding];
      return val === null || val === undefined ? "" : String(val);
    }
  }
}

function renderSeverityBadge(severity: Severity): string {
  return `<span style="display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold;color:${SEVERITY_COLORS[severity]};background:${SEVERITY_BG[severity]};border:1px solid ${SEVERITY_COLORS[severity]};">${severity}</span>`;
}

export function exportFindingsToHtml(
  scan: Scan,
  findings: Finding[],
  fields: ExportField[],
  sortOrder: SortOrder
) {
  const sorted = sortFindings(findings, sortOrder);
  const scanName = scan.label ?? scan.path.split(/[/\\]/).pop() ?? `scan-${scan.id}`;
  const date = new Date(scan.started_at).toLocaleDateString();

  const groupByTool = sortOrder === "tool" || sortOrder === "both";

  let body = "";

  if (groupByTool) {
    const toolMap = new Map<string, Finding[]>();
    for (const f of sorted) {
      if (!toolMap.has(f.tool)) toolMap.set(f.tool, []);
      toolMap.get(f.tool)!.push(f);
    }

    for (const [tool, toolFindings] of toolMap) {
      body += `<h2 style="margin-top:24px;margin-bottom:8px;font-size:16px;color:#374151;border-bottom:2px solid #e5e7eb;padding-bottom:4px;">${esc(tool)} (${toolFindings.length} finding${toolFindings.length !== 1 ? "s" : ""})</h2>\n`;
      body += buildTable(toolFindings, fields);
    }
  } else {
    body = buildTable(sorted, fields);
  }

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SAST Findings — ${esc(scanName)}</title>
<style>
  body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; color: #1f2937; margin: 24px; }
  h1 { font-size: 18pt; margin-bottom: 4px; }
  .meta { color: #6b7280; font-size: 10pt; margin-bottom: 16px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
  th { background: #f3f4f6; text-align: left; padding: 6px 10px; border: 1px solid #d1d5db; font-size: 10pt; font-weight: 600; }
  td { padding: 6px 10px; border: 1px solid #d1d5db; font-size: 10pt; vertical-align: top; }
  tr:nth-child(even) td { background: #f9fafb; }
  code { font-family: Consolas, "Courier New", monospace; font-size: 9pt; background: #f3f4f6; padding: 1px 4px; border-radius: 2px; }
  .summary-table td, .summary-table th { padding: 4px 12px; }
</style>
</head>
<body>
<h1>SAST Findings Report</h1>
<p class="meta"><strong>Scan:</strong> ${esc(scanName)} &nbsp;|&nbsp; <strong>Date:</strong> ${esc(date)} &nbsp;|&nbsp; <strong>Findings:</strong> ${findings.length}</p>

<table class="summary-table" style="width:auto;margin-bottom:20px;">
<tr><th>Severity</th><th>Count</th></tr>
${(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[])
  .map((sev) => {
    const count = findings.filter((f) => f.severity === sev).length;
    return count > 0
      ? `<tr><td>${renderSeverityBadge(sev)}</td><td style="font-weight:600;">${count}</td></tr>`
      : "";
  })
  .join("\n")}
</table>

${body}
</body>
</html>`;

  const blob = new Blob([html], { type: "text/html;charset=utf-8;" });
  const url = URL.createObjectURL(blob);

  const safeName = (scan.label ?? scan.path.split(/[/\\]/).pop() ?? `scan-${scan.id}`)
    .replace(/[^a-z0-9_-]/gi, "_")
    .toLowerCase();
  const fileDate = new Date(scan.started_at).toISOString().slice(0, 10);
  const filename = `sasty_${safeName}_${fileDate}.html`;

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function buildTable(findings: Finding[], fields: ExportField[]): string {
  let html = "<table>\n<tr>";
  html += fields.map((f) => `<th>${esc(FIELD_LABELS[f])}</th>`).join("");
  html += "</tr>\n";

  for (const f of findings) {
    html += "<tr>";
    for (const field of fields) {
      if (field === "severity") {
        html += `<td>${renderSeverityBadge(f.severity)}</td>`;
      } else if (field === "matched_code") {
        const val = getFieldValue(f, field);
        html += `<td>${val ? `<code>${esc(val)}</code>` : ""}</td>`;
      } else if (field === "references") {
        const refs = f.references ?? [];
        html += `<td>${refs.map((r) => `<a href="${esc(r)}" style="color:#2563eb;font-size:9pt;">${esc(r)}</a>`).join("<br>")}</td>`;
      } else {
        html += `<td>${esc(getFieldValue(f, field))}</td>`;
      }
    }
    html += "</tr>\n";
  }

  html += "</table>\n";
  return html;
}
