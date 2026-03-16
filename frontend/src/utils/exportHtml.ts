import type { Finding, Scan, Severity } from "../types";
import type { ExportField, SortOrder } from "../components/ExportModal";

type HtmlLayout = "text" | "table";

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
  commit_author: "Commit Author",
  commit_date: "Commit Date",
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

function renderCodeBlock(f: Finding): string {
  if (f.code_context && f.code_context.lines.length > 0) {
    const { lines, start_line, highlight_start, highlight_end } = f.code_context;
    let code = "";
    for (let i = 0; i < lines.length; i++) {
      const lineNum = start_line + i;
      const isHighlighted = lineNum >= highlight_start && lineNum <= highlight_end;
      const lineNumStr = String(lineNum).padStart(4, " ");
      const bg = isHighlighted ? "background:#fef9c3;font-weight:bold;" : "";
      code += `<div style="white-space:pre;${bg}"><span style="color:#9ca3af;user-select:none;">${lineNumStr} | </span>${esc(lines[i])}</div>`;
    }
    return `<div style="font-family:Consolas,'Courier New',monospace;font-size:9pt;background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;padding:8px;margin:6px 0 10px 0;overflow-x:auto;line-height:1.5;">${code}</div>`;
  }

  if (f.matched_code) {
    return `<div style="font-family:Consolas,'Courier New',monospace;font-size:9pt;background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;padding:8px;margin:6px 0 10px 0;overflow-x:auto;line-height:1.5;white-space:pre;">${esc(f.matched_code)}</div>`;
  }

  return "";
}

/** Fields that vary per instance (shown for each occurrence). */
const INSTANCE_FIELDS: Set<ExportField> = new Set([
  "file_path", "line_start", "line_end", "col_start", "col_end",
  "matched_code", "fingerprint", "commit_hash", "commit_author",
  "commit_date", "triage_state",
]);

interface ExportGroup {
  rule_id: string;
  rule_name?: string;
  severity: Severity;
  tool: string;
  category?: string;
  message: string;
  cwe?: string[];
  owasp?: string[];
  references?: string[];
  findings: Finding[];
}

function groupFindings(findings: Finding[]): ExportGroup[] {
  const map = new Map<string, ExportGroup>();
  for (const f of findings) {
    const key = `${f.rule_id}__${f.tool}`;
    if (!map.has(key)) {
      map.set(key, {
        rule_id: f.rule_id,
        rule_name: f.rule_name,
        severity: f.severity,
        tool: f.tool,
        category: f.category,
        message: f.message,
        cwe: f.cwe,
        owasp: f.owasp,
        references: f.references,
        findings: [],
      });
    }
    map.get(key)!.findings.push(f);
  }
  return [...map.values()];
}

const TRIAGE_LABELS: Record<string, string> = {
  false_positive: "False Positive",
  test_dev: "Test / Dev",
  reported: "Reported",
};

function buildTextGroup(group: ExportGroup, fields: ExportField[], index: number): string {
  const hasField = (field: ExportField) => fields.includes(field);
  const count = group.findings.length;
  let html = "";

  // ── Group header ──
  html += `<div style="margin-bottom:20px;border:1px solid #e5e7eb;border-left:4px solid ${SEVERITY_COLORS[group.severity]};border-radius:4px;background:#ffffff;">`;
  html += `<div style="padding:12px 16px;background:${SEVERITY_BG[group.severity]};border-bottom:1px solid #e5e7eb;">`;

  html += `<div style="margin-bottom:4px;">`;
  if (hasField("severity")) html += renderSeverityBadge(group.severity) + " ";
  if (hasField("tool")) html += `<span style="display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:600;color:#4b5563;background:#f3f4f6;border:1px solid #d1d5db;margin-left:4px;">${esc(group.tool)}</span> `;
  html += `<strong style="font-size:11pt;color:#111827;margin-left:4px;">${esc(group.rule_name || group.rule_id)}</strong>`;
  html += `<span style="font-size:9pt;color:#9ca3af;margin-left:8px;">${count} instance${count !== 1 ? "s" : ""}</span>`;
  html += `</div>`;

  if (hasField("rule_id") && group.rule_name) {
    html += `<div style="font-family:Consolas,'Courier New',monospace;font-size:9pt;color:#2563eb;font-weight:600;margin:2px 0;">${esc(group.rule_id)}</div>`;
  }

  if (hasField("message") && group.message) {
    html += `<div style="margin:6px 0;font-size:10pt;color:#1f2937;line-height:1.4;">${esc(group.message)}</div>`;
  }

  // Group-level metadata
  const groupMeta: string[] = [];
  if (hasField("category") && group.category) groupMeta.push(`<strong>Category:</strong> ${esc(group.category)}`);
  if (hasField("cwe") && group.cwe?.length) groupMeta.push(`<strong>CWE:</strong> ${esc(group.cwe.join(", "))}`);
  if (hasField("owasp") && group.owasp?.length) groupMeta.push(`<strong>OWASP:</strong> ${esc(group.owasp.join(", "))}`);
  if (hasField("references") && group.references?.length) {
    groupMeta.push(`<strong>References:</strong> ${group.references.map((r) => `<a href="${esc(r)}" style="color:#2563eb;font-size:9pt;">${esc(r)}</a>`).join(", ")}`);
  }
  if (groupMeta.length > 0) {
    html += `<div style="font-size:9pt;color:#6b7280;margin-top:6px;line-height:1.6;">${groupMeta.join("<br>")}</div>`;
  }

  html += `</div>\n`; // close header

  // ── Instances ──
  for (let i = 0; i < group.findings.length; i++) {
    const f = group.findings[i];
    html += `<div style="padding:10px 16px 10px 24px;${i < group.findings.length - 1 ? "border-bottom:1px solid #f3f4f6;" : ""}">`;

    // Instance sub-header
    html += `<div style="margin-bottom:4px;">`;
    html += `<span style="font-size:9pt;font-weight:600;color:#9ca3af;">Instance ${i + 1}</span>`;
    if (hasField("triage_state") && f.triage_state) {
      html += `<span style="font-size:9pt;color:#b45309;margin-left:8px;font-style:italic;"> &mdash; ${esc(TRIAGE_LABELS[f.triage_state] ?? f.triage_state)}</span>`;
    }
    html += `</div>`;

    // Location
    if (hasField("file_path")) {
      let loc = `<strong>${esc(f.file_path)}</strong>`;
      if (hasField("line_start") && f.line_start) {
        loc += `:${f.line_start}`;
        if (hasField("line_end") && f.line_end && f.line_end !== f.line_start) {
          loc += `-${f.line_end}`;
        }
      }
      html += `<div style="font-family:Consolas,'Courier New',monospace;font-size:9pt;color:#4b5563;margin:4px 0;">${loc}</div>`;
    }

    // Code
    if (hasField("matched_code")) {
      html += renderCodeBlock(f);
    }

    // Instance-level metadata
    const instanceMeta: string[] = [];
    const skipInInstance = new Set<ExportField>(["file_path", "line_start", "line_end", "col_start", "col_end", "matched_code", "triage_state"]);
    for (const field of fields) {
      if (!INSTANCE_FIELDS.has(field) || skipInInstance.has(field)) continue;
      const val = getFieldValue(f, field);
      if (!val) continue;
      instanceMeta.push(`<strong>${FIELD_LABELS[field]}:</strong> ${esc(val)}`);
    }
    if (instanceMeta.length > 0) {
      html += `<div style="font-size:9pt;color:#6b7280;margin-top:4px;line-height:1.5;">${instanceMeta.join(" &nbsp;|&nbsp; ")}</div>`;
    }

    html += `</div>\n`;
  }

  html += `</div>\n`; // close group wrapper
  return html;
}

function buildTextLayout(findings: Finding[], fields: ExportField[]): string {
  const groups = groupFindings(findings);
  let html = "";
  for (let i = 0; i < groups.length; i++) {
    html += buildTextGroup(groups[i], fields, i + 1);
  }
  return html;
}

function buildTableLayout(findings: Finding[], fields: ExportField[]): string {
  let html = "<table>\n<tr>";
  html += fields.map((f) => `<th>${esc(FIELD_LABELS[f])}</th>`).join("");
  html += "</tr>\n";

  for (const f of findings) {
    html += "<tr>";
    for (const field of fields) {
      if (field === "severity") {
        html += `<td>${renderSeverityBadge(f.severity)}</td>`;
      } else if (field === "matched_code") {
        if (f.code_context && f.code_context.lines.length > 0) {
          const { lines, start_line, highlight_start, highlight_end } = f.code_context;
          let code = "";
          for (let i = 0; i < lines.length; i++) {
            const lineNum = start_line + i;
            const isHL = lineNum >= highlight_start && lineNum <= highlight_end;
            const prefix = `${String(lineNum).padStart(4, " ")} | `;
            const bg = isHL ? " style=\"background:#fef9c3;font-weight:bold;\"" : "";
            code += `<div${bg}>${esc(prefix + lines[i])}</div>`;
          }
          html += `<td><pre style="font-family:Consolas,'Courier New',monospace;font-size:8pt;margin:0;white-space:pre;line-height:1.4;">${code}</pre></td>`;
        } else {
          const val = f.matched_code ?? "";
          html += `<td>${val ? `<code style="font-size:8pt;">${esc(val)}</code>` : ""}</td>`;
        }
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

function buildBody(
  findings: Finding[],
  fields: ExportField[],
  layout: HtmlLayout,
  sortOrder: SortOrder
): string {
  const builder = layout === "text" ? buildTextLayout : buildTableLayout;
  const groupByTool = sortOrder === "tool" || sortOrder === "both";

  if (groupByTool) {
    const toolMap = new Map<string, Finding[]>();
    for (const f of findings) {
      if (!toolMap.has(f.tool)) toolMap.set(f.tool, []);
      toolMap.get(f.tool)!.push(f);
    }

    let html = "";
    for (const [tool, toolFindings] of toolMap) {
      html += `<h2 style="margin-top:24px;margin-bottom:8px;font-size:16px;color:#374151;border-bottom:2px solid #e5e7eb;padding-bottom:4px;">${esc(tool)} (${toolFindings.length} finding${toolFindings.length !== 1 ? "s" : ""})</h2>\n`;
      html += builder(toolFindings, fields);
    }
    return html;
  }

  return builder(findings, fields);
}

export function exportFindingsToHtml(
  scan: Scan,
  findings: Finding[],
  fields: ExportField[],
  sortOrder: SortOrder,
  layout: HtmlLayout = "text"
) {
  const sorted = sortFindings(findings, sortOrder);
  const scanName = scan.label ?? scan.path.split(/[/\\]/).pop() ?? `scan-${scan.id}`;
  const date = new Date(scan.started_at).toLocaleDateString();

  const body = buildBody(sorted, fields, layout, sortOrder);

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
