import type { ExportField, SortOrder } from "../components/ExportModal";
import type { Finding, Scan, Severity } from "../types";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function cell(value: string | number | boolean | null | undefined): string {
  const str = value === null || value === undefined ? "" : String(value);
  // Escape double-quotes and wrap in quotes if the value contains commas, quotes, or newlines
  if (str.includes('"') || str.includes(",") || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function row(fields: (string | number | boolean | null | undefined)[]): string {
  return fields.map(cell).join(",");
}

const FIELD_HEADERS: Record<ExportField, string> = {
  severity: "severity",
  tool: "tool",
  rule_id: "rule_id",
  rule_name: "rule_name",
  category: "category",
  message: "message",
  file_path: "file_path",
  line_start: "line_start",
  line_end: "line_end",
  col_start: "col_start",
  col_end: "col_end",
  matched_code: "matched_code",
  cwe: "cwe",
  owasp: "owasp",
  references: "references",
  fingerprint: "fingerprint",
  commit_hash: "commit_hash",
  triage_state: "triage_state",
};

function getFieldValue(f: Finding, field: ExportField): string | number | null | undefined {
  switch (field) {
    case "cwe": return f.cwe?.join("; ") ?? "";
    case "owasp": return f.owasp?.join("; ") ?? "";
    case "references": return f.references?.join("; ") ?? "";
    case "triage_state": return f.triage_state ?? "";
    default: {
      const val = f[field as keyof Finding];
      return val === null || val === undefined ? "" : val as string | number;
    }
  }
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

export function exportFindingsToCsv(
  scan: Scan,
  findings: Finding[],
  fields?: ExportField[],
  sortOrder?: SortOrder
) {
  const exportFields: ExportField[] = fields ?? (Object.keys(FIELD_HEADERS) as ExportField[]);
  const sorted = sortOrder ? sortFindings(findings, sortOrder) : findings;

  const lines: string[] = [row(exportFields.map((f) => FIELD_HEADERS[f]))];

  for (const f of sorted) {
    lines.push(row(exportFields.map((field) => getFieldValue(f, field))));
  }

  const csv = lines.join("\r\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);

  const scanName = (scan.label ?? scan.path.split(/[/\\]/).pop() ?? `scan-${scan.id}`)
    .replace(/[^a-z0-9_-]/gi, "_")
    .toLowerCase();
  const date = new Date(scan.started_at).toISOString().slice(0, 10);
  const filename = `sasty_${scanName}_${date}.csv`;

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
