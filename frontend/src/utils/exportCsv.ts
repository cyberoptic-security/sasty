import type { Finding, Scan } from "../types";

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

const HEADERS = [
  "severity",
  "tool",
  "rule_id",
  "rule_name",
  "category",
  "message",
  "file_path",
  "line_start",
  "line_end",
  "col_start",
  "col_end",
  "matched_code",
  "cwe",
  "owasp",
  "references",
  "fingerprint",
  "commit_hash",
  "triage_state",
];

export function exportFindingsToCsv(scan: Scan, findings: Finding[]) {
  const lines: string[] = [HEADERS.join(",")];

  for (const f of findings) {
    lines.push(
      row([
        f.severity,
        f.tool,
        f.rule_id,
        f.rule_name ?? "",
        f.category ?? "",
        f.message,
        f.file_path,
        f.line_start ?? "",
        f.line_end ?? "",
        f.col_start ?? "",
        f.col_end ?? "",
        f.matched_code ?? "",
        f.cwe?.join("; ") ?? "",
        f.owasp?.join("; ") ?? "",
        f.references?.join("; ") ?? "",
        f.fingerprint ?? "",
        f.commit_hash ?? "",
        f.triage_state ?? "",
      ])
    );
  }

  const csv = lines.join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
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
