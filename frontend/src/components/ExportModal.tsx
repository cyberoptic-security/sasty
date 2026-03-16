import clsx from "clsx";
import { Check, ChevronDown, Download, X } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import type { Finding, Scan, Severity, TriageState } from "../types";
import { exportFindingsToCsv } from "../utils/exportCsv";
import { exportFindingsToDocx } from "../utils/exportDocx";
import { exportFindingsToHtml } from "../utils/exportHtml";
import { redactFindings } from "../utils/redact";

export type ExportFormat = "docx-text" | "docx-table" | "html-text" | "html-table" | "csv";
export type SortOrder = "severity" | "tool" | "both";

export const ALL_EXPORT_FIELDS = [
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
  "commit_author",
  "commit_date",
  "triage_state",
] as const;

export type ExportField = (typeof ALL_EXPORT_FIELDS)[number];

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

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

interface Props {
  scan: Scan;
  findings: Finding[];
  onClose: () => void;
}

type TriageFilterKey = TriageState | "open";

const ALL_TRIAGE_FILTERS: { key: TriageFilterKey; label: string }[] = [
  { key: "open", label: "Open" },
  { key: "false_positive", label: "False Positive" },
  { key: "test_dev", label: "Test / Dev" },
  { key: "reported", label: "Reported" },
];

export default function ExportModal({ scan, findings, onClose }: Props) {
  const [format, setFormat] = useState<ExportFormat>("docx-text");
  const [sortOrder, setSortOrder] = useState<SortOrder>("severity");
  const [selectedFields, setSelectedFields] = useState<Set<ExportField>>(
    new Set(ALL_EXPORT_FIELDS)
  );
  const [triageFilters, setTriageFilters] = useState<Set<TriageFilterKey>>(
    new Set(ALL_TRIAGE_FILTERS.map((t) => t.key))
  );
  const [redactSecrets, setRedactSecrets] = useState(false);

  // Filter findings by triage status
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (f.triage_state === null) return triageFilters.has("open");
      return triageFilters.has(f.triage_state as TriageFilterKey);
    });
  }, [findings, triageFilters]);

  // Group filtered findings by tool
  const toolGroups = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of filteredFindings) {
      if (!map.has(f.tool)) map.set(f.tool, []);
      map.get(f.tool)!.push(f);
    }
    const result = [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
    for (const [, group] of result) {
      group.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    }
    return result;
  }, [filteredFindings]);

  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<number>>(
    () => new Set(findings.map((f) => f.id))
  );

  // When triage filters change, remove deselected findings from the selection
  const effectiveSelectedIds = useMemo(() => {
    const filteredIds = new Set(filteredFindings.map((f) => f.id));
    return new Set([...selectedFindingIds].filter((id) => filteredIds.has(id)));
  }, [selectedFindingIds, filteredFindings]);

  const [expandedTools, setExpandedTools] = useState<Set<string>>(new Set());

  const selectedCount = effectiveSelectedIds.size;
  const totalCount = filteredFindings.length;

  const toggleTool = useCallback(
    (tool: string) => {
      setExpandedTools((prev) => {
        const next = new Set(prev);
        if (next.has(tool)) next.delete(tool);
        else next.add(tool);
        return next;
      });
    },
    []
  );

  const toggleToolFindings = useCallback(
    (toolFindings: Finding[]) => {
      setSelectedFindingIds((prev) => {
        const next = new Set(prev);
        const ids = toolFindings.map((f) => f.id);
        const allSelected = ids.every((id) => next.has(id));
        if (allSelected) {
          ids.forEach((id) => next.delete(id));
        } else {
          ids.forEach((id) => next.add(id));
        }
        return next;
      });
    },
    []
  );

  const toggleFinding = useCallback((id: number) => {
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelectedFindingIds(new Set(filteredFindings.map((f) => f.id)));
  }, [filteredFindings]);

  const selectNone = useCallback(() => {
    setSelectedFindingIds(new Set());
  }, []);

  const toggleTriageFilter = useCallback((key: TriageFilterKey) => {
    setTriageFilters((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const toggleField = useCallback((field: ExportField) => {
    setSelectedFields((prev) => {
      const next = new Set(prev);
      if (next.has(field)) next.delete(field);
      else next.add(field);
      return next;
    });
  }, []);

  const [exportedJust, setExportedJust] = useState(false);

  const handleExport = useCallback(() => {
    const raw = filteredFindings.filter((f) => effectiveSelectedIds.has(f.id));
    const fields = ALL_EXPORT_FIELDS.filter((f) => selectedFields.has(f));

    if (raw.length === 0) return;

    const selected = redactSecrets ? redactFindings(raw) : raw;

    if (format === "docx-text" || format === "docx-table") {
      exportFindingsToDocx(scan, selected, fields, sortOrder, format === "docx-text" ? "text" : "table");
    } else if (format === "html-text" || format === "html-table") {
      exportFindingsToHtml(scan, selected, fields, sortOrder, format === "html-text" ? "text" : "table");
    } else {
      exportFindingsToCsv(scan, selected, fields, sortOrder);
    }

    // Show brief confirmation, then reset
    setExportedJust(true);
    setTimeout(() => setExportedJust(false), 2500);
  }, [filteredFindings, effectiveSelectedIds, selectedFields, format, sortOrder, scan, redactSecrets]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded-lg shadow-xl w-full max-w-2xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-200 dark:border-zinc-800">
          <h2 className="text-base font-semibold text-zinc-800 dark:text-zinc-100">
            Export Findings
          </h2>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Format + Sort row */}
          <div className="flex gap-6">
            <div className="flex-1">
              <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider mb-2 block">
                Format
              </label>
              <div className="flex gap-2 flex-wrap">
                {(
                  [
                    ["docx-text", "Word Text"],
                    ["docx-table", "Word Table"],
                    ["html-text", "HTML Text"],
                    ["html-table", "HTML Table"],
                    ["csv", "CSV"],
                  ] as [ExportFormat, string][]
                ).map(([val, label]) => (
                  <button
                    key={val}
                    onClick={() => setFormat(val)}
                    className={clsx(
                      "px-3 py-1.5 text-sm rounded border transition-all",
                      format === val
                        ? "border-blue-400 bg-blue-50 text-blue-700 dark:border-blue-600 dark:bg-blue-950 dark:text-blue-300"
                        : "border-zinc-200 text-zinc-500 dark:border-zinc-700 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-600"
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex-1">
              <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider mb-2 block">
                Sort Order
              </label>
              <div className="flex gap-2">
                {(
                  [
                    ["severity", "By Severity"],
                    ["tool", "By Tool"],
                    ["both", "Tool + Severity"],
                  ] as [SortOrder, string][]
                ).map(([val, label]) => (
                  <button
                    key={val}
                    onClick={() => setSortOrder(val)}
                    className={clsx(
                      "px-3 py-1.5 text-sm rounded border transition-all",
                      sortOrder === val
                        ? "border-blue-400 bg-blue-50 text-blue-700 dark:border-blue-600 dark:bg-blue-950 dark:text-blue-300"
                        : "border-zinc-200 text-zinc-500 dark:border-zinc-700 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-600"
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Redact Secrets */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setRedactSecrets((v) => !v)}
              className={clsx(
                "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors",
                redactSecrets
                  ? "bg-blue-600 border-blue-600"
                  : "bg-zinc-200 border-zinc-300 dark:bg-zinc-700 dark:border-zinc-600"
              )}
            >
              <span
                className={clsx(
                  "inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform",
                  redactSecrets ? "translate-x-[18px]" : "translate-x-[3px]"
                )}
              />
            </button>
            <div>
              <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
                Redact secrets
              </span>
              <p className="text-xs text-zinc-400 dark:text-zinc-500">
                Mask detected secrets in code and matched values, keeping first &amp; last characters
              </p>
            </div>
          </div>

          {/* Triage Status Filter */}
          <div>
            <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider mb-2 block">
              Triage Status
            </label>
            <div className="flex gap-2 flex-wrap">
              {ALL_TRIAGE_FILTERS.map(({ key, label }) => {
                const count = findings.filter((f) =>
                  key === "open" ? f.triage_state === null : f.triage_state === key
                ).length;
                return (
                  <button
                    key={key}
                    onClick={() => toggleTriageFilter(key)}
                    className={clsx(
                      "px-3 py-1.5 text-sm rounded border transition-all",
                      triageFilters.has(key)
                        ? "border-blue-400 bg-blue-50 text-blue-700 dark:border-blue-600 dark:bg-blue-950 dark:text-blue-300"
                        : "border-zinc-200 text-zinc-400 dark:border-zinc-700 dark:text-zinc-500"
                    )}
                  >
                    {label} <span className="text-xs opacity-60">({count})</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Finding Selection */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                Findings ({selectedCount} of {totalCount} selected)
              </label>
              <div className="flex gap-2">
                <button
                  onClick={selectAll}
                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                >
                  Select all
                </button>
                <button
                  onClick={selectNone}
                  className="text-xs text-zinc-400 dark:text-zinc-500 hover:underline"
                >
                  Select none
                </button>
              </div>
            </div>

            <div className="border border-zinc-200 dark:border-zinc-700 rounded-lg overflow-hidden max-h-60 overflow-y-auto">
              {toolGroups.map(([tool, toolFindings]) => {
                const toolSelectedCount = toolFindings.filter((f) =>
                  effectiveSelectedIds.has(f.id)
                ).length;
                const allToolSelected = toolSelectedCount === toolFindings.length;
                const someToolSelected = toolSelectedCount > 0 && !allToolSelected;
                const expanded = expandedTools.has(tool);

                return (
                  <div key={tool}>
                    <div className="flex items-center gap-2 px-3 py-2 bg-zinc-50 dark:bg-zinc-800/50 border-b border-zinc-200 dark:border-zinc-700">
                      <button
                        onClick={() => toggleToolFindings(toolFindings)}
                        className={clsx(
                          "w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors",
                          allToolSelected
                            ? "bg-blue-500 border-blue-500 text-white"
                            : someToolSelected
                              ? "bg-blue-200 border-blue-400 dark:bg-blue-800 dark:border-blue-600"
                              : "border-zinc-300 dark:border-zinc-600"
                        )}
                      >
                        {(allToolSelected || someToolSelected) && <Check size={10} />}
                      </button>
                      <button
                        onClick={() => toggleTool(tool)}
                        className="flex items-center gap-1.5 flex-1 text-left"
                      >
                        <ChevronDown
                          size={13}
                          className={clsx(
                            "text-zinc-400 transition-transform",
                            !expanded && "-rotate-90"
                          )}
                        />
                        <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
                          {tool}
                        </span>
                        <span className="text-xs text-zinc-400 dark:text-zinc-500">
                          ({toolSelectedCount}/{toolFindings.length})
                        </span>
                      </button>
                    </div>

                    {expanded && (
                      <div>
                        {toolFindings.map((f) => (
                          <label
                            key={f.id}
                            className="flex items-center gap-2 px-3 py-1.5 pl-10 hover:bg-zinc-50 dark:hover:bg-zinc-800/30 cursor-pointer border-b border-zinc-100 dark:border-zinc-800 last:border-b-0"
                          >
                            <input
                              type="checkbox"
                              checked={effectiveSelectedIds.has(f.id)}
                              onChange={() => toggleFinding(f.id)}
                              className="rounded border-zinc-300 text-blue-500 focus:ring-blue-500 dark:border-zinc-600"
                            />
                            <span
                              className="text-xs font-bold shrink-0"
                              style={{
                                color:
                                  f.severity === "CRITICAL"
                                    ? "#dc2626"
                                    : f.severity === "HIGH"
                                      ? "#ea580c"
                                      : f.severity === "MEDIUM"
                                        ? "#ca8a04"
                                        : f.severity === "LOW"
                                          ? "#2563eb"
                                          : "#6b7280",
                              }}
                            >
                              {f.severity}
                            </span>
                            <span className="text-xs text-zinc-600 dark:text-zinc-400 truncate">
                              {f.rule_id}
                            </span>
                            <span className="text-xs text-zinc-400 dark:text-zinc-500 truncate ml-auto">
                              {f.file_path}
                              {f.line_start ? `:${f.line_start}` : ""}
                            </span>
                          </label>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Field Selection */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                Fields ({selectedFields.size} of {ALL_EXPORT_FIELDS.length})
              </label>
              <div className="flex gap-2">
                <button
                  onClick={() => setSelectedFields(new Set(ALL_EXPORT_FIELDS))}
                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                >
                  All
                </button>
                <button
                  onClick={() => setSelectedFields(new Set())}
                  className="text-xs text-zinc-400 dark:text-zinc-500 hover:underline"
                >
                  None
                </button>
              </div>
            </div>

            <div className="flex flex-wrap gap-1.5">
              {ALL_EXPORT_FIELDS.map((field) => (
                <button
                  key={field}
                  onClick={() => toggleField(field)}
                  className={clsx(
                    "text-xs px-2.5 py-1 rounded border transition-all",
                    selectedFields.has(field)
                      ? "border-blue-300 bg-blue-50 text-blue-700 dark:border-blue-600 dark:bg-blue-950 dark:text-blue-300"
                      : "border-zinc-200 text-zinc-400 dark:border-zinc-700 dark:text-zinc-500"
                  )}
                >
                  {FIELD_LABELS[field]}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 rounded-b-lg">
          <span className="text-xs text-zinc-400 dark:text-zinc-500">
            {selectedCount} finding{selectedCount !== 1 ? "s" : ""} &middot;{" "}
            {selectedFields.size} field{selectedFields.size !== 1 ? "s" : ""} &middot;{" "}
            {format === "csv" ? "CSV" : format.replace("-", " ").replace(/\b\w/g, (c) => c.toUpperCase())}
          </span>
          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 text-sm text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleExport}
              disabled={selectedCount === 0 || selectedFields.size === 0}
              className={clsx(
                "flex items-center gap-1.5 px-4 py-1.5 text-sm rounded text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed",
                exportedJust
                  ? "bg-green-600 hover:bg-green-700"
                  : "bg-blue-600 hover:bg-blue-700"
              )}
            >
              {exportedJust ? <Check size={14} /> : <Download size={14} />}
              {exportedJust ? "Exported!" : "Export"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
