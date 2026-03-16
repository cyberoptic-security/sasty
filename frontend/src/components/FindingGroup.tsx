import { useMutation, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import {
  ChevronDown,
  ChevronRight,
  FileCode,
  Tag,
} from "lucide-react";
import { useState } from "react";
import { updateFinding } from "../api/client";
import type { Finding, FindingGroup as FindingGroupType, TriageState } from "../types";
import CodeViewer from "./CodeViewer";
import SeverityBadge from "./SeverityBadge";

interface Props {
  group: FindingGroupType;
  scanId: number;
  showTriaged: boolean;
  selectedFindings?: Set<number>;
  onToggleFinding?: (id: number) => void;
  onToggleGroup?: (ids: number[]) => void;
}

const TRIAGE_LABELS: Record<TriageState, string> = {
  false_positive: "False Positive",
  test_dev: "Test / Dev",
  reported: "Reported",
};

const TOOL_COLORS: Record<string, string> = {
  semgrep: "bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800",
  gitleaks: "bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-950 dark:text-orange-300 dark:border-orange-800",
  betterleaks: "bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800",
  hadolint: "bg-purple-100 text-purple-700 border-purple-200 dark:bg-purple-950 dark:text-purple-300 dark:border-purple-800",
};

function ToolBadge({ tool }: { tool: string }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono border",
        TOOL_COLORS[tool] ?? "bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700"
      )}
    >
      {tool}
    </span>
  );
}

export default function FindingGroup({ group, scanId, showTriaged, selectedFindings, onToggleFinding, onToggleGroup }: Props) {
  const [open, setOpen] = useState(false);

  const visibleFindings = showTriaged
    ? group.findings
    : group.findings.filter((f) => !f.triage_state);

  if (visibleFindings.length === 0) return null;

  const allTriaged = visibleFindings.every((f) => f.triage_state);
  const groupIds = visibleFindings.map((f) => f.id);
  const allSelected = selectedFindings ? groupIds.length > 0 && groupIds.every((id) => selectedFindings.has(id)) : false;
  const someSelected = selectedFindings ? groupIds.some((id) => selectedFindings.has(id)) && !allSelected : false;

  return (
    <div
      className={clsx(
        "border rounded-lg overflow-hidden transition-colors",
        allTriaged
          ? "border-zinc-200 opacity-60 dark:border-zinc-800"
          : "border-zinc-200 dark:border-zinc-700"
      )}
    >
      <div
        className={clsx(
          "w-full flex items-center gap-3 px-4 py-3 text-left transition-colors",
          open
            ? "bg-zinc-100 dark:bg-zinc-800/30"
            : "bg-zinc-50 dark:bg-zinc-900 hover:bg-zinc-100 dark:hover:bg-zinc-800/50"
        )}
      >
        {onToggleGroup && (
          <input
            type="checkbox"
            checked={allSelected}
            ref={(el) => { if (el) el.indeterminate = someSelected; }}
            onChange={() => onToggleGroup(groupIds)}
            className="rounded border-zinc-300 dark:border-zinc-600 text-emerald-600 focus:ring-emerald-500 shrink-0 cursor-pointer"
          />
        )}
        <button className="flex items-center gap-2 flex-1 min-w-0 text-left" onClick={() => setOpen((v) => !v)}>
          {open ? (
            <ChevronDown size={14} className="text-zinc-400 dark:text-zinc-500 shrink-0" />
          ) : (
            <ChevronRight size={14} className="text-zinc-400 dark:text-zinc-500 shrink-0" />
          )}

          <div className="flex items-center gap-1.5 shrink-0 w-[9.5rem]">
            <SeverityBadge severity={group.severity} />
            <ToolBadge tool={group.tool} />
          </div>

          <span className="font-medium text-sm min-w-0 truncate ml-3">
            {group.rule_name ?? group.rule_id}
          </span>

          <span className="text-xs text-zinc-400 dark:text-zinc-500 shrink-0 ml-auto">
            {visibleFindings.length} {visibleFindings.length === 1 ? "instance" : "instances"}
            {group.falsePositiveCount > 0 && (
              <span className="ml-1 text-zinc-300 dark:text-zinc-600">
                ({group.falsePositiveCount} triaged)
              </span>
            )}
          </span>
        </button>
      </div>

      {open && (
        <div className="border-t border-zinc-200 dark:border-zinc-800 divide-y divide-zinc-100 dark:divide-zinc-800/80">
          {/* Rule-level metadata */}
          <div className="px-4 py-3 bg-zinc-50/50 dark:bg-zinc-900/50">
            <p className="text-sm text-zinc-700 dark:text-zinc-300 leading-relaxed">{group.message}</p>
            <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
              {group.category && (
                <span className="text-xs text-zinc-500 flex items-center gap-1">
                  <Tag size={10} /> {group.category}
                </span>
              )}
              {group.cwe && group.cwe.length > 0 && (
                <span className="text-xs text-zinc-500">
                  CWE: {group.cwe.join(", ")}
                </span>
              )}
              {group.owasp && group.owasp.length > 0 && (
                <span className="text-xs text-zinc-500">
                  OWASP: {group.owasp.join(", ")}
                </span>
              )}
              {group.references && group.references.length > 0 && (
                <span className="text-xs text-zinc-500 flex items-center gap-1">
                  Refs:
                  {group.references.map((r, i) => (
                    <a
                      key={i}
                      href={r}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-emerald-600 dark:text-emerald-500 hover:underline"
                    >
                      [{i + 1}]
                    </a>
                  ))}
                </span>
              )}
            </div>
          </div>

          {visibleFindings.map((finding) => (
            <FindingItem
              key={finding.id}
              finding={finding}
              scanId={scanId}
              selected={selectedFindings?.has(finding.id) ?? false}
              onToggle={onToggleFinding}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingItem({ finding, scanId, selected, onToggle }: { finding: Finding; scanId: number; selected: boolean; onToggle?: (id: number) => void }) {
  const [showCode, setShowCode] = useState(false);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (triage_state: string | null) =>
      updateFinding(finding.id, { triage_state }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
    },
  });

  const triaged = !!finding.triage_state;
  const hasContext = !!finding.code_context;
  const hasMatched = !!finding.matched_code;

  return (
    <div className={clsx("px-4 py-3 bg-white dark:bg-zinc-900/20", triaged && "opacity-50")}>
      {/* File + location row */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            {onToggle && (
              <input
                type="checkbox"
                checked={selected}
                onChange={() => onToggle(finding.id)}
                className="rounded border-zinc-300 dark:border-zinc-600 text-emerald-600 focus:ring-emerald-500 shrink-0 cursor-pointer"
              />
            )}
            <FileCode size={13} className="text-zinc-400 dark:text-zinc-500 shrink-0" />
            <span className="text-xs font-mono text-zinc-700 dark:text-zinc-300 break-all">
              {finding.file_path}
            </span>
            {finding.line_start && (
              <span className="text-xs text-zinc-400 dark:text-zinc-600 font-mono">
                :{finding.line_start}
                {finding.line_end && finding.line_end !== finding.line_start
                  ? `–${finding.line_end}`
                  : ""}
              </span>
            )}
            {finding.triage_state && (
              <span className="text-xs bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950/30 dark:text-amber-400 dark:border-amber-800 px-1.5 py-0.5 rounded">
                {TRIAGE_LABELS[finding.triage_state]}
              </span>
            )}
          </div>

          {/* Per-finding metadata */}
          <div className="flex flex-wrap gap-x-3 gap-y-1 pl-5">
            <ToolBadge tool={finding.tool} />
            {finding.category && (
              <span className="text-xs text-zinc-400 dark:text-zinc-500 flex items-center gap-1">
                <Tag size={10} />{finding.category}
              </span>
            )}
            {finding.cwe && finding.cwe.length > 0 && (
              <span className="text-xs text-zinc-400 dark:text-zinc-500">
                {finding.cwe.join(", ")}
              </span>
            )}
            {finding.owasp && finding.owasp.length > 0 && (
              <span className="text-xs text-zinc-400 dark:text-zinc-500">
                {finding.owasp.join(", ")}
              </span>
            )}
            {finding.commit_hash && (
              <span className="text-xs font-mono text-zinc-500 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-700 px-1.5 py-0.5 rounded" title={`Commit: ${finding.commit_hash}`}>
                {finding.commit_hash.slice(0, 8)}
              </span>
            )}
            {finding.commit_author && (
              <span className="text-xs text-zinc-500 dark:text-zinc-400">
                {finding.commit_author}
              </span>
            )}
            {finding.commit_date && (
              <span className="text-xs text-zinc-400 dark:text-zinc-500">
                {finding.commit_date.slice(0, 10)}
              </span>
            )}
            {finding.fingerprint && !finding.commit_hash && (
              <span className="text-xs text-zinc-300 dark:text-zinc-700 font-mono" title="Fingerprint">
                {finding.fingerprint.slice(0, 12)}…
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {(hasContext || hasMatched) && (
            <button
              onClick={() => setShowCode((v) => !v)}
              className="text-xs text-zinc-400 hover:text-zinc-700 dark:text-zinc-500 dark:hover:text-zinc-300 flex items-center gap-1 transition-colors"
            >
              {showCode ? "Hide" : "Code"}
            </button>
          )}
          <select
            value={finding.triage_state ?? ""}
            onChange={(e) => mutation.mutate(e.target.value || null)}
            disabled={mutation.isPending}
            className={clsx(
              "text-xs px-2 py-1 rounded border bg-white dark:bg-zinc-900 transition-colors cursor-pointer appearance-none",
              triaged
                ? "border-amber-300 text-amber-700 dark:border-amber-700 dark:text-amber-400"
                : "border-zinc-200 text-zinc-400 dark:border-zinc-700 dark:text-zinc-500 hover:border-zinc-400 dark:hover:border-zinc-500"
            )}
          >
            <option value="">Open</option>
            <option value="false_positive">False Positive</option>
            <option value="test_dev">Test / Dev</option>
            <option value="reported">Reported</option>
          </select>
        </div>
      </div>

      {showCode && finding.code_context && (
        <div className="mt-3">
          <CodeViewer context={finding.code_context} filePath={finding.file_path} />
        </div>
      )}
      {showCode && !finding.code_context && finding.matched_code && (
        <div className="mt-3">
          <pre className="text-xs font-mono bg-zinc-50 border border-zinc-200 dark:bg-zinc-900 dark:border-zinc-800 rounded p-3 overflow-x-auto text-zinc-700 dark:text-zinc-300">
            {finding.matched_code}
          </pre>
        </div>
      )}
    </div>
  );
}
