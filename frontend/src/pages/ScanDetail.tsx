import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle,
  Download,
  Eye,
  Filter,
  History,
  Loader2,
  RefreshCw,
  RotateCcw,
  StopCircle,
  XCircle,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { bulkUpdateFindings, cancelScan, getFindings, getScan, getScans, rescan } from "../api/client";
import FindingGroup from "../components/FindingGroup";
import ScanProgress from "../components/ScanProgress";
import SeverityBadge from "../components/SeverityBadge";
import type { FindingGroup as FindingGroupType, Scan, Severity } from "../types";
import { exportFindingsToCsv } from "../utils/exportCsv";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const ALL_SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const scanId = Number(id);

  const navigate = useNavigate();
  const [filterSeverities, setFilterSeverities] = useState<Severity[]>([...ALL_SEVERITIES]);
  const [filterTools, setFilterTools] = useState<string[]>([]);
  const [showTriaged, setShowTriaged] = useState(false);
  const [selectedFindings, setSelectedFindings] = useState<Set<number>>(new Set());

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId),
    refetchInterval: (query) => {
      const s = query.state.data;
      return s?.status === "running" || s?.status === "pending" ? 2000 : false;
    },
  });

  const { data: findings = [], isLoading: findingsLoading } = useQuery({
    queryKey: ["findings", scanId],
    queryFn: () => getFindings(scanId),
    enabled: scan?.status === "completed",
  });

  // Fetch sibling versions for version navigation
  const rootId = scan?.parent_scan_id ?? scan?.id;
  const { data: allScans = [] } = useQuery({
    queryKey: ["scans"],
    queryFn: getScans,
  });
  const siblingVersions = useMemo(() => {
    if (!rootId) return [];
    return allScans
      .filter((s: Scan) => s.id === rootId || s.parent_scan_id === rootId)
      .sort((a: Scan, b: Scan) => (b.version ?? 1) - (a.version ?? 1));
  }, [allScans, rootId]);

  const allTools = useMemo(() => {
    const tools = [...new Set(findings.map((f) => f.tool))];
    if (filterTools.length === 0 && tools.length > 0) {
      setFilterTools(tools);
    }
    return tools;
  }, [findings]);

  const rescanMutation = useMutation({
    mutationFn: (findingIds?: number[]) => rescan(scanId, findingIds),
    onSuccess: (newScan) => {
      navigate(`/scans/${newScan.id}`);
    },
  });

  const cancelMutation = useMutation({
    mutationFn: () => cancelScan(scanId),
  });

  const queryClient = useQueryClient();
  const bulkTriageMutation = useMutation({
    mutationFn: (triage_state: string | null) =>
      bulkUpdateFindings([...selectedFindings], triage_state),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
      queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
      setSelectedFindings(new Set());
    },
  });

  const toggleFinding = useCallback((id: number) => {
    setSelectedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const toggleGroup = useCallback((ids: number[]) => {
    setSelectedFindings((prev) => {
      const next = new Set(prev);
      const allSelected = ids.every((id) => next.has(id));
      if (allSelected) {
        ids.forEach((id) => next.delete(id));
      } else {
        ids.forEach((id) => next.add(id));
      }
      return next;
    });
  }, []);

  const toggleAllVisible = useCallback(() => {
    setSelectedFindings((prev) => {
      const visibleIds = findings
        .filter((f) => filterSeverities.includes(f.severity) && (filterTools.length === 0 || filterTools.includes(f.tool)))
        .map((f) => f.id);
      const allSelected = visibleIds.every((id) => prev.has(id));
      if (allSelected) return new Set();
      return new Set(visibleIds);
    });
  }, [findings, filterSeverities, filterTools]);

  const groups: FindingGroupType[] = useMemo(() => {
    const map = new Map<string, FindingGroupType>();
    for (const finding of findings) {
      const key = `${finding.rule_id}__${finding.tool}`;
      if (!map.has(key)) {
        map.set(key, {
          rule_id: finding.rule_id,
          rule_name: finding.rule_name,
          severity: finding.severity,
          tool: finding.tool,
          category: finding.category,
          message: finding.message,
          cwe: finding.cwe,
          owasp: finding.owasp,
          references: finding.references,
          findings: [],
          falsePositiveCount: 0,
        });
      }
      const g = map.get(key)!;
      g.findings.push(finding);
      if (finding.triage_state) g.falsePositiveCount++;
    }

    return [...map.values()].sort(
      (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    );
  }, [findings]);

  const filteredGroups = useMemo(
    () =>
      groups.filter(
        (g) =>
          filterSeverities.includes(g.severity) &&
          (filterTools.length === 0 || filterTools.includes(g.tool))
      ),
    [groups, filterSeverities, filterTools]
  );

  function toggleSeverity(sev: Severity) {
    setFilterSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
  }

  function toggleTool(tool: string) {
    setFilterTools((prev) =>
      prev.includes(tool) ? prev.filter((t) => t !== tool) : [...prev, tool]
    );
  }

  if (scanLoading) {
    return (
      <div className="flex items-center gap-2 text-zinc-500 p-8">
        <Loader2 size={16} className="animate-spin" /> Loading...
      </div>
    );
  }

  if (!scan) {
    return <div className="p-8 text-red-500">Scan not found</div>;
  }

  const isRunning = scan.status === "running" || scan.status === "pending";
  const triagedCount = findings.filter((f) => f.triage_state).length;

  return (
    <div className="max-w-6xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-6">
        <Link
          to="/"
          className="inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-700 dark:text-zinc-500 dark:hover:text-zinc-300 transition-colors"
        >
          <ArrowLeft size={14} /> All Scans
        </Link>
        {siblingVersions.length > 1 && (
          <div className="flex items-center gap-2">
            <History size={13} className="text-zinc-400" />
            <select
              value={scanId}
              onChange={(e) => navigate(`/scans/${e.target.value}`)}
              className="text-xs px-2 py-1 rounded border border-zinc-300 bg-white dark:bg-zinc-900 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300 cursor-pointer"
            >
              {siblingVersions.map((s: Scan) => (
                <option key={s.id} value={s.id}>
                  v{s.version ?? 1} — {new Date(s.started_at).toLocaleDateString()} {s.status === "completed" ? `(${s.summary?.total ?? 0} findings)` : `(${s.status})`}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Header */}
      <div className="mb-6">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold font-mono truncate" title={scan.path}>
                {scan.label ?? scan.path.split(/[/\\]/).pop()}
              </h1>
              {(scan.version ?? 1) > 1 && (
                <span className="text-xs font-medium px-1.5 py-0.5 rounded bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400 shrink-0">
                  v{scan.version}
                </span>
              )}
            </div>
            <p className="text-xs text-zinc-400 dark:text-zinc-500 font-mono mt-1 truncate">{scan.path}</p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            {scan.status === "running" && (
              <>
                <span className="flex items-center gap-1.5 text-emerald-500 dark:text-emerald-400 text-sm">
                  <Loader2 size={14} className="animate-spin" /> Scanning...
                </span>
                <button
                  onClick={() => cancelMutation.mutate()}
                  disabled={cancelMutation.isPending}
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-red-300 text-red-600 hover:text-red-800 hover:border-red-400 dark:border-red-700 dark:text-red-400 dark:hover:text-red-200 dark:hover:border-red-500 transition-colors disabled:opacity-50"
                >
                  <StopCircle size={13} />
                  {cancelMutation.isPending ? "Cancelling..." : "Cancel"}
                </button>
              </>
            )}
            {scan.status === "completed" && (
              <CheckCircle size={16} className="text-emerald-500 dark:text-emerald-400" />
            )}
            {scan.status === "failed" && <XCircle size={16} className="text-red-500" />}
            {scan.status === "completed" && (
              <button
                onClick={() => rescanMutation.mutate(undefined)}
                disabled={rescanMutation.isPending}
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-emerald-300 text-emerald-700 hover:text-emerald-900 hover:border-emerald-400 dark:border-emerald-700 dark:text-emerald-400 dark:hover:text-emerald-200 dark:hover:border-emerald-500 transition-colors disabled:opacity-50"
              >
                <RefreshCw size={13} className={rescanMutation.isPending ? "animate-spin" : ""} />
                Re-scan
              </button>
            )}
            {findings.length > 0 && (
              <>
                <button
                  onClick={() => {
                    window.open(`/api/scans/${scanId}/raw-output`, "_blank");
                  }}
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-zinc-300 text-zinc-600 hover:text-zinc-900 hover:border-zinc-400 dark:border-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200 dark:hover:border-zinc-500 transition-colors"
                >
                  <Download size={13} />
                  Export JSON
                </button>
                <button
                  onClick={() => exportFindingsToCsv(scan, findings)}
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-zinc-300 text-zinc-600 hover:text-zinc-900 hover:border-zinc-400 dark:border-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200 dark:hover:border-zinc-500 transition-colors"
                >
                  <Download size={13} />
                  Export CSV
                </button>
              </>
            )}
          </div>
        </div>

        {scan.summary && (
          <div className="flex items-center gap-3 mt-4 flex-wrap">
            {ALL_SEVERITIES.map((sev) => {
              const count = scan.summary![sev.toLowerCase() as keyof typeof scan.summary] as number;
              if (count === 0) return null;
              return (
                <div key={sev} className="flex items-center gap-1.5">
                  <SeverityBadge severity={sev} />
                  <span className="text-sm font-mono text-zinc-700 dark:text-zinc-300">{count}</span>
                </div>
              );
            })}
            {triagedCount > 0 && (
              <span className="text-xs text-zinc-400 dark:text-zinc-600">({triagedCount} triaged)</span>
            )}
          </div>
        )}

        {scan.error_log && (
          <div className="mt-3 bg-red-50 border border-red-200 dark:bg-red-950/20 dark:border-red-900 rounded px-3 py-2 text-xs text-red-600 dark:text-red-400 font-mono whitespace-pre-wrap">
            <AlertTriangle size={12} className="inline mr-1" />
            {scan.error_log}
          </div>
        )}
      </div>

      {isRunning && (
        <div>
          {scan.progress ? (
            <ScanProgress progress={scan.progress} />
          ) : (
            <div className="flex items-center gap-3 text-zinc-500 py-12 justify-center">
              <Loader2 size={20} className="animate-spin text-emerald-500 dark:text-emerald-400" />
              <span>Starting scan...</span>
            </div>
          )}
        </div>
      )}

      {scan.status === "completed" && (
        <>
          {/* Filter bar */}
          <div className="flex items-center gap-4 mb-5 flex-wrap">
            <div className="flex items-center gap-1.5">
              <Filter size={13} className="text-zinc-400" />
              <span className="text-xs text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">Severity</span>
            </div>
            {ALL_SEVERITIES.map((sev) => {
              const active = filterSeverities.includes(sev);
              return (
                <button
                  key={sev}
                  onClick={() => toggleSeverity(sev)}
                  className={clsx("transition-opacity", !active && "opacity-30")}
                >
                  <SeverityBadge severity={sev} />
                </button>
              );
            })}

            {allTools.length > 1 && (
              <>
                <div className="w-px h-4 bg-zinc-200 dark:bg-zinc-800" />
                <span className="text-xs text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">Tool</span>
                {allTools.map((tool) => (
                  <button
                    key={tool}
                    onClick={() => toggleTool(tool)}
                    className={clsx(
                      "text-xs font-mono px-2 py-0.5 rounded border transition-all",
                      filterTools.includes(tool)
                        ? "border-zinc-400 text-zinc-700 bg-zinc-100 dark:border-zinc-600 dark:text-zinc-300 dark:bg-zinc-800"
                        : "border-zinc-200 text-zinc-400 dark:border-zinc-800 dark:text-zinc-600"
                    )}
                  >
                    {tool}
                  </button>
                ))}
              </>
            )}

            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => setShowTriaged((v) => !v)}
                className={clsx(
                  "flex items-center gap-1.5 text-xs px-2 py-1 rounded border transition-all",
                  showTriaged
                    ? "border-zinc-400 text-zinc-700 bg-zinc-100 dark:border-zinc-600 dark:text-zinc-300 dark:bg-zinc-800"
                    : "border-zinc-200 text-zinc-400 dark:border-zinc-800 dark:text-zinc-600"
                )}
              >
                <Eye size={11} />
                {showTriaged ? "Hiding" : "Show"} triaged
              </button>
              <button
                onClick={toggleAllVisible}
                className={clsx(
                  "flex items-center gap-1.5 text-xs px-2 py-1 rounded border transition-all",
                  selectedFindings.size > 0
                    ? "border-blue-400 text-blue-700 bg-blue-50 dark:border-blue-600 dark:text-blue-300 dark:bg-blue-950"
                    : "border-zinc-200 text-zinc-400 dark:border-zinc-800 dark:text-zinc-600"
                )}
              >
                {selectedFindings.size > 0 ? `${selectedFindings.size} selected` : "Select all"}
              </button>
            </div>
          </div>

          {findingsLoading ? (
            <div className="flex items-center gap-2 text-zinc-500">
              <Loader2 size={14} className="animate-spin" /> Loading findings...
            </div>
          ) : filteredGroups.length === 0 ? (
            <div className="text-center py-16 text-zinc-400 dark:text-zinc-600">
              <p>{groups.length === 0 ? "No findings — clean scan!" : "No findings match the current filters."}</p>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredGroups.map((group) => (
                <FindingGroup
                  key={`${group.rule_id}__${group.tool}`}
                  group={group}
                  scanId={scanId}
                  showTriaged={showTriaged}
                  selectedFindings={selectedFindings}
                  onToggleFinding={toggleFinding}
                  onToggleGroup={toggleGroup}
                />
              ))}
            </div>
          )}
        </>
      )}

      {/* Floating selection action bar */}
      {selectedFindings.size > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 bg-white dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 shadow-lg rounded-lg px-4 py-2.5">
          <span className="text-sm text-zinc-600 dark:text-zinc-300 font-medium">
            {selectedFindings.size} finding{selectedFindings.size !== 1 ? "s" : ""} selected
          </span>
          <select
            value="__placeholder__"
            onChange={(e) => {
              const val = e.target.value;
              bulkTriageMutation.mutate(val === "__open__" ? null : val);
              e.target.value = "__placeholder__";
            }}
            disabled={bulkTriageMutation.isPending}
            className="text-xs px-2 py-1.5 rounded border border-amber-300 bg-white dark:bg-zinc-900 dark:border-amber-700 text-amber-700 dark:text-amber-400 cursor-pointer disabled:opacity-50"
          >
            <option value="__placeholder__" disabled>Set status...</option>
            <option value="__open__">Open</option>
            <option value="false_positive">False Positive</option>
            <option value="test_dev">Test / Dev</option>
            <option value="reported">Reported</option>
          </select>
          <button
            onClick={() => rescanMutation.mutate([...selectedFindings])}
            disabled={rescanMutation.isPending}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-emerald-600 text-white hover:bg-emerald-700 transition-colors disabled:opacity-50"
          >
            <RotateCcw size={13} className={rescanMutation.isPending ? "animate-spin" : ""} />
            Re-scan selected
          </button>
          <button
            onClick={() => setSelectedFindings(new Set())}
            className="text-xs text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300 transition-colors"
          >
            Clear
          </button>
        </div>
      )}
    </div>
  );
}
