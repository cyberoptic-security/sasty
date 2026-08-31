import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Box,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Clock,
  Loader2,
  Plus,
  RotateCcw,
  Settings,
  Trash2,
  XCircle,
} from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { deleteScan, getScans, resetScan } from "../api/client";
import NewScanModal from "../components/NewScanModal";
import SeverityBadge from "../components/SeverityBadge";
import ToolsPanel from "../components/ToolsPanel";
import type { Scan } from "../types";

const STATUS_ICON: Record<string, React.ReactNode> = {
  pending: <Clock size={14} className="text-zinc-400" />,
  running: <Loader2 size={14} className="text-emerald-500 dark:text-emerald-400 animate-spin" />,
  completed: <CheckCircle size={14} className="text-emerald-500 dark:text-emerald-400" />,
  failed: <XCircle size={14} className="text-red-500" />,
};

function fmt(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

interface ScanGroup {
  rootId: number;
  latest: Scan;
  versions: Scan[]; // all versions sorted newest first (includes latest)
}

function groupScans(scans: Scan[]): ScanGroup[] {
  const byRoot = new Map<number, Scan[]>();

  for (const scan of scans) {
    const rootId = scan.parent_scan_id ?? scan.id;
    if (!byRoot.has(rootId)) byRoot.set(rootId, []);
    byRoot.get(rootId)!.push(scan);
  }

  const groups: ScanGroup[] = [];
  for (const [rootId, versions] of byRoot) {
    // Sort by version descending (latest first)
    versions.sort((a, b) => (b.version ?? 1) - (a.version ?? 1));
    groups.push({
      rootId,
      latest: versions[0],
      versions,
    });
  }

  // Sort groups by latest scan date descending
  groups.sort((a, b) => new Date(b.latest.started_at).getTime() - new Date(a.latest.started_at).getTime());

  return groups;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showNewScan, setShowNewScan] = useState(false);
  const [showTools, setShowTools] = useState(false);
  const [expandedGroups, setExpandedGroups] = useState<Set<number>>(new Set());

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: getScans,
    refetchInterval: (query) => {
      const data = query.state.data as Scan[] | undefined;
      const hasRunning = data?.some((s) => s.status === "running" || s.status === "pending");
      return hasRunning ? 2000 : false;
    },
  });

  const groups = useMemo(() => groupScans(scans), [scans]);

  const deleteMutation = useMutation({
    mutationFn: deleteScan,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  const resetMutation = useMutation({
    mutationFn: resetScan,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  function toggleExpand(rootId: number) {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(rootId)) next.delete(rootId);
      else next.add(rootId);
      return next;
    });
  }

  function renderScanRow(scan: Scan, opts: { isVersion?: boolean; versionCount?: number; expanded?: boolean; rootId?: number }) {
    const { isVersion, versionCount, expanded, rootId } = opts;
    return (
      <tr
        key={scan.id}
        onClick={() => navigate(`/scans/${scan.id}`)}
        className={clsx(
          "transition-colors cursor-pointer",
          isVersion
            ? "bg-zinc-50/60 dark:bg-zinc-800/20 hover:bg-zinc-100 dark:hover:bg-zinc-800/40"
            : "bg-white dark:bg-transparent hover:bg-zinc-50 dark:hover:bg-zinc-800/40"
        )}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {!isVersion && versionCount && versionCount > 1 ? (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  toggleExpand(rootId!);
                }}
                className="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300 transition-colors shrink-0"
              >
                {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </button>
            ) : isVersion ? (
              <span className="w-[14px] shrink-0" />
            ) : null}
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-zinc-700 dark:text-zinc-200 truncate max-w-xs" title={scan.path}>
                  {scan.label ?? scan.path.split(/[/\\]/).pop()}
                </span>
                {scan.source_type === "image" && (
                  <span className="flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded bg-sky-100 text-sky-700 dark:bg-sky-950 dark:text-sky-300 shrink-0">
                    <Box size={10} /> image
                  </span>
                )}
                {!isVersion && versionCount && versionCount > 1 && (
                  <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400 shrink-0">
                    v{scan.version ?? 1}
                  </span>
                )}
                {isVersion && (
                  <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400 shrink-0">
                    v{scan.version ?? 1}
                  </span>
                )}
              </div>
              {!isVersion && (
                <div className="text-xs text-zinc-400 dark:text-zinc-500 mt-0.5 font-mono truncate max-w-xs" title={scan.path}>
                  {scan.path}
                </div>
              )}
            </div>
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1.5 capitalize text-zinc-500 dark:text-zinc-400">
            {STATUS_ICON[scan.status]}
            {scan.status}
          </div>
        </td>
        <td className="px-4 py-3">
          {scan.summary ? (
            <div className="flex items-center gap-1.5 flex-wrap">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map(
                (sev) =>
                  scan.summary![sev.toLowerCase() as keyof typeof scan.summary] > 0 && (
                    <SeverityBadge key={sev} severity={sev} />
                  )
              )}
              <span className="text-xs text-zinc-400 dark:text-zinc-500">
                {scan.summary.total} total
              </span>
            </div>
          ) : (
            <span className="text-zinc-300 dark:text-zinc-700">—</span>
          )}
        </td>
        <td className="px-4 py-3 text-xs text-zinc-400 dark:text-zinc-500">
          {fmt(scan.started_at)}
        </td>
        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center gap-2">
            {scan.status === "running" && (
              <button
                onClick={() => {
                  if (confirm("Reset this stuck scan? It will be marked as failed.")) {
                    resetMutation.mutate(scan.id);
                  }
                }}
                disabled={resetMutation.isPending && resetMutation.variables === scan.id}
                title="Reset stuck scan"
                className="text-zinc-300 hover:text-amber-500 dark:text-zinc-700 dark:hover:text-amber-400 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <RotateCcw size={14} />
              </button>
            )}
            <button
              onClick={() => {
                if (confirm("Delete this scan and all its findings?")) {
                  deleteMutation.mutate(scan.id);
                }
              }}
              disabled={scan.status === "running"}
              className="text-zinc-300 hover:text-red-500 dark:text-zinc-700 dark:hover:text-red-400 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <Trash2 size={14} />
            </button>
          </div>
        </td>
      </tr>
    );
  }

  return (
    <div className="max-w-5xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold">Scans</h1>
          <p className="text-zinc-500 text-sm mt-1">
            {scans.length === 0 ? "No scans yet" : `${groups.length} scan${groups.length !== 1 ? "s" : ""}${scans.length > groups.length ? ` (${scans.length} total with versions)` : ""}`}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowTools((v) => !v)}
            className={clsx(
              "flex items-center gap-2 px-3 py-2 text-sm rounded border transition-colors",
              showTools
                ? "border-emerald-500 bg-emerald-50 text-emerald-600 dark:border-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400"
                : "border-zinc-300 text-zinc-500 hover:text-zinc-800 hover:border-zinc-400 dark:border-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200 dark:hover:border-zinc-600"
            )}
          >
            <Settings size={15} />
            Tools
          </button>
          <button
            onClick={() => setShowNewScan(true)}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded font-medium transition-colors"
          >
            <Plus size={15} />
            New Scan
          </button>
        </div>
      </div>

      {showTools && (
        <div className="mb-8">
          <h2 className="text-sm font-medium text-zinc-500 dark:text-zinc-400 mb-3 uppercase tracking-wider">
            Tool Status
          </h2>
          <ToolsPanel />
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center gap-2 text-zinc-500">
          <Loader2 size={16} className="animate-spin" /> Loading scans...
        </div>
      ) : groups.length === 0 ? (
        <div className="text-center py-20 text-zinc-400 dark:text-zinc-600">
          <p className="text-lg mb-2">No scans yet</p>
          <p className="text-sm">Click "New Scan" to get started</p>
        </div>
      ) : (
        <div className="border border-zinc-200 dark:border-zinc-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900">
                <th className="text-left px-4 py-3 text-zinc-500 font-medium">Scan</th>
                <th className="text-left px-4 py-3 text-zinc-500 font-medium w-32">Status</th>
                <th className="text-left px-4 py-3 text-zinc-500 font-medium w-48">Findings</th>
                <th className="text-left px-4 py-3 text-zinc-500 font-medium w-36">Date</th>
                <th className="px-4 py-3 w-10" />
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
              {groups.map((group) => {
                const expanded = expandedGroups.has(group.rootId);
                const olderVersions = group.versions.slice(1);
                return (
                  <Fragment key={group.rootId}>
                    {renderScanRow(group.latest, {
                      versionCount: group.versions.length,
                      expanded,
                      rootId: group.rootId,
                    })}
                    {expanded &&
                      olderVersions.map((scan) =>
                        renderScanRow(scan, { isVersion: true })
                      )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {showNewScan && <NewScanModal onClose={() => setShowNewScan(false)} />}
    </div>
  );
}
