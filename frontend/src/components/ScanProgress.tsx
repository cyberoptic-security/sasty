import clsx from "clsx";
import { AlertTriangle, CheckCircle, Clock, Loader2, SkipForward } from "lucide-react";
import type { ScanProgress as ScanProgressType } from "../types";

interface Props {
  progress: ScanProgressType;
}

const STEP_ICON: Record<string, React.ReactNode> = {
  pending: <Clock size={14} className="text-zinc-400 dark:text-zinc-600" />,
  running: <Loader2 size={14} className="text-emerald-500 dark:text-emerald-400 animate-spin" />,
  done: <CheckCircle size={14} className="text-emerald-500 dark:text-emerald-400" />,
  error: <AlertTriangle size={14} className="text-red-500" />,
  skipped: <SkipForward size={14} className="text-zinc-400 dark:text-zinc-500" />,
};

export default function ScanProgress({ progress }: Props) {
  const { steps } = progress;
  const done = steps.filter((s) => s.status === "done" || s.status === "skipped" || s.status === "error").length;
  const pct = steps.length > 0 ? Math.round((done / steps.length) * 100) : 0;

  return (
    <div className="my-8 max-w-md mx-auto">
      {/* Bar */}
      <div className="h-1.5 bg-zinc-100 dark:bg-zinc-800 rounded-full overflow-hidden mb-6">
        <div
          className="h-full bg-emerald-500 dark:bg-emerald-400 rounded-full transition-all duration-700"
          style={{ width: `${pct}%` }}
        />
      </div>

      {/* Steps */}
      <div className="space-y-3">
        {steps.map((step) => (
          <div key={step.tool}>
            <div
              className={clsx(
                "flex items-center justify-between gap-3 px-4 py-3 rounded-lg border transition-colors",
                step.status === "running"
                  ? "border-emerald-200 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-950/30"
                  : step.status === "done"
                  ? "border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900/50"
                  : step.status === "error"
                  ? "border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/20"
                  : "border-zinc-100 bg-zinc-50/50 dark:border-zinc-800/50 dark:bg-zinc-900/20"
              )}
            >
              <div className="flex items-center gap-3">
                {STEP_ICON[step.status]}
                <span
                  className={clsx(
                    "text-sm font-mono",
                    step.status === "pending"
                      ? "text-zinc-400 dark:text-zinc-600"
                      : step.status === "running"
                      ? "text-emerald-700 dark:text-emerald-300 font-medium"
                      : step.status === "error"
                      ? "text-red-600 dark:text-red-400"
                      : "text-zinc-700 dark:text-zinc-300"
                  )}
                >
                  {step.tool}
                </span>
              </div>

              <div className="text-right text-xs shrink-0">
                {step.status === "running" && (
                  <span className="text-emerald-600 dark:text-emerald-400">Scanning...</span>
                )}
                {step.status === "done" && step.findings !== null && (
                  <span className="text-zinc-500 dark:text-zinc-400">
                    {step.findings} finding{step.findings !== 1 ? "s" : ""}
                  </span>
                )}
                {step.status === "error" && step.error && (
                  <span className="text-red-500 max-w-xs truncate block" title={step.error}>
                    {step.error.length > 60 ? step.error.slice(0, 60) + "…" : step.error}
                  </span>
                )}
                {step.status === "pending" && (
                  <span className="text-zinc-300 dark:text-zinc-700">Waiting</span>
                )}
              </div>
            </div>

            {/* Live output log */}
            {step.status === "running" && step.log_tail && step.log_tail.length > 0 && (
              <div className="ml-8 -mt-1 mb-2 px-3 py-2 bg-zinc-950 rounded-b-lg border border-t-0 border-zinc-800 overflow-hidden">
                {step.log_tail.map((line, idx) => (
                  <p
                    key={idx}
                    className={clsx(
                      "font-mono text-[11px] leading-relaxed truncate",
                      idx === step.log_tail!.length - 1
                        ? "text-emerald-400"
                        : "text-zinc-500"
                    )}
                  >
                    {line}
                  </p>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      <p className="text-center text-xs text-zinc-400 dark:text-zinc-600 mt-4">
        {done} of {steps.length} tools complete
      </p>
    </div>
  );
}
