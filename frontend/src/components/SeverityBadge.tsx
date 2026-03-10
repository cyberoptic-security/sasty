import clsx from "clsx";
import type { Severity } from "../types";

const STYLES: Record<Severity, string> = {
  CRITICAL: "bg-red-950 text-red-300 border border-red-800",
  HIGH: "bg-orange-950 text-orange-300 border border-orange-800",
  MEDIUM: "bg-yellow-950 text-yellow-300 border border-yellow-800",
  LOW: "bg-blue-950 text-blue-300 border border-blue-800",
  INFO: "bg-zinc-800 text-zinc-400 border border-zinc-700",
};

interface Props {
  severity: string;
  className?: string;
}

export default function SeverityBadge({ severity, className }: Props) {
  const sev = severity.toUpperCase() as Severity;
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium font-mono uppercase tracking-wider",
        STYLES[sev] ?? STYLES.INFO,
        className
      )}
    >
      {severity}
    </span>
  );
}
