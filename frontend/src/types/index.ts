export type ScanStatus = "pending" | "running" | "completed" | "failed";

export type TriageState = "false_positive" | "test_dev" | "reported";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ProgressStep {
  tool: string;
  status: "pending" | "running" | "done" | "error" | "skipped";
  findings: number | null;
  error: string | null;
  log_tail?: string[];
}

export interface ScanProgress {
  steps: ProgressStep[];
  current_tool: string | null;
}

export interface Scan {
  id: number;
  path: string;
  label?: string;
  status: ScanStatus;
  started_at: string;
  finished_at?: string;
  tools_used: string[];
  semgrep_configs: string[];
  summary?: ScanSummary;
  progress?: ScanProgress;
  error_log?: string;
  parent_scan_id?: number | null;
  version: number;
}

export interface CodeContext {
  lines: string[];
  start_line: number;
  highlight_start: number;
  highlight_end: number;
}

export interface Finding {
  id: number;
  scan_id: number;
  tool: string;
  rule_id: string;
  rule_name?: string;
  severity: Severity;
  category?: string;
  message: string;
  file_path: string;
  line_start?: number;
  line_end?: number;
  col_start?: number;
  col_end?: number;
  matched_code?: string;
  code_context?: CodeContext;
  fingerprint?: string;
  commit_hash?: string | null;
  commit_author?: string | null;
  commit_date?: string | null;
  cwe?: string[];
  owasp?: string[];
  references?: string[];
  triage_state: TriageState | null;
}

export interface FindingGroup {
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
  falsePositiveCount: number;
}

export interface Tool {
  name: string;
  description: string;
  current_version?: string;
  installed: boolean;
}
