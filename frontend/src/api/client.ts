import type { Finding, Scan, Tool } from "../types";

const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// --- Info ---
export const getInfo = () =>
  request<{
    is_docker: boolean;
    image_extract_available: boolean;
    image_extract_backend: "crane" | "docker" | null;
  }>("/info");

// --- Tools ---
export const getTools = () => request<Tool[]>("/tools");
export const updateTool = (name: string) =>
  request<{ version: string }>(`/tools/${name}/update`, { method: "POST" });

// --- Scans ---
export const getScans = () => request<Scan[]>("/scans");
export const checkGit = (path: string) =>
  request<{ is_git: boolean }>(`/scans/check-git?path=${encodeURIComponent(path)}`);
export const getScan = (id: number) => request<Scan>(`/scans/${id}`);
export const deleteScan = (id: number) =>
  request<void>(`/scans/${id}`, { method: "DELETE" });
export const cancelScan = (id: number) =>
  request<{ status: string }>(`/scans/${id}/cancel`, { method: "POST" });
export const resetScan = (id: number) =>
  request<{ status: string; message: string }>(`/scans/${id}/reset`, { method: "POST" });
export const rescan = (scanId: number, findingIds?: number[]) =>
  request<Scan>(`/scans/${scanId}/rescan`, {
    method: "POST",
    body: JSON.stringify({ finding_ids: findingIds ?? null }),
  });
export const createScan = (body: {
  path: string;
  label?: string;
  tools: string[];
  semgrep_configs: string[];
  tool_options?: Record<string, Record<string, string | boolean | number>>;
  custom_commands?: { label: string; command: string }[];
}) =>
  request<Scan>("/scans", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const checkImage = (image: string) =>
  request<{ image: string; extract_available: boolean; extract_backend: string | null }>(
    `/scans/check-image?image=${encodeURIComponent(image)}`
  );

export const createImageScan = (body: {
  image: string;
  label?: string;
  tools: string[];
  semgrep_configs: string[];
  tool_options?: Record<string, Record<string, string | boolean | number>>;
  custom_commands?: { label: string; command: string }[];
  extract_filesystem?: boolean;
}) =>
  request<Scan>("/scans/image", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const uploadScan = async (
  file: File,
  opts: { label?: string; tools: string[]; semgrep_configs: string[]; onProgress?: (pct: number) => void }
): Promise<Scan> => {
  const form = new FormData();
  form.append("file", file);
  if (opts.label) form.append("label", opts.label);
  form.append("tools", opts.tools.join(","));
  form.append("semgrep_configs", opts.semgrep_configs.join(","));

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${BASE}/scans/upload`);

    if (opts.onProgress) {
      xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable) {
          opts.onProgress!(Math.round((e.loaded / e.total) * 100));
        }
      });
    }

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText));
      } else {
        reject(new Error(xhr.responseText || `HTTP ${xhr.status}`));
      }
    };
    xhr.onerror = () => reject(new Error("Network error"));
    xhr.send(form);
  });
};

export const importScan = async (
  file: File,
  opts: { label?: string }
): Promise<Scan> => {
  const form = new FormData();
  form.append("file", file);
  if (opts.label) form.append("label", opts.label);
  const res = await fetch(`${BASE}/scans/import`, { method: "POST", body: form });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `HTTP ${res.status}`);
  }
  return res.json() as Promise<Scan>;
};

// --- Findings ---
export const getFindings = (scanId: number) =>
  request<Finding[]>(`/findings/scan/${scanId}`);

export const updateFinding = (
  id: number,
  body: { triage_state: string | null }
) =>
  request<Finding>(`/findings/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });

export const bulkUpdateFindings = (
  ids: number[],
  triage_state: string | null
) =>
  request<{ updated: number }>(`/findings/bulk`, {
    method: "PATCH",
    body: JSON.stringify({ ids, triage_state }),
  });
