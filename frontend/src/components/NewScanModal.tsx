import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { FileJson, GitBranch, Upload, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { checkGit, createScan, getInfo, importScan, uploadScan } from "../api/client";

const TOOLS = ["semgrep", "gitleaks", "hadolint", "bandit", "trivy"] as const;

const SEMGREP_CONFIGS = [
  { id: "auto", label: "Auto (recommended)" },
  { id: "p/javascript", label: "JavaScript" },
  { id: "p/typescript", label: "TypeScript" },
  { id: "p/nodejs", label: "Node.js" },
  { id: "p/docker", label: "Docker" },
  { id: "p/secrets", label: "Secrets" },
  { id: "p/owasp-top-ten", label: "OWASP Top 10" },
];

type Mode = "path" | "upload" | "import";

interface Props {
  onClose: () => void;
}

export default function NewScanModal({ onClose }: Props) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: info } = useQuery({
    queryKey: ["info"],
    queryFn: getInfo,
    staleTime: Infinity,
  });
  const isDocker = info?.is_docker ?? false;

  const [mode, setMode] = useState<Mode>(isDocker ? "upload" : "path");
  const [path, setPath] = useState("");
  const [label, setLabel] = useState("");
  const [selectedTools, setSelectedTools] = useState<string[]>([...TOOLS]);
  const [selectedConfigs, setSelectedConfigs] = useState<string[]>([
    "auto",
  ]);
  const [isGitRepo, setIsGitRepo] = useState<boolean | null>(null);
  const gitCheckTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Upload / import state
  const [file, setFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const importFileRef = useRef<HTMLInputElement>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);

  // Switch away from "path" mode if Docker is detected
  useEffect(() => {
    if (isDocker && mode === "path") setMode("upload");
  }, [isDocker]);

  // Debounced git check when path changes
  useEffect(() => {
    if (mode !== "path") return;
    setIsGitRepo(null);
    if (gitCheckTimer.current) clearTimeout(gitCheckTimer.current);
    const trimmed = path.trim();
    if (!trimmed) return;
    gitCheckTimer.current = setTimeout(() => {
      checkGit(trimmed)
        .then(({ is_git }) => {
          setIsGitRepo(is_git);
          if (!is_git) {
            setSelectedTools((prev) => prev.filter((t) => t !== "gitleaks"));
          } else {
            setSelectedTools((prev) =>
              prev.includes("gitleaks") ? prev : [...prev, "gitleaks"]
            );
          }
        })
        .catch(() => setIsGitRepo(null));
    }, 600);
    return () => {
      if (gitCheckTimer.current) clearTimeout(gitCheckTimer.current);
    };
  }, [path, mode]);

  const pathMutation = useMutation({
    mutationFn: createScan,
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      onClose();
      navigate(`/scans/${scan.id}`);
    },
  });

  const uploadMutation = useMutation({
    mutationFn: (f: File) => {
      setUploadProgress(0);
      return uploadScan(f, {
        label: label.trim() || undefined,
        tools: selectedTools,
        semgrep_configs: selectedConfigs,
        onProgress: setUploadProgress,
      });
    },
    onSuccess: (scan) => {
      setUploadProgress(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      onClose();
      navigate(`/scans/${scan.id}`);
    },
    onError: () => setUploadProgress(null),
  });

  const importMutation = useMutation({
    mutationFn: (f: File) =>
      importScan(f, { label: label.trim() || undefined }),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      onClose();
      navigate(`/scans/${scan.id}`);
    },
  });

  const mutation = mode === "path" ? pathMutation : mode === "upload" ? uploadMutation : importMutation;

  function toggleTool(tool: string) {
    setSelectedTools((prev) =>
      prev.includes(tool) ? prev.filter((t) => t !== tool) : [...prev, tool]
    );
  }

  function toggleConfig(id: string) {
    setSelectedConfigs((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (mode === "path") {
      if (!path.trim()) return;
      pathMutation.mutate({
        path: path.trim(),
        label: label.trim() || undefined,
        tools: selectedTools,
        semgrep_configs: selectedConfigs,
      });
    } else if (mode === "upload") {
      if (!file) return;
      uploadMutation.mutate(file);
    } else {
      if (!importFile) return;
      importMutation.mutate(importFile);
    }
  }

  function handleFileDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped && dropped.name.toLowerCase().endsWith(".zip")) {
      setFile(dropped);
    }
  }

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0];
    if (selected) setFile(selected);
  }

  function handleImportDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped && dropped.name.toLowerCase().endsWith(".json")) {
      setImportFile(dropped);
    }
  }

  function handleImportSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0];
    if (selected) setImportFile(selected);
  }

  const canSubmit =
    mode === "path" ? !!path.trim() : mode === "upload" ? !!file : !!importFile;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-white border border-zinc-200 dark:bg-zinc-900 dark:border-zinc-700 rounded-lg w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-200 dark:border-zinc-800">
          <h2 className="font-semibold text-lg">New Scan</h2>
          <button onClick={onClose} className="text-zinc-400 hover:text-zinc-700 dark:text-zinc-500 dark:hover:text-zinc-300 transition-colors">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {/* Mode tabs */}
          <div className="flex gap-1 bg-zinc-100 dark:bg-zinc-800 rounded-lg p-1">
            {!isDocker && (
              <button
                type="button"
                onClick={() => setMode("path")}
                className={clsx(
                  "flex-1 text-sm py-1.5 rounded-md transition-colors font-medium",
                  mode === "path"
                    ? "bg-white dark:bg-zinc-700 text-zinc-800 dark:text-zinc-200 shadow-sm"
                    : "text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300"
                )}
              >
                Local Path
              </button>
            )}
            <button
              type="button"
              onClick={() => setMode("upload")}
              className={clsx(
                "flex-1 text-sm py-1.5 rounded-md transition-colors font-medium flex items-center justify-center gap-1.5",
                mode === "upload"
                  ? "bg-white dark:bg-zinc-700 text-zinc-800 dark:text-zinc-200 shadow-sm"
                  : "text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300"
              )}
            >
              <Upload size={13} />
              Upload Zip
            </button>
            <button
              type="button"
              onClick={() => setMode("import")}
              className={clsx(
                "flex-1 text-sm py-1.5 rounded-md transition-colors font-medium flex items-center justify-center gap-1.5",
                mode === "import"
                  ? "bg-white dark:bg-zinc-700 text-zinc-800 dark:text-zinc-200 shadow-sm"
                  : "text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300"
              )}
            >
              <FileJson size={13} />
              Import JSON
            </button>
          </div>

          {mode === "path" ? (
            <div>
              <label className="block text-sm text-zinc-600 dark:text-zinc-400 mb-1.5">Target Path *</label>
              <input
                type="text"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="/home/user/project  or  C:\Users\user\project"
                className="w-full bg-white border border-zinc-300 dark:bg-zinc-800 dark:border-zinc-700 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-emerald-500 placeholder:text-zinc-400 dark:placeholder:text-zinc-600"
                required={mode === "path"}
                autoFocus
              />
            </div>
          ) : mode === "upload" ? (
            <div>
              <label className="block text-sm text-zinc-600 dark:text-zinc-400 mb-1.5">Zip File *</label>
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                className={clsx(
                  "border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors",
                  dragOver
                    ? "border-emerald-400 bg-emerald-50 dark:border-emerald-600 dark:bg-emerald-950/30"
                    : file
                    ? "border-emerald-300 bg-emerald-50/50 dark:border-emerald-700 dark:bg-emerald-950/20"
                    : "border-zinc-300 dark:border-zinc-700 hover:border-zinc-400 dark:hover:border-zinc-600"
                )}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip"
                  onChange={handleFileSelect}
                  className="hidden"
                />
                {file ? (
                  <div>
                    <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300">{file.name}</p>
                    <p className="text-xs text-zinc-400 dark:text-zinc-500 mt-1">
                      {(file.size / 1024 / 1024).toFixed(1)} MB
                    </p>
                    {uploadProgress !== null && (
                      <div className="mt-2 w-full bg-zinc-200 dark:bg-zinc-700 rounded-full h-1.5 overflow-hidden">
                        <div
                          className="bg-emerald-500 h-1.5 rounded-full transition-all duration-300"
                          style={{ width: `${uploadProgress}%` }}
                        />
                      </div>
                    )}
                    {uploadProgress !== null && (
                      <p className="text-xs text-emerald-600 dark:text-emerald-400 mt-1">
                        {uploadProgress < 100 ? `Uploading... ${uploadProgress}%` : "Processing..."}
                      </p>
                    )}
                  </div>
                ) : (
                  <div>
                    <Upload size={20} className="mx-auto text-zinc-400 dark:text-zinc-500 mb-2" />
                    <p className="text-sm text-zinc-500 dark:text-zinc-400">
                      Drop a .zip file here or click to browse
                    </p>
                    <p className="text-xs text-zinc-400 dark:text-zinc-600 mt-1">No size limit</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-sm text-zinc-600 dark:text-zinc-400 mb-1.5">JSON File *</label>
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleImportDrop}
                onClick={() => importFileRef.current?.click()}
                className={clsx(
                  "border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors",
                  dragOver
                    ? "border-emerald-400 bg-emerald-50 dark:border-emerald-600 dark:bg-emerald-950/30"
                    : importFile
                    ? "border-emerald-300 bg-emerald-50/50 dark:border-emerald-700 dark:bg-emerald-950/20"
                    : "border-zinc-300 dark:border-zinc-700 hover:border-zinc-400 dark:hover:border-zinc-600"
                )}
              >
                <input
                  ref={importFileRef}
                  type="file"
                  accept=".json"
                  onChange={handleImportSelect}
                  className="hidden"
                />
                {importFile ? (
                  <div>
                    <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300">{importFile.name}</p>
                    <p className="text-xs text-zinc-400 dark:text-zinc-500 mt-1">
                      {(importFile.size / 1024 / 1024).toFixed(1)} MB
                    </p>
                  </div>
                ) : (
                  <div>
                    <FileJson size={20} className="mx-auto text-zinc-400 dark:text-zinc-500 mb-2" />
                    <p className="text-sm text-zinc-500 dark:text-zinc-400">
                      Drop a semgrep, gitleaks, hadolint, bandit, or trivy JSON file
                    </p>
                    <p className="text-xs text-zinc-400 dark:text-zinc-600 mt-1">
                      Raw tool output (e.g. semgrep --json)
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          <div>
            <label className="block text-sm text-zinc-600 dark:text-zinc-400 mb-1.5">Label (optional)</label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. myapp v1.2"
              className="w-full bg-white border border-zinc-300 dark:bg-zinc-800 dark:border-zinc-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-emerald-500 placeholder:text-zinc-400 dark:placeholder:text-zinc-600"
            />
          </div>

          {mode !== "import" && (
            <>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm text-zinc-600 dark:text-zinc-400">Tools</label>
                  {mode === "path" && isGitRepo === true && (
                    <span className="flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                      <GitBranch size={11} /> Git repository
                    </span>
                  )}
                  {mode === "path" && isGitRepo === false && (
                    <span className="flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
                      <GitBranch size={11} /> Not a git repo — gitleaks skipped
                    </span>
                  )}
                </div>
                <div className="flex gap-3 flex-wrap">
                  {TOOLS.map((tool) => {
                    const disabled = mode === "path" && tool === "gitleaks" && isGitRepo === false;
                    return (
                      <label
                        key={tool}
                        className={clsx(
                          "flex items-center gap-2 select-none",
                          disabled ? "cursor-not-allowed opacity-40" : "cursor-pointer"
                        )}
                      >
                        <input
                          type="checkbox"
                          checked={selectedTools.includes(tool)}
                          onChange={() => !disabled && toggleTool(tool)}
                          disabled={disabled}
                          className="accent-emerald-500"
                        />
                        <span className="text-sm font-mono">{tool}</span>
                      </label>
                    );
                  })}
                </div>
              </div>

              {selectedTools.includes("semgrep") && (
                <div>
                  <label className="block text-sm text-zinc-600 dark:text-zinc-400 mb-2">Semgrep Rule Sets</label>
                  <div className="grid grid-cols-2 gap-2">
                    {SEMGREP_CONFIGS.map(({ id, label: lbl }) => (
                      <label key={id} className="flex items-center gap-2 cursor-pointer select-none">
                        <input
                          type="checkbox"
                          checked={selectedConfigs.includes(id)}
                          onChange={() => toggleConfig(id)}
                          className="accent-emerald-500"
                        />
                        <span className="text-sm">{lbl}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {mode === "import" && (
            <p className="text-xs text-zinc-400 dark:text-zinc-600">
              The tool type is auto-detected from the JSON structure. Supports semgrep, gitleaks, hadolint, bandit, and trivy output.
            </p>
          )}

          {mutation.error && (
            <p className="text-red-500 text-sm bg-red-50 border border-red-200 dark:bg-red-950/30 dark:border-red-900 rounded px-3 py-2">
              {String(mutation.error)}
            </p>
          )}

          <div className="flex justify-end gap-3 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending || !canSubmit}
              className="px-4 py-2 text-sm bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50 disabled:cursor-not-allowed rounded font-medium transition-colors"
            >
              {mutation.isPending
                ? mode === "import" ? "Importing..." : mode === "upload" ? (uploadProgress !== null && uploadProgress < 100 ? `Uploading ${uploadProgress}%...` : "Processing...") : "Starting..."
                : mode === "import" ? "Import" : "Start Scan"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
