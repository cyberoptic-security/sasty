import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { Box, ChevronDown, ChevronRight, FileJson, GitBranch, Plus, Terminal, Trash2, Upload, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { checkGit, createImageScan, createScan, getInfo, importScan, uploadScan } from "../api/client";

const TOOLS = ["semgrep", "betterleaks", "trufflehog", "hadolint", "bandit", "trivy"] as const;

const SEMGREP_CONFIGS = [
  { id: "auto", label: "Auto (recommended)" },
  { id: "p/javascript", label: "JavaScript" },
  { id: "p/typescript", label: "TypeScript" },
  { id: "p/nodejs", label: "Node.js" },
  { id: "p/docker", label: "Docker" },
  { id: "p/secrets", label: "Secrets" },
  { id: "p/owasp-top-ten", label: "OWASP Top 10" },
];

// Per-tool option definitions: known CLI flags with types
interface ToolOptionDef {
  key: string;
  label: string;
  type: "toggle" | "text" | "select";
  placeholder?: string;
  choices?: { value: string; label: string }[];
  hint?: string;
}

const TOOL_OPTIONS: Record<string, ToolOptionDef[]> = {
  semgrep: [
    { key: "severity", label: "Min Severity", type: "select", choices: [
      { value: "", label: "Default" }, { value: "ERROR", label: "Error" },
      { value: "WARNING", label: "Warning" }, { value: "INFO", label: "Info" },
    ]},
    { key: "exclude", label: "Exclude Patterns", type: "text", placeholder: "test/,*.min.js", hint: "Comma-separated glob patterns" },
    { key: "verbose", label: "Verbose Output", type: "toggle" },
  ],
  betterleaks: [
    { key: "log_level", label: "Log Level", type: "select", choices: [
      { value: "", label: "Default" }, { value: "debug", label: "Debug" },
      { value: "info", label: "Info" }, { value: "warn", label: "Warn" },
      { value: "error", label: "Error" },
    ]},
    { key: "config", label: "Config File Path", type: "text", placeholder: "/path/to/config.toml" },
    { key: "max_archive_depth", label: "Max Archive Depth", type: "text", placeholder: "0 (disabled by default)" },
    { key: "max_decode_depth", label: "Max Decode Depth", type: "text", placeholder: "5" },
  ],
  trufflehog: [
    { key: "only_verified", label: "Verified Only", type: "toggle", hint: "Skip unverified findings (fewer results, higher confidence)" },
    { key: "include_detectors", label: "Include Detectors", type: "text", placeholder: "AWS,GitHub,Slack", hint: "Comma-separated detector names" },
    { key: "exclude_detectors", label: "Exclude Detectors", type: "text", placeholder: "GitHubOauth", hint: "Comma-separated detector names" },
  ],
  hadolint: [
    { key: "failure_threshold", label: "Failure Threshold", type: "select", choices: [
      { value: "", label: "Default" }, { value: "error", label: "Error" },
      { value: "warning", label: "Warning" }, { value: "info", label: "Info" },
      { value: "style", label: "Style" },
    ]},
    { key: "ignore", label: "Ignore Rules", type: "text", placeholder: "DL3008,DL3009", hint: "Comma-separated rule IDs" },
    { key: "trusted_registry", label: "Trusted Registries", type: "text", placeholder: "docker.io,gcr.io", hint: "Comma-separated" },
  ],
  bandit: [
    { key: "severity", label: "Min Severity", type: "select", choices: [
      { value: "", label: "Default (all)" }, { value: "LOW", label: "Low+" },
      { value: "MEDIUM", label: "Medium+" }, { value: "HIGH", label: "High only" },
    ]},
    { key: "confidence", label: "Min Confidence", type: "select", choices: [
      { value: "", label: "Default (all)" }, { value: "LOW", label: "Low+" },
      { value: "MEDIUM", label: "Medium+" }, { value: "HIGH", label: "High only" },
    ]},
    { key: "skip", label: "Skip Tests", type: "text", placeholder: "B101,B601", hint: "Comma-separated test IDs" },
    { key: "tests", label: "Only Run Tests", type: "text", placeholder: "B101,B102", hint: "Comma-separated test IDs" },
  ],
  trivy: [
    { key: "severity", label: "Severities", type: "text", placeholder: "CRITICAL,HIGH,MEDIUM", hint: "Comma-separated" },
    { key: "ignore_unfixed", label: "Ignore Unfixed", type: "toggle" },
    { key: "scanners", label: "Scanners", type: "text", placeholder: "vuln,misconfig", hint: "Default: vuln,misconfig" },
  ],
};

type Mode = "path" | "upload" | "import" | "image";

// Only trivy reads a container image directly. Everything else needs the
// image filesystem exported first.
const IMAGE_NATIVE_TOOLS = ["trivy"];

interface CustomCmd {
  label: string;
  command: string;
}

interface Props {
  onClose: () => void;
}

export default function NewScanModal({ onClose }: Props) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: info } = useQuery({
    queryKey: ["info"],
    queryFn: getInfo,
    // Not cached forever: installing crane from the Tools panel changes
    // whether filesystem extraction is available.
    staleTime: 30_000,
  });
  const isDocker = info?.is_docker ?? false;
  const canExtract = info?.image_extract_available ?? false;
  const extractBackend = info?.image_extract_backend ?? null;

  const [mode, setMode] = useState<Mode>(isDocker ? "upload" : "path");
  const [path, setPath] = useState("");
  const [image, setImage] = useState("");
  const [extractFs, setExtractFs] = useState(false);
  const [label, setLabel] = useState("");
  const [selectedTools, setSelectedTools] = useState<string[]>([...TOOLS]);
  const [selectedConfigs, setSelectedConfigs] = useState<string[]>(["auto"]);
  const [isGitRepo, setIsGitRepo] = useState<boolean | null>(null);
  const gitCheckTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Scanner options state: { toolName: { optionKey: value } }
  const [toolOptions, setToolOptions] = useState<Record<string, Record<string, string | boolean>>>({});
  const [showOptions, setShowOptions] = useState(false);

  // Custom commands state
  const [customCommands, setCustomCommands] = useState<CustomCmd[]>([]);
  const [showCustom, setShowCustom] = useState(false);

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

  const imageMutation = useMutation({
    mutationFn: createImageScan,
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

  const mutation =
    mode === "path"
      ? pathMutation
      : mode === "image"
      ? imageMutation
      : mode === "upload"
      ? uploadMutation
      : importMutation;

  // Without filesystem extraction only trivy can read an image, so drop the
  // tools that would just be skipped server-side.
  useEffect(() => {
    if (mode === "image" && !extractFs) {
      setSelectedTools((prev) => prev.filter((t) => IMAGE_NATIVE_TOOLS.includes(t)));
    }
  }, [mode, extractFs]);

  function toggleExtractFs(on: boolean) {
    setExtractFs(on);
    setSelectedTools(on ? [...TOOLS] : [...IMAGE_NATIVE_TOOLS]);
  }

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

  function setToolOption(tool: string, key: string, value: string | boolean) {
    setToolOptions((prev) => ({
      ...prev,
      [tool]: { ...(prev[tool] || {}), [key]: value },
    }));
  }

  // Build the tool_options payload (only non-empty values)
  function buildToolOptions(): Record<string, Record<string, string | boolean | number>> | undefined {
    const result: Record<string, Record<string, string | boolean | number>> = {};
    let hasAny = false;
    for (const [tool, opts] of Object.entries(toolOptions)) {
      if (!selectedTools.includes(tool)) continue;
      const filtered: Record<string, string | boolean | number> = {};
      for (const [k, v] of Object.entries(opts)) {
        if (v !== "" && v !== false) {
          filtered[k] = v;
          hasAny = true;
        }
      }
      if (Object.keys(filtered).length > 0) result[tool] = filtered;
    }
    return hasAny ? result : undefined;
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (mode === "image") {
      if (!image.trim()) return;
      const cmds = customCommands.filter((c) => c.label.trim() && c.command.trim());
      imageMutation.mutate({
        image: image.trim(),
        label: label.trim() || undefined,
        tools: selectedTools,
        semgrep_configs: selectedConfigs,
        tool_options: buildToolOptions(),
        custom_commands: cmds.length > 0 ? cmds : undefined,
        extract_filesystem: extractFs,
      });
      return;
    }
    if (mode === "path") {
      if (!path.trim()) return;
      const cmds = customCommands.filter((c) => c.label.trim() && c.command.trim());
      pathMutation.mutate({
        path: path.trim(),
        label: label.trim() || undefined,
        tools: selectedTools,
        semgrep_configs: selectedConfigs,
        tool_options: buildToolOptions(),
        custom_commands: cmds.length > 0 ? cmds : undefined,
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
    mode === "path"
      ? !!path.trim()
      : mode === "image"
      ? !!image.trim()
      : mode === "upload"
      ? !!file
      : !!importFile;

  // Check if any tool options have been set (for indicator)
  const hasOptionsSet = Object.values(toolOptions).some((opts) =>
    Object.values(opts).some((v) => v !== "" && v !== false)
  );

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-white border border-zinc-200 dark:bg-zinc-900 dark:border-zinc-700 rounded-lg w-full max-w-lg shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-200 dark:border-zinc-800">
          <h2 className="font-semibold text-lg">New Scan</h2>
          <button onClick={onClose} className="text-zinc-400 hover:text-zinc-700 dark:text-zinc-500 dark:hover:text-zinc-300 transition-colors">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5 overflow-y-auto">
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
              onClick={() => {
                setMode("image");
                setExtractFs(false);
                setSelectedTools([...IMAGE_NATIVE_TOOLS]);
              }}
              className={clsx(
                "flex-1 text-sm py-1.5 rounded-md transition-colors font-medium flex items-center justify-center gap-1.5",
                mode === "image"
                  ? "bg-white dark:bg-zinc-700 text-zinc-800 dark:text-zinc-200 shadow-sm"
                  : "text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300"
              )}
            >
              <Box size={13} />
              Image
            </button>
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

          {mode === "image" ? (
            <div>
              <label className="block text-sm text-zinc-600 dark:text-zinc-400 mb-1.5">Image Reference *</label>
              <input
                type="text"
                value={image}
                onChange={(e) => setImage(e.target.value)}
                placeholder="myorg/myapp:latest"
                className="w-full bg-white border border-zinc-300 dark:bg-zinc-800 dark:border-zinc-700 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-emerald-500 placeholder:text-zinc-400 dark:placeholder:text-zinc-600"
                required={mode === "image"}
                autoFocus
              />
              <p className="text-[11px] text-zinc-400 dark:text-zinc-600 mt-1">
                Docker Hub or any registry — <code className="bg-zinc-100 dark:bg-zinc-800 px-1 rounded">nginx:1.25</code>,{" "}
                <code className="bg-zinc-100 dark:bg-zinc-800 px-1 rounded">ghcr.io/org/app:v2</code> or a{" "}
                <code className="bg-zinc-100 dark:bg-zinc-800 px-1 rounded">@sha256:</code> digest. Trivy pulls it for you; no tag means <code className="bg-zinc-100 dark:bg-zinc-800 px-1 rounded">:latest</code>.
              </p>

              <label
                className={clsx(
                  "flex items-start gap-2 mt-3 select-none",
                  canExtract ? "cursor-pointer" : "cursor-not-allowed opacity-60"
                )}
              >
                <input
                  type="checkbox"
                  checked={extractFs}
                  disabled={!canExtract}
                  onChange={(e) => toggleExtractFs(e.target.checked)}
                  className="accent-emerald-500 mt-0.5"
                />
                <span>
                  <span className="text-sm">Extract image filesystem</span>
                  <span className="block text-[11px] text-zinc-400 dark:text-zinc-600">
                    {canExtract
                      ? `Unpacks the image so the secret scanners and SAST tools can run over its contents (via ${extractBackend}). Slower, and needs disk space.`
                      : "Unavailable — install crane from the Tools panel, or make a Docker daemon reachable. Trivy still scans the image on its own."}
                  </span>
                </span>
              </label>
            </div>
          ) : mode === "path" ? (
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
                      Drop a semgrep, gitleaks, betterleaks, hadolint, bandit, or trivy JSON file
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
                </div>
                <div className="flex gap-3 flex-wrap">
                  {TOOLS.map((tool) => {
                    // In image mode the file-based tools only have something to
                    // read once the filesystem has been extracted.
                    const needsFs = mode === "image" && !IMAGE_NATIVE_TOOLS.includes(tool);
                    const disabled = needsFs && !extractFs;
                    return (
                      <label
                        key={tool}
                        title={disabled ? "Needs image filesystem extraction" : undefined}
                        className={clsx(
                          "flex items-center gap-2 select-none",
                          disabled ? "cursor-not-allowed opacity-40" : "cursor-pointer"
                        )}
                      >
                        <input
                          type="checkbox"
                          checked={selectedTools.includes(tool)}
                          disabled={disabled}
                          onChange={() => toggleTool(tool)}
                          className="accent-emerald-500"
                        />
                        <span className="text-sm font-mono">{tool}</span>
                      </label>
                    );
                  })}
                </div>
                {mode === "image" && (
                  <p className="text-[11px] text-zinc-400 dark:text-zinc-600 mt-1.5">
                    Trivy scans the image directly for vulnerable packages, baked-in secrets and
                    misconfigurations. The other scanners need the filesystem extracted first.
                  </p>
                )}
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

              {/* Scanner Options (collapsible) */}
              <div className="border border-zinc-200 dark:border-zinc-700 rounded-lg">
                <button
                  type="button"
                  onClick={() => setShowOptions(!showOptions)}
                  className="w-full flex items-center justify-between px-4 py-2.5 text-sm text-zinc-600 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200 transition-colors"
                >
                  <span className="flex items-center gap-2">
                    {showOptions ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    Scanner Options
                    {hasOptionsSet && (
                      <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
                    )}
                  </span>
                  <span className="text-xs text-zinc-400 dark:text-zinc-600">Optional</span>
                </button>

                {showOptions && (
                  <div className="px-4 pb-4 space-y-4 border-t border-zinc-100 dark:border-zinc-800 pt-3">
                    {selectedTools.filter((t) => TOOL_OPTIONS[t]).map((tool) => (
                      <div key={tool}>
                        <h4 className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide mb-2">
                          {tool}
                        </h4>
                        <div className="space-y-2">
                          {TOOL_OPTIONS[tool].map((opt) => (
                            <div key={opt.key} className="flex items-start gap-2">
                              {opt.type === "toggle" ? (
                                <label className="flex items-center gap-2 cursor-pointer select-none">
                                  <input
                                    type="checkbox"
                                    checked={!!(toolOptions[tool]?.[opt.key])}
                                    onChange={(e) => setToolOption(tool, opt.key, e.target.checked)}
                                    className="accent-emerald-500"
                                  />
                                  <span className="text-sm">{opt.label}</span>
                                </label>
                              ) : opt.type === "select" ? (
                                <div className="flex-1">
                                  <label className="block text-xs text-zinc-500 dark:text-zinc-500 mb-0.5">{opt.label}</label>
                                  <select
                                    value={String(toolOptions[tool]?.[opt.key] ?? "")}
                                    onChange={(e) => setToolOption(tool, opt.key, e.target.value)}
                                    className="w-full bg-white border border-zinc-300 dark:bg-zinc-800 dark:border-zinc-700 rounded px-2 py-1 text-sm focus:outline-none focus:border-emerald-500"
                                  >
                                    {opt.choices!.map((c) => (
                                      <option key={c.value} value={c.value}>{c.label}</option>
                                    ))}
                                  </select>
                                </div>
                              ) : (
                                <div className="flex-1">
                                  <label className="block text-xs text-zinc-500 dark:text-zinc-500 mb-0.5">{opt.label}</label>
                                  <input
                                    type="text"
                                    value={String(toolOptions[tool]?.[opt.key] ?? "")}
                                    onChange={(e) => setToolOption(tool, opt.key, e.target.value)}
                                    placeholder={opt.placeholder}
                                    className="w-full bg-white border border-zinc-300 dark:bg-zinc-800 dark:border-zinc-700 rounded px-2 py-1 text-sm font-mono focus:outline-none focus:border-emerald-500 placeholder:text-zinc-400 dark:placeholder:text-zinc-600"
                                  />
                                  {opt.hint && (
                                    <p className="text-[11px] text-zinc-400 dark:text-zinc-600 mt-0.5">{opt.hint}</p>
                                  )}
                                </div>
                              )}
                            </div>
                          ))}
                          {/* Extra args freetext for every tool */}
                          <div>
                            <label className="block text-xs text-zinc-500 dark:text-zinc-500 mb-0.5">Extra CLI Flags</label>
                            <input
                              type="text"
                              value={String(toolOptions[tool]?.["extra_args"] ?? "")}
                              onChange={(e) => setToolOption(tool, "extra_args", e.target.value)}
                              placeholder="e.g. --timeout 300 --debug"
                              className="w-full bg-white border border-zinc-300 dark:bg-zinc-800 dark:border-zinc-700 rounded px-2 py-1 text-sm font-mono focus:outline-none focus:border-emerald-500 placeholder:text-zinc-400 dark:placeholder:text-zinc-600"
                            />
                            <p className="text-[11px] text-zinc-400 dark:text-zinc-600 mt-0.5">Raw flags appended to the command</p>
                          </div>
                        </div>
                      </div>
                    ))}
                    {selectedTools.filter((t) => TOOL_OPTIONS[t]).length === 0 && (
                      <p className="text-sm text-zinc-400 dark:text-zinc-600">Select a tool above to configure its options.</p>
                    )}
                  </div>
                )}
              </div>

              {/* Custom Commands (collapsible) */}
              {(mode === "path" || mode === "image") && (
                <div className="border border-zinc-200 dark:border-zinc-700 rounded-lg">
                  <button
                    type="button"
                    onClick={() => setShowCustom(!showCustom)}
                    className="w-full flex items-center justify-between px-4 py-2.5 text-sm text-zinc-600 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200 transition-colors"
                  >
                    <span className="flex items-center gap-2">
                      {showCustom ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      <Terminal size={14} />
                      Custom Commands
                      {customCommands.length > 0 && (
                        <span className="text-xs bg-zinc-200 dark:bg-zinc-700 rounded px-1.5 py-0.5">
                          {customCommands.length}
                        </span>
                      )}
                    </span>
                    <span className="text-xs text-zinc-400 dark:text-zinc-600">Optional</span>
                  </button>

                  {showCustom && (
                    <div className="px-4 pb-4 border-t border-zinc-100 dark:border-zinc-800 pt-3 space-y-3">
                      <p className="text-xs text-zinc-400 dark:text-zinc-600">
                        Run custom scanner commands. Use <code className="bg-zinc-100 dark:bg-zinc-800 px-1 rounded">{"{path}"}</code> for the scan target{mode === "image" && <>, <code className="bg-zinc-100 dark:bg-zinc-800 px-1 rounded">{"{image}"}</code> for the image reference</>} and <code className="bg-zinc-100 dark:bg-zinc-800 px-1 rounded">{"{output}"}</code> for the JSON output file. Output is auto-detected (semgrep/gitleaks/hadolint/bandit/trivy format).
                      </p>

                      {customCommands.map((cmd, idx) => (
                        <div key={idx} className="space-y-1.5 bg-zinc-50 dark:bg-zinc-800/50 rounded p-2.5">
                          <div className="flex gap-2 items-center">
                            <input
                              type="text"
                              value={cmd.label}
                              onChange={(e) => {
                                const updated = [...customCommands];
                                updated[idx] = { ...cmd, label: e.target.value };
                                setCustomCommands(updated);
                              }}
                              placeholder="Label (e.g. eslint-security)"
                              className="flex-1 bg-white border border-zinc-300 dark:bg-zinc-800 dark:border-zinc-700 rounded px-2 py-1 text-sm focus:outline-none focus:border-emerald-500 placeholder:text-zinc-400 dark:placeholder:text-zinc-600"
                            />
                            <button
                              type="button"
                              onClick={() => setCustomCommands(customCommands.filter((_, i) => i !== idx))}
                              className="text-zinc-400 hover:text-red-500 transition-colors p-1"
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                          <input
                            type="text"
                            value={cmd.command}
                            onChange={(e) => {
                              const updated = [...customCommands];
                              updated[idx] = { ...cmd, command: e.target.value };
                              setCustomCommands(updated);
                            }}
                            placeholder="e.g. eslint --format json -o {output} {path}"
                            className="w-full bg-white border border-zinc-300 dark:bg-zinc-800 dark:border-zinc-700 rounded px-2 py-1 text-sm font-mono focus:outline-none focus:border-emerald-500 placeholder:text-zinc-400 dark:placeholder:text-zinc-600"
                          />
                        </div>
                      ))}

                      <button
                        type="button"
                        onClick={() => setCustomCommands([...customCommands, { label: "", command: "" }])}
                        className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 hover:text-emerald-500 transition-colors"
                      >
                        <Plus size={12} /> Add Command
                      </button>
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {mode === "import" && (
            <p className="text-xs text-zinc-400 dark:text-zinc-600">
              The tool type is auto-detected from the JSON structure. Supports semgrep, gitleaks, betterleaks, hadolint, bandit, and trivy output.
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
