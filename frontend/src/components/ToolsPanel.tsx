import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle, Download, RefreshCw, XCircle } from "lucide-react";
import { getTools, updateTool } from "../api/client";

export default function ToolsPanel() {
  const queryClient = useQueryClient();
  const { data: tools = [], isLoading } = useQuery({
    queryKey: ["tools"],
    queryFn: getTools,
  });

  const mutation = useMutation({
    mutationFn: (name: string) => updateTool(name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["tools"] }),
  });

  if (isLoading) {
    return <div className="text-zinc-500 text-sm p-4">Loading tools...</div>;
  }

  return (
    <div className="space-y-2">
      {tools.map((tool) => (
        <div
          key={tool.name}
          className="flex items-center justify-between bg-zinc-50 border border-zinc-200 dark:bg-zinc-800/50 dark:border-zinc-700 rounded-lg px-4 py-3"
        >
          <div className="flex items-center gap-3">
            {tool.installed ? (
              <CheckCircle size={16} className="text-emerald-500 dark:text-emerald-400 shrink-0" />
            ) : (
              <XCircle size={16} className="text-zinc-400 dark:text-zinc-600 shrink-0" />
            )}
            <div>
              <div className="text-sm font-medium font-mono">{tool.name}</div>
              <div className="text-xs text-zinc-500">{tool.description}</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {tool.current_version && (
              <span className="text-xs text-zinc-400 dark:text-zinc-500 font-mono">{tool.current_version}</span>
            )}
            <button
              onClick={() => mutation.mutate(tool.name)}
              disabled={mutation.isPending && mutation.variables === tool.name}
              title={tool.installed ? "Update to latest" : "Download"}
              className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-emerald-500 dark:text-zinc-400 dark:hover:text-emerald-400 disabled:opacity-50 transition-colors"
            >
              {mutation.isPending && mutation.variables === tool.name ? (
                <RefreshCw size={14} className="animate-spin" />
              ) : tool.installed ? (
                <RefreshCw size={14} />
              ) : (
                <Download size={14} />
              )}
              {tool.installed ? "Update" : "Install"}
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
