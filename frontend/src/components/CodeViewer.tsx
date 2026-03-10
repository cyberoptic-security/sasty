import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneLight } from "react-syntax-highlighter/dist/esm/styles/prism";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import { useTheme } from "../contexts/ThemeContext";
import type { CodeContext } from "../types";

interface Props {
  context: CodeContext;
  filePath: string;
}

function guessLanguage(filePath: string): string {
  const ext = filePath.split(".").pop()?.toLowerCase();
  const map: Record<string, string> = {
    ts: "typescript",
    tsx: "tsx",
    js: "javascript",
    jsx: "jsx",
    mjs: "javascript",
    cjs: "javascript",
    json: "json",
    yaml: "yaml",
    yml: "yaml",
    dockerfile: "docker",
    sh: "bash",
    md: "markdown",
  };
  if (filePath.toLowerCase().includes("dockerfile")) return "docker";
  return map[ext ?? ""] ?? "text";
}

export default function CodeViewer({ context, filePath }: Props) {
  const { dark } = useTheme();
  const { lines, start_line, highlight_start, highlight_end } = context;
  const lang = guessLanguage(filePath);

  const lineProps = (lineNum: number) => {
    const absolute = start_line + lineNum - 1;
    const isHighlighted = absolute >= highlight_start && absolute <= highlight_end;
    return {
      style: isHighlighted
        ? { backgroundColor: dark ? "rgba(234, 179, 8, 0.12)" : "rgba(234, 179, 8, 0.18)", display: "block", width: "100%" }
        : { display: "block", width: "100%" },
    };
  };

  return (
    <div className="rounded-md overflow-hidden border border-zinc-200 dark:border-zinc-800 text-xs font-mono">
      <SyntaxHighlighter
        language={lang}
        style={dark ? vscDarkPlus : oneLight}
        showLineNumbers
        startingLineNumber={start_line}
        wrapLines
        lineProps={lineProps}
        customStyle={{
          margin: 0,
          padding: "0.75rem",
          background: dark ? "#0f0f0f" : "#fafafa",
          fontSize: "0.78rem",
        }}
        lineNumberStyle={{
          minWidth: "3em",
          paddingRight: "1em",
          color: dark ? "#4b5563" : "#9ca3af",
          userSelect: "none",
        }}
      >
        {lines.join("\n")}
      </SyntaxHighlighter>
    </div>
  );
}
