import {
  AlignmentType,
  BorderStyle,
  Document,
  HeadingLevel,
  Packer,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from "docx";
import { saveAs } from "file-saver";
import type { Finding, Scan, Severity } from "../types";
import type { ExportField, SortOrder } from "../components/ExportModal";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "DC2626",
  HIGH: "EA580C",
  MEDIUM: "CA8A04",
  LOW: "2563EB",
  INFO: "6B7280",
};

const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "FEF2F2",
  HIGH: "FFF7ED",
  MEDIUM: "FEFCE8",
  LOW: "EFF6FF",
  INFO: "F9FAFB",
};

const FIELD_LABELS: Record<ExportField, string> = {
  severity: "Severity",
  tool: "Tool",
  rule_id: "Rule ID",
  rule_name: "Rule Name",
  category: "Category",
  message: "Message",
  file_path: "File Path",
  line_start: "Line Start",
  line_end: "Line End",
  col_start: "Col Start",
  col_end: "Col End",
  matched_code: "Matched Code",
  cwe: "CWE",
  owasp: "OWASP",
  references: "References",
  fingerprint: "Fingerprint",
  commit_hash: "Commit Hash",
  triage_state: "Triage State",
};

function getFieldValue(f: Finding, field: ExportField): string {
  switch (field) {
    case "cwe": return f.cwe?.join(", ") ?? "";
    case "owasp": return f.owasp?.join(", ") ?? "";
    case "references": return f.references?.join(", ") ?? "";
    case "triage_state": return f.triage_state ?? "Open";
    default: {
      const val = f[field as keyof Finding];
      return val === null || val === undefined ? "" : String(val);
    }
  }
}

function sortFindings(findings: Finding[], sortOrder: SortOrder): Finding[] {
  const sorted = [...findings];
  switch (sortOrder) {
    case "severity":
      return sorted.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    case "tool":
      return sorted.sort((a, b) => a.tool.localeCompare(b.tool));
    case "both":
      return sorted.sort((a, b) => {
        const toolCmp = a.tool.localeCompare(b.tool);
        if (toolCmp !== 0) return toolCmp;
        return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      });
  }
}

const THIN_BORDER = {
  top: { style: BorderStyle.SINGLE, size: 1, color: "D1D5DB" },
  bottom: { style: BorderStyle.SINGLE, size: 1, color: "D1D5DB" },
  left: { style: BorderStyle.SINGLE, size: 1, color: "D1D5DB" },
  right: { style: BorderStyle.SINGLE, size: 1, color: "D1D5DB" },
} as const;

const NO_BORDER = {
  top: { style: BorderStyle.NONE, size: 0 },
  bottom: { style: BorderStyle.NONE, size: 0 },
  left: { style: BorderStyle.NONE, size: 0 },
  right: { style: BorderStyle.NONE, size: 0 },
} as const;

// Fields that are rendered inline in text layout (not as separate key:value lines)
const TEXT_SKIP_IN_DETAIL: Set<ExportField> = new Set([
  "severity", "tool", "rule_id", "rule_name", "message", "file_path",
  "line_start", "line_end", "col_start", "col_end", "matched_code",
]);

function buildCodeParagraphs(f: Finding): Paragraph[] {
  if (f.code_context && f.code_context.lines.length > 0) {
    const { lines, start_line, highlight_start, highlight_end } = f.code_context;
    return lines.map((line, i) => {
      const lineNum = start_line + i;
      const isHL = lineNum >= highlight_start && lineNum <= highlight_end;
      return new Paragraph({
        spacing: { before: 0, after: 0, line: 260 },
        shading: isHL
          ? { type: ShadingType.CLEAR, fill: "FEF9C3" }
          : { type: ShadingType.CLEAR, fill: "F8FAFC" },
        children: [
          new TextRun({
            text: `${String(lineNum).padStart(4, " ")} | `,
            font: "Consolas",
            size: 16,
            color: "9CA3AF",
          }),
          new TextRun({
            text: line,
            font: "Consolas",
            size: 16,
            bold: isHL,
          }),
        ],
      });
    });
  }

  if (f.matched_code) {
    return [
      new Paragraph({
        spacing: { before: 0, after: 0, line: 260 },
        shading: { type: ShadingType.CLEAR, fill: "F8FAFC" },
        children: [
          new TextRun({ text: f.matched_code, font: "Consolas", size: 16 }),
        ],
      }),
    ];
  }

  return [];
}

function buildTextFinding(f: Finding, fields: ExportField[], index: number): Paragraph[] {
  const hasField = (field: ExportField) => fields.includes(field);
  const paragraphs: Paragraph[] = [];

  // Title line: #N  SEVERITY  [tool]  rule_id (rule_name)
  const titleRuns: TextRun[] = [
    new TextRun({ text: `#${index}  `, color: "9CA3AF", size: 22 }),
  ];
  if (hasField("severity")) {
    titleRuns.push(new TextRun({
      text: ` ${f.severity} `,
      bold: true,
      color: SEVERITY_COLORS[f.severity],
      shading: { type: ShadingType.CLEAR, fill: SEVERITY_BG[f.severity] },
      size: 22,
    }));
    titleRuns.push(new TextRun({ text: "  ", size: 22 }));
  }
  if (hasField("tool")) {
    titleRuns.push(new TextRun({ text: `[${f.tool}]`, color: "4B5563", size: 22 }));
    titleRuns.push(new TextRun({ text: "  ", size: 22 }));
  }
  if (hasField("rule_id")) {
    titleRuns.push(new TextRun({ text: f.rule_id, bold: true, font: "Consolas", size: 22, color: "000000" }));
  }
  if (hasField("rule_name") && f.rule_name) {
    titleRuns.push(new TextRun({ text: `  (${f.rule_name})`, color: "6B7280", size: 22 }));
  }
  paragraphs.push(new Paragraph({
    spacing: { before: 240, after: 60 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 1, color: "E5E7EB" } },
    children: titleRuns,
  }));

  // Message
  if (hasField("message")) {
    paragraphs.push(new Paragraph({
      spacing: { before: 60, after: 80 },
      children: [new TextRun({ text: f.message, size: 22, color: "000000" })],
    }));
  }

  // Location
  if (hasField("file_path")) {
    let loc = f.file_path;
    if (hasField("line_start") && f.line_start) {
      loc += `:${f.line_start}`;
      if (hasField("line_end") && f.line_end && f.line_end !== f.line_start) {
        loc += `-${f.line_end}`;
      }
    }
    paragraphs.push(new Paragraph({
      spacing: { before: 40, after: 80 },
      children: [new TextRun({ text: loc, font: "Consolas", size: 20, bold: true, color: "000000" })],
    }));
  }

  // Code block
  if (hasField("matched_code")) {
    paragraphs.push(...buildCodeParagraphs(f));
  }

  // Extra metadata
  for (const field of fields) {
    if (TEXT_SKIP_IN_DETAIL.has(field)) continue;
    const val = getFieldValue(f, field);
    if (!val) continue;
    paragraphs.push(new Paragraph({
      spacing: { before: 20, after: 20 },
      children: [
        new TextRun({ text: `${FIELD_LABELS[field]}: `, bold: true, size: 20, color: "4B5563" }),
        new TextRun({ text: val, size: 20, color: "000000" }),
      ],
    }));
  }

  return paragraphs;
}

function buildTableExport(findings: Finding[], fields: ExportField[]): Table {
  const headerCells = fields.map(
    (field) =>
      new TableCell({
        shading: { type: ShadingType.CLEAR, fill: "F3F4F6" },
        borders: THIN_BORDER,
        children: [
          new Paragraph({
            children: [
              new TextRun({ text: FIELD_LABELS[field], bold: true, size: 20, color: "000000" }),
            ],
          }),
        ],
      })
  );

  const rows = [new TableRow({ children: headerCells })];

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const rowBg = i % 2 === 1 ? "F9FAFB" : "FFFFFF";

    const cells = fields.map((field) => {
      const children: Paragraph[] = [];

      if (field === "severity") {
        children.push(
          new Paragraph({
            children: [
              new TextRun({
                text: f.severity,
                bold: true,
                color: SEVERITY_COLORS[f.severity],
                size: 20,
              }),
            ],
          })
        );
      } else if (field === "matched_code") {
        const codeParagraphs = buildCodeParagraphs(f);
        if (codeParagraphs.length > 0) {
          children.push(...codeParagraphs);
        } else {
          children.push(new Paragraph({ children: [] }));
        }
      } else {
        children.push(
          new Paragraph({
            children: [new TextRun({ text: getFieldValue(f, field), size: 20, color: "000000" })],
          })
        );
      }

      return new TableCell({
        shading: { type: ShadingType.CLEAR, fill: rowBg },
        borders: THIN_BORDER,
        children,
      });
    });

    rows.push(new TableRow({ children: cells }));
  }

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows,
  });
}

function buildSummaryTable(findings: Finding[]): Table {
  const severities: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const rows: TableRow[] = [
    new TableRow({
      children: [
        new TableCell({
          shading: { type: ShadingType.CLEAR, fill: "F3F4F6" },
          borders: THIN_BORDER,
          children: [new Paragraph({ children: [new TextRun({ text: "Severity", bold: true, size: 20, color: "000000" })] })],
        }),
        new TableCell({
          shading: { type: ShadingType.CLEAR, fill: "F3F4F6" },
          borders: THIN_BORDER,
          children: [new Paragraph({ children: [new TextRun({ text: "Count", bold: true, size: 20, color: "000000" })] })],
        }),
      ],
    }),
  ];

  for (const sev of severities) {
    const count = findings.filter((f) => f.severity === sev).length;
    if (count === 0) continue;
    rows.push(
      new TableRow({
        children: [
          new TableCell({
            borders: THIN_BORDER,
            shading: { type: ShadingType.CLEAR, fill: SEVERITY_BG[sev] },
            children: [
              new Paragraph({
                children: [new TextRun({ text: sev, bold: true, color: SEVERITY_COLORS[sev], size: 20 })],
              }),
            ],
          }),
          new TableCell({
            borders: THIN_BORDER,
            children: [
              new Paragraph({
                children: [new TextRun({ text: String(count), bold: true, size: 20, color: "000000" })],
              }),
            ],
          }),
        ],
      })
    );
  }

  return new Table({
    width: { size: 40, type: WidthType.PERCENTAGE },
    rows,
  });
}

export type DocxLayout = "text" | "table";

export async function exportFindingsToDocx(
  scan: Scan,
  findings: Finding[],
  fields: ExportField[],
  sortOrder: SortOrder,
  layout: DocxLayout = "text"
) {
  const sorted = sortFindings(findings, sortOrder);
  const scanName = scan.label ?? scan.path.split(/[/\\]/).pop() ?? `scan-${scan.id}`;
  const date = new Date(scan.started_at).toLocaleDateString();
  const groupByTool = sortOrder === "tool" || sortOrder === "both";

  // Build document sections
  const children: (Paragraph | Table)[] = [];

  // Title
  children.push(
    new Paragraph({
      heading: HeadingLevel.HEADING_1,
      children: [new TextRun({ text: "SAST Findings Report" })],
    })
  );

  // Metadata
  children.push(
    new Paragraph({
      spacing: { after: 200 },
      children: [
        new TextRun({ text: "Scan: ", bold: true, size: 22, color: "4B5563" }),
        new TextRun({ text: scanName, size: 22, color: "000000" }),
        new TextRun({ text: "  |  ", size: 22, color: "9CA3AF" }),
        new TextRun({ text: "Date: ", bold: true, size: 22, color: "4B5563" }),
        new TextRun({ text: date, size: 22, color: "000000" }),
        new TextRun({ text: "  |  ", size: 22, color: "9CA3AF" }),
        new TextRun({ text: "Findings: ", bold: true, size: 22, color: "4B5563" }),
        new TextRun({ text: String(findings.length), size: 22, color: "000000" }),
      ],
    })
  );

  // Summary table
  children.push(buildSummaryTable(findings));
  children.push(new Paragraph({ spacing: { after: 200 }, children: [] }));

  // Findings
  if (groupByTool) {
    const toolMap = new Map<string, Finding[]>();
    for (const f of sorted) {
      if (!toolMap.has(f.tool)) toolMap.set(f.tool, []);
      toolMap.get(f.tool)!.push(f);
    }

    for (const [tool, toolFindings] of toolMap) {
      children.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_2,
          spacing: { before: 360, after: 120 },
          border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: "E5E7EB" } },
          children: [
            new TextRun({
              text: `${tool} (${toolFindings.length} finding${toolFindings.length !== 1 ? "s" : ""})`,
            }),
          ],
        })
      );

      if (layout === "table") {
        children.push(buildTableExport(toolFindings, fields));
      } else {
        let idx = 1;
        for (const f of toolFindings) {
          children.push(...buildTextFinding(f, fields, idx++));
        }
      }
    }
  } else {
    if (layout === "table") {
      children.push(buildTableExport(sorted, fields));
    } else {
      for (let i = 0; i < sorted.length; i++) {
        children.push(...buildTextFinding(sorted[i], fields, i + 1));
      }
    }
  }

  const doc = new Document({
    styles: {
      default: {
        document: {
          run: { font: "Calibri", size: 22 },
        },
      },
    },
    sections: [{ children }],
  });

  const blob = await Packer.toBlob(doc);

  const safeName = (scan.label ?? scan.path.split(/[/\\]/).pop() ?? `scan-${scan.id}`)
    .replace(/[^a-z0-9_-]/gi, "_")
    .toLowerCase();
  const fileDate = new Date(scan.started_at).toISOString().slice(0, 10);
  const filename = `sasty_${safeName}_${fileDate}.docx`;

  saveAs(blob, filename);
}
