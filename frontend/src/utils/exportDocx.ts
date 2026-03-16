import {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  Header,
  Packer,
  PageBreak,
  PageNumber,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
  convertInchesToTwip,
} from "docx";
import { saveAs } from "file-saver";
import type { Finding, Scan, Severity } from "../types";
import type { ExportField, SortOrder } from "../components/ExportModal";

/* ── Palette ─────────────────────────────────────────────────────────── */

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

const SEV = {
  CRITICAL: { fg: "FFFFFF", bg: "991B1B", accent: "DC2626", light: "FEF2F2" },
  HIGH:     { fg: "FFFFFF", bg: "9A3412", accent: "EA580C", light: "FFF7ED" },
  MEDIUM:   { fg: "FFFFFF", bg: "854D0E", accent: "CA8A04", light: "FEFCE8" },
  LOW:      { fg: "FFFFFF", bg: "1E40AF", accent: "2563EB", light: "EFF6FF" },
  INFO:     { fg: "FFFFFF", bg: "4B5563", accent: "6B7280", light: "F9FAFB" },
} as const;

const BRAND = {
  primary:    "1E40AF",   // deep blue
  primaryLt:  "DBEAFE",   // light blue tint
  dark:       "111827",   // near-black for headings
  body:       "374151",   // dark gray for body text
  muted:      "6B7280",   // medium gray for labels
  subtle:     "9CA3AF",   // lighter gray for separators
  ruleLine:   "E5E7EB",   // very light gray rule line
  pageBg:     "FFFFFF",
  stripeBg:   "F9FAFB",   // alternating row stripe
  codeBg:     "F1F5F9",   // code block background (slate-100)
  codeHL:     "FEF9C3",   // highlighted code line (yellow-100)
  headerBg:   "1E3A5F",   // dark blue header bar
  headerFg:   "FFFFFF",
};

const FONT = {
  heading: "Segoe UI",
  body:    "Segoe UI",
  mono:    "Cascadia Code",
};

const FIELD_LABELS: Record<ExportField, string> = {
  severity: "Severity", tool: "Tool", rule_id: "Rule ID", rule_name: "Rule Name",
  category: "Category", message: "Message", file_path: "File Path",
  line_start: "Line Start", line_end: "Line End", col_start: "Col Start",
  col_end: "Col End", matched_code: "Matched Code", cwe: "CWE",
  owasp: "OWASP", references: "References", fingerprint: "Fingerprint",
  commit_hash: "Commit Hash", commit_author: "Commit Author",
  commit_date: "Commit Date", triage_state: "Triage State",
};

/* ── Helpers ──────────────────────────────────────────────────────────── */

function getFieldValue(f: Finding, field: ExportField): string {
  switch (field) {
    case "cwe":        return f.cwe?.join(", ") ?? "";
    case "owasp":      return f.owasp?.join(", ") ?? "";
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

/* ── Border presets ───────────────────────────────────────────────────── */

const THIN_BORDER = {
  top:    { style: BorderStyle.SINGLE, size: 1, color: BRAND.ruleLine },
  bottom: { style: BorderStyle.SINGLE, size: 1, color: BRAND.ruleLine },
  left:   { style: BorderStyle.SINGLE, size: 1, color: BRAND.ruleLine },
  right:  { style: BorderStyle.SINGLE, size: 1, color: BRAND.ruleLine },
} as const;

const NO_BORDER = {
  top:    { style: BorderStyle.NONE, size: 0 },
  bottom: { style: BorderStyle.NONE, size: 0 },
  left:   { style: BorderStyle.NONE, size: 0 },
  right:  { style: BorderStyle.NONE, size: 0 },
} as const;

/** Fields that vary per instance (shown for each occurrence). */
const INSTANCE_FIELDS: Set<ExportField> = new Set([
  "file_path", "line_start", "line_end", "col_start", "col_end",
  "matched_code", "fingerprint", "commit_hash", "commit_author",
  "commit_date", "triage_state",
]);

interface ExportGroup {
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
}

function groupFindings(findings: Finding[]): ExportGroup[] {
  const map = new Map<string, ExportGroup>();
  for (const f of findings) {
    const key = `${f.rule_id}__${f.tool}`;
    if (!map.has(key)) {
      map.set(key, {
        rule_id: f.rule_id,
        rule_name: f.rule_name,
        severity: f.severity,
        tool: f.tool,
        category: f.category,
        message: f.message,
        cwe: f.cwe,
        owasp: f.owasp,
        references: f.references,
        findings: [],
      });
    }
    map.get(key)!.findings.push(f);
  }
  return [...map.values()];
}

/* ── Title page / header elements ─────────────────────────────────────── */

function buildCoverSection(scanName: string, date: string, findingCount: number): (Paragraph | Table)[] {
  const items: (Paragraph | Table)[] = [];

  // Spacer
  items.push(new Paragraph({ spacing: { after: 600 }, children: [] }));

  // Accent line
  items.push(new Paragraph({
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: BRAND.primary } },
    spacing: { after: 200 },
    children: [],
  }));

  // Main title
  items.push(new Paragraph({
    spacing: { after: 80 },
    children: [
      new TextRun({
        text: "SAST Findings Report",
        font: FONT.heading,
        size: 52, // 26pt
        bold: true,
        color: BRAND.dark,
      }),
    ],
  }));

  // Subtitle / scan name
  items.push(new Paragraph({
    spacing: { after: 300 },
    children: [
      new TextRun({
        text: scanName,
        font: FONT.heading,
        size: 28, // 14pt
        color: BRAND.muted,
      }),
    ],
  }));

  // Accent line
  items.push(new Paragraph({
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: BRAND.primary } },
    spacing: { after: 400 },
    children: [],
  }));

  // Metadata table (clean, no-border key-value pairs)
  const metaRows: { label: string; value: string }[] = [
    { label: "Date", value: date },
    { label: "Total Findings", value: String(findingCount) },
    { label: "Generated by", value: "Sasty SAST Scanner" },
  ];

  for (const { label, value } of metaRows) {
    items.push(new Paragraph({
      spacing: { before: 60, after: 60 },
      children: [
        new TextRun({ text: `${label}:  `, font: FONT.body, size: 22, color: BRAND.muted, bold: true }),
        new TextRun({ text: value, font: FONT.body, size: 22, color: BRAND.body }),
      ],
    }));
  }

  return items;
}

/* ── Summary table ────────────────────────────────────────────────────── */

function buildSummaryTable(findings: Finding[]): (Paragraph | Table)[] {
  const items: (Paragraph | Table)[] = [];

  items.push(new Paragraph({
    spacing: { before: 400, after: 200 },
    children: [
      new TextRun({
        text: "Executive Summary",
        font: FONT.heading,
        size: 32, // 16pt
        bold: true,
        color: BRAND.dark,
      }),
    ],
  }));

  items.push(new Paragraph({
    border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: BRAND.primary } },
    spacing: { after: 200 },
    children: [],
  }));

  const severities: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

  // Header row
  const headerCells = [
    new TableCell({
      shading: { type: ShadingType.CLEAR, fill: BRAND.headerBg },
      borders: THIN_BORDER,
      width: { size: 50, type: WidthType.PERCENTAGE },
      children: [new Paragraph({
        spacing: { before: 60, after: 60 },
        children: [new TextRun({ text: "Severity", bold: true, font: FONT.heading, size: 20, color: BRAND.headerFg })],
      })],
    }),
    new TableCell({
      shading: { type: ShadingType.CLEAR, fill: BRAND.headerBg },
      borders: THIN_BORDER,
      width: { size: 25, type: WidthType.PERCENTAGE },
      children: [new Paragraph({
        spacing: { before: 60, after: 60 },
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Count", bold: true, font: FONT.heading, size: 20, color: BRAND.headerFg })],
      })],
    }),
    new TableCell({
      shading: { type: ShadingType.CLEAR, fill: BRAND.headerBg },
      borders: THIN_BORDER,
      width: { size: 25, type: WidthType.PERCENTAGE },
      children: [new Paragraph({
        spacing: { before: 60, after: 60 },
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "% of Total", bold: true, font: FONT.heading, size: 20, color: BRAND.headerFg })],
      })],
    }),
  ];

  const rows: TableRow[] = [new TableRow({ children: headerCells })];

  for (const sev of severities) {
    const count = findings.filter((f) => f.severity === sev).length;
    if (count === 0) continue;
    const pct = ((count / findings.length) * 100).toFixed(1);

    rows.push(new TableRow({
      children: [
        new TableCell({
          borders: THIN_BORDER,
          shading: { type: ShadingType.CLEAR, fill: SEV[sev].light },
          children: [new Paragraph({
            spacing: { before: 50, after: 50 },
            children: [
              new TextRun({
                text: `  ${sev}`,
                bold: true,
                color: SEV[sev].accent,
                font: FONT.heading,
                size: 20,
              }),
            ],
          })],
        }),
        new TableCell({
          borders: THIN_BORDER,
          shading: { type: ShadingType.CLEAR, fill: SEV[sev].light },
          children: [new Paragraph({
            spacing: { before: 50, after: 50 },
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ text: String(count), bold: true, font: FONT.body, size: 20, color: BRAND.body })],
          })],
        }),
        new TableCell({
          borders: THIN_BORDER,
          shading: { type: ShadingType.CLEAR, fill: SEV[sev].light },
          children: [new Paragraph({
            spacing: { before: 50, after: 50 },
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ text: `${pct}%`, font: FONT.body, size: 20, color: BRAND.muted })],
          })],
        }),
      ],
    }));
  }

  // Total row
  rows.push(new TableRow({
    children: [
      new TableCell({
        borders: THIN_BORDER,
        shading: { type: ShadingType.CLEAR, fill: "F3F4F6" },
        children: [new Paragraph({
          spacing: { before: 50, after: 50 },
          children: [new TextRun({ text: "  TOTAL", bold: true, font: FONT.heading, size: 20, color: BRAND.dark })],
        })],
      }),
      new TableCell({
        borders: THIN_BORDER,
        shading: { type: ShadingType.CLEAR, fill: "F3F4F6" },
        children: [new Paragraph({
          spacing: { before: 50, after: 50 },
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: String(findings.length), bold: true, font: FONT.body, size: 20, color: BRAND.dark })],
        })],
      }),
      new TableCell({
        borders: THIN_BORDER,
        shading: { type: ShadingType.CLEAR, fill: "F3F4F6" },
        children: [new Paragraph({
          spacing: { before: 50, after: 50 },
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "100%", font: FONT.body, size: 20, color: BRAND.muted })],
        })],
      }),
    ],
  }));

  items.push(new Table({
    width: { size: 60, type: WidthType.PERCENTAGE },
    rows,
  }));

  return items;
}

/* ── Code block rendering ────────────────────────────────────────────── */

function buildCodeParagraphs(f: Finding): Paragraph[] {
  if (f.code_context && f.code_context.lines.length > 0) {
    const { lines, start_line, highlight_start, highlight_end } = f.code_context;
    const paras: Paragraph[] = [];

    // Code header bar
    paras.push(new Paragraph({
      spacing: { before: 120, after: 0 },
      shading: { type: ShadingType.CLEAR, fill: "334155" }, // slate-700
      children: [
        new TextRun({
          text: "  Code Context",
          font: FONT.mono,
          size: 15,
          color: "94A3B8",
          bold: true,
        }),
      ],
    }));

    for (let i = 0; i < lines.length; i++) {
      const lineNum = start_line + i;
      const isHL = lineNum >= highlight_start && lineNum <= highlight_end;
      paras.push(new Paragraph({
        spacing: { before: 0, after: 0, line: 264 },
        shading: { type: ShadingType.CLEAR, fill: isHL ? BRAND.codeHL : BRAND.codeBg },
        border: isHL
          ? { left: { style: BorderStyle.SINGLE, size: 6, color: SEV.MEDIUM.accent } }
          : undefined,
        children: [
          new TextRun({
            text: ` ${String(lineNum).padStart(4, " ")}  `,
            font: FONT.mono,
            size: 16, // 8pt
            color: "94A3B8", // slate-400
          }),
          new TextRun({
            text: isHL ? "| " : "  ",
            font: FONT.mono,
            size: 16,
            color: isHL ? SEV.MEDIUM.accent : "CBD5E1",
          }),
          new TextRun({
            text: lines[i],
            font: FONT.mono,
            size: 16,
            bold: isHL,
            color: isHL ? BRAND.dark : BRAND.body,
          }),
        ],
      }));
    }

    // Bottom border for code block
    paras.push(new Paragraph({
      spacing: { before: 0, after: 120 },
      border: { top: { style: BorderStyle.SINGLE, size: 1, color: "CBD5E1" } },
      children: [],
    }));

    return paras;
  }

  if (f.matched_code) {
    return [
      new Paragraph({
        spacing: { before: 80, after: 0 },
        shading: { type: ShadingType.CLEAR, fill: "334155" },
        children: [
          new TextRun({ text: "  Code", font: FONT.mono, size: 15, color: "94A3B8", bold: true }),
        ],
      }),
      new Paragraph({
        spacing: { before: 0, after: 80, line: 264 },
        shading: { type: ShadingType.CLEAR, fill: BRAND.codeBg },
        children: [
          new TextRun({ text: `  ${f.matched_code}`, font: FONT.mono, size: 16, color: BRAND.body }),
        ],
      }),
    ];
  }

  return [];
}

/* ── Grouped text layout ─────────────────────────────────────────────── */

function buildGroupHeader(group: ExportGroup, fields: ExportField[], index: number): Paragraph[] {
  const hasField = (field: ExportField) => fields.includes(field);
  const paragraphs: Paragraph[] = [];
  const sev = SEV[group.severity];
  const instanceCount = group.findings.length;

  // ── Header bar: severity badge + title + tool + instance count ──
  const headerRuns: TextRun[] = [];

  if (hasField("severity")) {
    headerRuns.push(new TextRun({
      text: ` ${group.severity} `,
      bold: true,
      font: FONT.heading,
      size: 20,
      color: sev.fg,
      shading: { type: ShadingType.CLEAR, fill: sev.bg },
    }));
    headerRuns.push(new TextRun({ text: "  ", size: 20 }));
  }

  headerRuns.push(new TextRun({
    text: group.rule_name || group.rule_id || `Finding #${index}`,
    font: FONT.heading,
    size: 20,
    bold: true,
    color: BRAND.dark,
  }));

  if (hasField("tool")) {
    headerRuns.push(new TextRun({
      text: `    ${group.tool}`,
      font: FONT.body,
      size: 20,
      color: BRAND.muted,
      italics: true,
    }));
  }

  headerRuns.push(new TextRun({
    text: `    ${instanceCount} instance${instanceCount !== 1 ? "s" : ""}`,
    font: FONT.body,
    size: 18,
    color: BRAND.subtle,
  }));

  paragraphs.push(new Paragraph({
    spacing: { before: 320, after: 100 },
    shading: { type: ShadingType.CLEAR, fill: sev.light },
    border: {
      left: { style: BorderStyle.SINGLE, size: 8, color: sev.accent },
      bottom: { style: BorderStyle.SINGLE, size: 1, color: BRAND.ruleLine },
    },
    children: headerRuns,
  }));

  // ── Rule ID ──
  if (hasField("rule_id")) {
    paragraphs.push(new Paragraph({
      spacing: { before: 60, after: 60 },
      children: [new TextRun({
        text: group.rule_id,
        font: FONT.mono,
        size: 20,
        bold: true,
        color: BRAND.primary,
      })],
    }));
  }

  // ── Message ──
  if (hasField("message") && group.message) {
    paragraphs.push(new Paragraph({
      spacing: { before: 60, after: 100 },
      children: [new TextRun({
        text: group.message,
        font: FONT.body,
        size: 21,
        color: BRAND.body,
      })],
    }));
  }

  // ── Group-level metadata (category, CWE, OWASP, references) ──
  const groupMeta: { label: string; val: string }[] = [];
  if (hasField("category") && group.category) {
    groupMeta.push({ label: "Category", val: group.category });
  }
  if (hasField("cwe") && group.cwe?.length) {
    groupMeta.push({ label: "CWE", val: group.cwe.join(", ") });
  }
  if (hasField("owasp") && group.owasp?.length) {
    groupMeta.push({ label: "OWASP", val: group.owasp.join(", ") });
  }
  if (hasField("references") && group.references?.length) {
    groupMeta.push({ label: "References", val: group.references.join(", ") });
  }

  for (const { label, val } of groupMeta) {
    paragraphs.push(new Paragraph({
      spacing: { before: 20, after: 20 },
      indent: { left: convertInchesToTwip(0.15) },
      children: [
        new TextRun({ text: `${label}:  `, font: FONT.body, bold: true, size: 19, color: BRAND.muted }),
        new TextRun({ text: val, font: FONT.body, size: 19, color: BRAND.body }),
      ],
    }));
  }

  return paragraphs;
}

function buildGroupInstance(f: Finding, fields: ExportField[], instanceNum: number): Paragraph[] {
  const hasField = (field: ExportField) => fields.includes(field);
  const paragraphs: Paragraph[] = [];

  // ── Instance sub-header ──
  const subRuns: TextRun[] = [
    new TextRun({
      text: `Instance ${instanceNum}`,
      font: FONT.heading,
      size: 18,
      bold: true,
      color: BRAND.muted,
    }),
  ];

  if (hasField("triage_state") && f.triage_state) {
    const labels: Record<string, string> = {
      false_positive: "False Positive",
      test_dev: "Test / Dev",
      reported: "Reported",
    };
    subRuns.push(new TextRun({
      text: `  \u2014  ${labels[f.triage_state] ?? f.triage_state}`,
      font: FONT.body,
      size: 18,
      color: BRAND.subtle,
      italics: true,
    }));
  }

  paragraphs.push(new Paragraph({
    spacing: { before: 180, after: 60 },
    indent: { left: convertInchesToTwip(0.2) },
    border: { bottom: { style: BorderStyle.SINGLE, size: 1, color: BRAND.ruleLine } },
    children: subRuns,
  }));

  // ── Location ──
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
      indent: { left: convertInchesToTwip(0.2) },
      shading: { type: ShadingType.CLEAR, fill: BRAND.codeBg },
      children: [
        new TextRun({ text: "  \uD83D\uDCC4 ", font: FONT.body, size: 18 }),
        new TextRun({
          text: loc,
          font: FONT.mono,
          size: 18,
          color: BRAND.primary,
          bold: true,
        }),
      ],
    }));
  }

  // ── Code block ──
  if (hasField("matched_code")) {
    paragraphs.push(...buildCodeParagraphs(f));
  }

  // ── Instance-level metadata ──
  const instanceMeta = fields
    .filter((field) => INSTANCE_FIELDS.has(field) && !new Set(["file_path", "line_start", "line_end", "col_start", "col_end", "matched_code", "triage_state"]).has(field))
    .map((field) => ({ field, val: getFieldValue(f, field) }))
    .filter(({ val }) => val);

  for (const { field, val } of instanceMeta) {
    paragraphs.push(new Paragraph({
      spacing: { before: 20, after: 20 },
      indent: { left: convertInchesToTwip(0.35) },
      children: [
        new TextRun({ text: `${FIELD_LABELS[field]}:  `, font: FONT.body, bold: true, size: 18, color: BRAND.muted }),
        new TextRun({ text: val, font: FONT.body, size: 18, color: BRAND.body }),
      ],
    }));
  }

  return paragraphs;
}

function buildTextGroup(group: ExportGroup, fields: ExportField[], groupIndex: number): Paragraph[] {
  const paragraphs: Paragraph[] = [];

  paragraphs.push(...buildGroupHeader(group, fields, groupIndex));

  for (let i = 0; i < group.findings.length; i++) {
    paragraphs.push(...buildGroupInstance(group.findings[i], fields, i + 1));
  }

  return paragraphs;
}

/* ── Table layout ────────────────────────────────────────────────────── */

function buildTableExport(findings: Finding[], fields: ExportField[]): Table {
  // Header row
  const headerCells = fields.map((field) =>
    new TableCell({
      shading: { type: ShadingType.CLEAR, fill: BRAND.headerBg },
      borders: THIN_BORDER,
      children: [new Paragraph({
        spacing: { before: 60, after: 60 },
        children: [new TextRun({
          text: FIELD_LABELS[field],
          bold: true,
          font: FONT.heading,
          size: 18,
          color: BRAND.headerFg,
        })],
      })],
    })
  );

  const rows = [new TableRow({ children: headerCells })];

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const rowBg = i % 2 === 1 ? BRAND.stripeBg : BRAND.pageBg;

    const cells = fields.map((field) => {
      const children: Paragraph[] = [];

      if (field === "severity") {
        children.push(new Paragraph({
          spacing: { before: 40, after: 40 },
          children: [new TextRun({
            text: ` ${f.severity} `,
            bold: true,
            color: SEV[f.severity].fg,
            font: FONT.heading,
            size: 18,
            shading: { type: ShadingType.CLEAR, fill: SEV[f.severity].bg },
          })],
        }));
      } else if (field === "matched_code") {
        const codeParagraphs = buildCodeParagraphs(f);
        if (codeParagraphs.length > 0) {
          children.push(...codeParagraphs);
        } else {
          children.push(new Paragraph({ children: [] }));
        }
      } else if (field === "file_path") {
        children.push(new Paragraph({
          spacing: { before: 40, after: 40 },
          children: [new TextRun({
            text: getFieldValue(f, field),
            font: FONT.mono,
            size: 17,
            color: BRAND.primary,
          })],
        }));
      } else if (field === "rule_id") {
        children.push(new Paragraph({
          spacing: { before: 40, after: 40 },
          children: [new TextRun({
            text: getFieldValue(f, field),
            font: FONT.mono,
            size: 17,
            color: BRAND.body,
            bold: true,
          })],
        }));
      } else {
        children.push(new Paragraph({
          spacing: { before: 40, after: 40 },
          children: [new TextRun({
            text: getFieldValue(f, field),
            font: FONT.body,
            size: 18,
            color: BRAND.body,
          })],
        }));
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

/* ── Tool group heading ──────────────────────────────────────────────── */

function buildToolHeading(tool: string, count: number): Paragraph[] {
  return [
    new Paragraph({
      spacing: { before: 500, after: 60 },
      children: [new TextRun({
        text: tool,
        font: FONT.heading,
        size: 28, // 14pt
        bold: true,
        color: BRAND.dark,
      })],
    }),
    new Paragraph({
      spacing: { after: 40 },
      children: [new TextRun({
        text: `${count} finding${count !== 1 ? "s" : ""}`,
        font: FONT.body,
        size: 20,
        color: BRAND.muted,
        italics: true,
      })],
    }),
    new Paragraph({
      border: { bottom: { style: BorderStyle.SINGLE, size: 3, color: BRAND.primary } },
      spacing: { after: 160 },
      children: [],
    }),
  ];
}

/* ── Main export function ────────────────────────────────────────────── */

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
  const date = new Date(scan.started_at).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric",
  });
  const groupByTool = sortOrder === "tool" || sortOrder === "both";

  // ── Cover page content ──
  const coverChildren = buildCoverSection(scanName, date, findings.length);

  // ── Summary section ──
  const summaryChildren = buildSummaryTable(findings);

  // ── Findings section ──
  const findingsChildren: (Paragraph | Table)[] = [];

  // Section title
  findingsChildren.push(new Paragraph({
    spacing: { before: 400, after: 200 },
    children: [new TextRun({
      text: "Detailed Findings",
      font: FONT.heading,
      size: 32,
      bold: true,
      color: BRAND.dark,
    })],
  }));
  findingsChildren.push(new Paragraph({
    border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: BRAND.primary } },
    spacing: { after: 200 },
    children: [],
  }));

  if (groupByTool) {
    const toolMap = new Map<string, Finding[]>();
    for (const f of sorted) {
      if (!toolMap.has(f.tool)) toolMap.set(f.tool, []);
      toolMap.get(f.tool)!.push(f);
    }

    for (const [tool, toolFindings] of toolMap) {
      findingsChildren.push(...buildToolHeading(tool, toolFindings.length));

      if (layout === "table") {
        findingsChildren.push(buildTableExport(toolFindings, fields));
      } else {
        const groups = groupFindings(toolFindings);
        let idx = 1;
        for (const group of groups) {
          findingsChildren.push(...buildTextGroup(group, fields, idx++));
        }
      }
    }
  } else {
    if (layout === "table") {
      findingsChildren.push(buildTableExport(sorted, fields));
    } else {
      const groups = groupFindings(sorted);
      for (let i = 0; i < groups.length; i++) {
        findingsChildren.push(...buildTextGroup(groups[i], fields, i + 1));
      }
    }
  }

  // ── Build document ──
  const doc = new Document({
    styles: {
      default: {
        document: {
          run: {
            font: FONT.body,
            size: 22,
            color: BRAND.body,
          },
        },
        heading1: {
          run: {
            font: FONT.heading,
            size: 48,
            bold: true,
            color: BRAND.dark,
          },
          paragraph: {
            spacing: { before: 400, after: 200 },
          },
        },
        heading2: {
          run: {
            font: FONT.heading,
            size: 32,
            bold: true,
            color: BRAND.primary,
          },
          paragraph: {
            spacing: { before: 300, after: 120 },
          },
        },
      },
    },
    sections: [
      {
        properties: {
          page: {
            margin: {
              top: convertInchesToTwip(0.8),
              bottom: convertInchesToTwip(0.8),
              left: convertInchesToTwip(1),
              right: convertInchesToTwip(1),
            },
          },
        },
        headers: {
          default: new Header({
            children: [new Paragraph({
              alignment: AlignmentType.RIGHT,
              children: [
                new TextRun({
                  text: "Sasty  |  SAST Findings Report",
                  font: FONT.heading,
                  size: 16,
                  color: BRAND.subtle,
                  italics: true,
                }),
              ],
            })],
          }),
        },
        footers: {
          default: new Footer({
            children: [new Paragraph({
              alignment: AlignmentType.CENTER,
              border: { top: { style: BorderStyle.SINGLE, size: 1, color: BRAND.ruleLine } },
              spacing: { before: 100 },
              children: [
                new TextRun({
                  text: "Page ",
                  font: FONT.body,
                  size: 16,
                  color: BRAND.subtle,
                }),
                new TextRun({
                  children: [PageNumber.CURRENT],
                  font: FONT.body,
                  size: 16,
                  color: BRAND.subtle,
                }),
                new TextRun({
                  text: " of ",
                  font: FONT.body,
                  size: 16,
                  color: BRAND.subtle,
                }),
                new TextRun({
                  children: [PageNumber.TOTAL_PAGES],
                  font: FONT.body,
                  size: 16,
                  color: BRAND.subtle,
                }),
              ],
            })],
          }),
        },
        children: [
          ...coverChildren,
          ...summaryChildren,
          // Page break before findings
          new Paragraph({
            children: [new PageBreak()],
          }),
          ...findingsChildren,
        ],
      },
    ],
  });

  const blob = await Packer.toBlob(doc);

  const safeName = (scan.label ?? scan.path.split(/[/\\]/).pop() ?? `scan-${scan.id}`)
    .replace(/[^a-z0-9_-]/gi, "_")
    .toLowerCase();
  const fileDate = new Date(scan.started_at).toISOString().slice(0, 10);
  const filename = `sasty_${safeName}_${fileDate}.docx`;

  saveAs(blob, filename);
}
