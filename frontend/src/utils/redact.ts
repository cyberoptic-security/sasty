import type { CodeContext, Finding } from "../types";

/**
 * Categories / tools whose matched_code always contains secrets.
 */
const SECRET_CATEGORIES = new Set(["secrets"]);
const SECRET_TOOLS = new Set(["gitleaks", "betterleaks"]);

/**
 * Keywords in rule_id, rule_name, or message that signal a secret/credential finding.
 * Matched case-insensitively.
 */
const SECRET_KEYWORDS = [
  "secret", "token", "password", "passwd", "credential", "api.key", "api_key",
  "apikey", "auth", "jwt", "bearer", "private.key", "private_key", "privatekey",
  "access.key", "access_key", "accesskey", "signing.key", "signing_key",
  "encryption.key", "encryption_key", "certificate", "ssh.key", "ssh_key",
];

/**
 * Redact a secret string, scaling the visible portion to ~10% on each end.
 *
 * Short secrets (<=6 chars):   "****"
 * Medium (7–40 chars):         first 2 + *** + last 2
 * Long (41–200 chars):         ~10% visible each end, min 3 chars
 * Very long (>200, e.g. keys): first 10 + *** + last 10
 *
 * Examples:
 *   "abc"                        →  "****"
 *   "sk-abc123"   (9 chars)      →  "sk*****23"
 *   "AKIAIOSFODNN7EXAMPLE" (20)  →  "AK****************LE"
 *   "-----BEGIN RSA..." (800+)   →  "-----BEGI...(redacted)...vate_key"
 */
function redactValue(secret: string): string {
  const s = secret.trim();
  const len = s.length;

  if (len <= 6) return "****";

  if (len <= 40) {
    // Show 2 chars each side
    const show = 2;
    return s.slice(0, show) + "*".repeat(len - show * 2) + s.slice(-show);
  }

  if (len <= 200) {
    // ~10% each side, minimum 3 chars
    const show = Math.max(3, Math.round(len * 0.1));
    return s.slice(0, show) + "*".repeat(len - show * 2) + s.slice(-show);
  }

  // Very long (private keys, certificates): show 10 chars each side
  const show = 10;
  return s.slice(0, show) + `...[REDACTED ${len - show * 2} chars]...` + s.slice(-show);
}

/**
 * Return true if this finding likely contains a raw secret that should be redacted.
 */
function isSecretFinding(f: Finding): boolean {
  // Explicit secret category or tool
  if (f.category && SECRET_CATEGORIES.has(f.category.toLowerCase())) return true;
  if (SECRET_TOOLS.has(f.tool.toLowerCase())) return true;

  // Keyword match on rule_id, rule_name, or message
  const haystack = [f.rule_id, f.rule_name ?? "", f.message].join(" ").toLowerCase();
  for (const kw of SECRET_KEYWORDS) {
    if (haystack.includes(kw)) return true;
  }

  return false;
}

/**
 * Replace all occurrences of `secret` in `text` with the redacted form.
 */
function redactIn(text: string, secret: string, replacement: string): string {
  if (!text || !secret) return text;
  return text.split(secret).join(replacement);
}

/**
 * Deep-clone and redact a single finding's sensitive values.
 * - matched_code is replaced with the redacted form
 * - code_context lines containing the secret are sanitised
 * - message is sanitised if it contains the raw secret
 */
function redactFinding(f: Finding): Finding {
  const secret = f.matched_code?.trim();
  if (!secret) return f;

  const redacted = redactValue(secret);

  const clone: Finding = { ...f };

  // Redact matched_code
  clone.matched_code = redacted;

  // Redact code_context lines
  if (f.code_context) {
    const ctx: CodeContext = {
      ...f.code_context,
      lines: f.code_context.lines.map((line) => redactIn(line, secret, redacted)),
    };
    clone.code_context = ctx;
  }

  // Redact message if it contains the raw secret
  if (f.message) {
    clone.message = redactIn(f.message, secret, redacted);
  }

  return clone;
}

/**
 * Return a new array of findings with secrets redacted.
 * Non-secret findings are passed through unchanged.
 */
export function redactFindings(findings: Finding[]): Finding[] {
  return findings.map((f) => (isSecretFinding(f) ? redactFinding(f) : f));
}
