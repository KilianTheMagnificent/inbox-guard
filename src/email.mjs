// Zero-width spaces, joiners, bidi controls, and Unicode Tag characters (U+E0000..U+E007F)
const INVISIBLE_UNICODE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]|\uDB40[\uDC00-\uDC7F]/g;

const HIDDEN_HTML_STYLE_RE =
  /style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])|font-size\s*:\s*0(?:px|pt|em|rem|%)?)[^"']*["']/i;

const PROMPT_OVERRIDE_PATTERNS = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
  /system\s+override\s*:/i,
  /do\s+not\s+inform\s+the\s+(?:user|human|recipient)/i,
  /forward\s+(?:all|every|the)\s+(?:emails?|invoices?|attachments?)\s+to/i
];

function extractDomain(address) {
  const match = String(address ?? "").toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})\b/);
  return match ? match[1] : null;
}

/**
 * Inspect an untrusted inbound email (headers + plain/HTML body) before
 * passing text to an automated triage or drafting step.
 * Strips invisible Unicode characters and flags hidden HTML blocks, reply-to
 * domain mismatches, and embedded instruction-override patterns.
 */
export function inspectInboundEmail({ from = "", replyTo = "", subject = "", text = "", html = "" } = {}) {
  const findings = [];

  const fromDomain = extractDomain(from);
  const replyToDomain = extractDomain(replyTo);
  if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
    findings.push({
      code: "REPLY_TO_DOMAIN_MISMATCH",
      severity: "medium",
      detail: `Sender domain '${fromDomain}' differs from Reply-To domain '${replyToDomain}'.`
    });
  }

  const combinedRaw = `${subject}\n${text}\n${html}`;
  const invisibleMatches = combinedRaw.match(INVISIBLE_UNICODE_RE);
  if (invisibleMatches && invisibleMatches.length > 0) {
    findings.push({
      code: "INVISIBLE_UNICODE_CHARS",
      severity: invisibleMatches.length >= 8 ? "high" : "low",
      detail: `Detected ${invisibleMatches.length} invisible or Unicode tag character(s) capable of hiding text from human reviewers.`
    });
  }

  if (html && HIDDEN_HTML_STYLE_RE.test(html)) {
    findings.push({
      code: "HIDDEN_HTML_CONTENT",
      severity: "high",
      detail: "HTML email contains CSS-hidden elements (display:none, visibility:hidden, opacity:0, or font-size:0)."
    });
  }

  const normalizedText = `${subject}\n${text}`.replace(INVISIBLE_UNICODE_RE, "");
  for (const pattern of PROMPT_OVERRIDE_PATTERNS) {
    if (pattern.test(normalizedText) || (html && pattern.test(html.replace(INVISIBLE_UNICODE_RE, "")))) {
      findings.push({
        code: "INSTRUCTION_OVERRIDE_PATTERN",
        severity: "high",
        detail: `Inbound content matches untrusted instruction-override pattern (${pattern.source}).`
      });
      break;
    }
  }

  return {
    safe: findings.length === 0,
    sanitizedSubject: String(subject).replace(INVISIBLE_UNICODE_RE, ""),
    sanitizedText: String(text).replace(INVISIBLE_UNICODE_RE, ""),
    findings
  };
}
