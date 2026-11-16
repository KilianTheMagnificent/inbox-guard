const BLOCKED_EXTENSIONS = new Set([
  "exe", "scr", "bat", "cmd", "com", "msi", "msp", "ps1", "vbs", "vbe",
  "js", "jse", "wsf", "wsh", "hta", "cpl", "jar", "lnk", "iso", "img",
  "vhd", "vhdx", "dll", "sys", "reg", "app", "pkg", "dmg", "command",
  "sh", "bash", "zsh", "docm", "xlsm", "pptm", "dotm", "xltm"
]);

const BIDI_OVERRIDE_RE = /[\u202A-\u202E\u2066-\u2069]/;
const CONTROL_CHARS_RE = /[\x00-\x1F\x7F]/;

function startsWithBytes(buf, prefix) {
  if (!buf || buf.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (buf[i] !== prefix[i]) return false;
  }
  return true;
}

/**
 * Inspect an untrusted attachment's filename and optional leading file bytes
 * for spoofing, path traversal, executable extensions, and magic-byte mismatches.
 */
export function checkAttachment({ filename, headBytes } = {}) {
  const findings = [];
  const rawName = String(filename ?? "");

  if (!rawName.trim()) {
    findings.push({ code: "EMPTY_FILENAME", severity: "high", detail: "Attachment filename is empty." });
    return { safe: false, findings };
  }

  if (BIDI_OVERRIDE_RE.test(rawName)) {
    findings.push({
      code: "UNICODE_BIDI_SPOOF",
      severity: "critical",
      detail: "Filename contains Unicode bidirectional override characters often used to disguise executable extensions."
    });
  }

  if (CONTROL_CHARS_RE.test(rawName)) {
    findings.push({
      code: "CONTROL_CHAR_FILENAME",
      severity: "high",
      detail: "Filename contains ASCII control or null bytes."
    });
  }

  if (rawName.includes("/") || rawName.includes("\\") || rawName.includes("..")) {
    findings.push({
      code: "PATH_TRAVERSAL_FILENAME",
      severity: "critical",
      detail: "Filename contains directory separators or parent-directory traversal sequences."
    });
  }

  const base = rawName.split(/[/\\]/).pop() ?? "";
  const parts = base.toLowerCase().split(".").filter(Boolean);
  const ext = parts.length > 1 ? parts[parts.length - 1] : "";

  if (!ext) {
    findings.push({
      code: "MISSING_EXTENSION",
      severity: "medium",
      detail: "Attachment has no file extension."
    });
  } else if (BLOCKED_EXTENSIONS.has(ext)) {
    findings.push({
      code: "BLOCKED_EXTENSION",
      severity: "critical",
      detail: `Blocked executable, macro, or disk-image extension '.${ext}'.`
    });
  }

  if (parts.length >= 3) {
    const penultimate = parts[parts.length - 2];
    const benignDecoys = new Set(["pdf", "csv", "xlsx", "xls", "doc", "docx", "png", "jpg", "jpeg", "txt"]);
    if (benignDecoys.has(penultimate) && BLOCKED_EXTENSIONS.has(ext)) {
      findings.push({
        code: "DOUBLE_EXTENSION_DECOY",
        severity: "critical",
        detail: `Double extension '.${penultimate}.${ext}' mimics a benign document.`
      });
    }
  }

  if (headBytes && headBytes.length > 0) {
    const buf = headBytes instanceof Uint8Array ? headBytes : Uint8Array.from(headBytes);
    const isWindowsPE = startsWithBytes(buf, [0x4D, 0x5A]); // "MZ"
    const isELF = startsWithBytes(buf, [0x7F, 0x45, 0x4C, 0x46]); // "\x7FELF"
    const isMachO =
      startsWithBytes(buf, [0xCF, 0xFA, 0xED, 0xFE]) ||
      startsWithBytes(buf, [0xFE, 0xED, 0xFA, 0xCF]) ||
      startsWithBytes(buf, [0xCA, 0xFE, 0xBA, 0xBE]);

    if (isWindowsPE || isELF || isMachO) {
      findings.push({
        code: "EXECUTABLE_MAGIC_BYTES",
        severity: "critical",
        detail: "File header matches a native executable binary regardless of filename."
      });
    }

    if (ext === "pdf" && !startsWithBytes(buf, [0x25, 0x50, 0x44, 0x46, 0x2D])) {
      findings.push({
        code: "PDF_HEADER_MISMATCH",
        severity: "high",
        detail: "File claims '.pdf' extension but does not begin with '%PDF-' header."
      });
    }

    if (ext === "png" && !startsWithBytes(buf, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) {
      findings.push({
        code: "PNG_HEADER_MISMATCH",
        severity: "high",
        detail: "File claims '.png' extension but lacks valid PNG signature bytes."
      });
    }

    if ((ext === "csv" || ext === "txt") && buf.length > 0) {
      const textSample = new TextDecoder("utf-8", { fatal: false }).decode(buf.slice(0, 256)).toLowerCase();
      if (textSample.includes("<script") || textSample.includes("<!doctype html") || textSample.includes("<html")) {
        findings.push({
          code: "HTML_SCRIPT_IN_PLAINTEXT",
          severity: "high",
          detail: `File claims '.${ext}' plaintext format but contains HTML or script tags.`
        });
      }
    }
  }

  return {
    safe: findings.length === 0,
    extension: ext || null,
    findings
  };
}
