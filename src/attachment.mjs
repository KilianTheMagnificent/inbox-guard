const BLOCKED_EXTENSIONS = new Set([
  "exe", "scr", "pif", "bat", "cmd", "com", "msi", "msp", "mst",
  "ps1", "ps1xml", "ps2", "psc1", "psc2", "vbs", "vbe",
  "js", "jse", "mjs", "cjs", "wsf", "wsh", "hta", "cpl", "msc",
  "jar", "jnlp", "lnk", "scf", "url", "webloc", "desktop", "inf", "reg",
  "iso", "img", "vhd", "vhdx", "dll", "sys", "drv", "ocx", "xll", "wll",
  "app", "pkg", "dmg", "command", "sh", "bash", "zsh", "ksh", "csh",
  "py", "pyc", "pl", "rb", "php", "chm", "hlp",
  "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm",
  "iqy", "dqy", "oqy", "rqy", "slk"
]);

const ACTIVE_CONTENT_EXTENSIONS = new Set([
  "svg", "svgz", "html", "htm", "xhtml", "shtml", "mht", "mhtml",
  "xml", "xsl", "xslt", "swf"
]);

const ARCHIVE_CONTAINER_EXTENSIONS = new Set([
  "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz2",
  "xz", "txz", "zst", "cab", "arj", "lzh", "ace", "cpio"
]);

const BENIGN_DECOY_EXTENSIONS = new Set([
  "pdf", "csv", "xlsx", "xls", "doc", "docx", "ppt", "pptx",
  "png", "jpg", "jpeg", "gif", "txt", "rtf"
]);

const BIDI_OVERRIDE_RE = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const CONTROL_CHARS_RE = /[\x00-\x1F\x7F]/;
const DECEPTIVE_SPACE_RE = /[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000\uFEFF]/;

const MAGIC_PDF = [0x25, 0x50, 0x44, 0x46, 0x2D]; // "%PDF-"
const MAGIC_PNG = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const MAGIC_JPEG = [0xFF, 0xD8, 0xFF];
const MAGIC_GIF87 = [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]; // "GIF87a"
const MAGIC_GIF89 = [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]; // "GIF89a"
const MAGIC_ZIP = [0x50, 0x4B, 0x03, 0x04]; // "PK\x03\x04"
const MAGIC_OLE2 = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const MAGIC_RAR = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]; // "Rar!\x1A\x07"
const MAGIC_7Z = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const MAGIC_GZIP = [0x1F, 0x8B];

function startsWithBytes(buf, prefix) {
  if (!buf || buf.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (buf[i] !== prefix[i]) return false;
  }
  return true;
}

function normalizeHeadBytes(headBytes) {
  if (headBytes instanceof Uint8Array) return headBytes;
  if (ArrayBuffer.isView(headBytes)) {
    return new Uint8Array(headBytes.buffer, headBytes.byteOffset, headBytes.byteLength);
  }
  if (headBytes instanceof ArrayBuffer) {
    return new Uint8Array(headBytes);
  }
  if (Array.isArray(headBytes)) {
    return Uint8Array.from(headBytes);
  }
  return null;
}

/**
 * Compare `buf` against one or more valid magic-byte prefixes for a claimed format.
 * Distinguishes valid full match ("match"), truncated partial prefix ("truncated"),
 * and definite byte mismatch ("mismatch") so short buffers never make false claims.
 */
function classifySignatureMatch(buf, validPrefixes) {
  for (const sig of validPrefixes) {
    if (buf.length >= sig.length && startsWithBytes(buf, sig)) {
      return "match";
    }
  }
  for (const sig of validPrefixes) {
    if (buf.length < sig.length && startsWithBytes(sig, buf)) {
      return "truncated";
    }
  }
  return "mismatch";
}

function stripTrailingDotsAndSpaces(str) {
  let end = str.length;
  while (end > 0) {
    const ch = str[end - 1];
    if (ch === "." || ch === "\x00" || /\s/u.test(ch)) {
      end -= 1;
    } else {
      break;
    }
  }
  return str.slice(0, end);
}

function extractNormalizedParts(segment) {
  const cleaned = stripTrailingDotsAndSpaces(segment.replace(/[\x00-\x1F\x7F]+/g, ""));
  if (!cleaned) return [];
  if (cleaned.startsWith(".") && !cleaned.slice(1).includes(".")) {
    return [cleaned.slice(1).trim().toLowerCase()].filter(Boolean);
  }
  return cleaned
    .toLowerCase()
    .split(".")
    .map((p) => p.trim())
    .filter(Boolean);
}

function decodeTextSample(buf) {
  const slice = buf.subarray(0, 4096);
  // Handle UTF-16LE / UTF-16BE BOM or null-interleaved ASCII tags in plaintext decoys
  let stripped = slice;
  if (slice.length >= 4) {
    let zeroCount = 0;
    for (let i = 0; i < slice.length; i++) {
      if (slice[i] === 0x00) zeroCount += 1;
    }
    if (zeroCount >= slice.length / 4) {
      stripped = slice.filter((b) => b !== 0x00);
    }
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(stripped).toLowerCase();
}

/**
 * Inspect an untrusted attachment's filename and optional leading file bytes
 * for spoofing, Windows/SMB trailing-dot/space canonicalization tricks,
 * active HTML/SVG content, uninspected archives, executable extensions,
 * and magic-byte mismatches.
 */
export function checkAttachment({ filename, headBytes } = {}) {
  const findings = [];
  const rawName = String(filename ?? "");

  if (!rawName.trim()) {
    findings.push({
      code: "EMPTY_FILENAME",
      severity: "high",
      detail: "Attachment filename is empty."
    });
    return { safe: false, extension: null, findings };
  }

  if (BIDI_OVERRIDE_RE.test(rawName)) {
    findings.push({
      code: "UNICODE_BIDI_SPOOF",
      severity: "critical",
      detail: "Filename contains Unicode bidirectional control characters used to disguise extensions."
    });
  }

  if (CONTROL_CHARS_RE.test(rawName)) {
    findings.push({
      code: "CONTROL_CHAR_FILENAME",
      severity: "high",
      detail: "Filename contains ASCII control or null bytes."
    });
  }

  if (
    rawName.includes("/") ||
    rawName.includes("\\") ||
    rawName.includes("..") ||
    /^[A-Za-z]:/.test(rawName)
  ) {
    findings.push({
      code: "PATH_TRAVERSAL_FILENAME",
      severity: "critical",
      detail: "Filename contains directory separators, drive prefixes, or parent-directory traversal sequences."
    });
  }

  const rawBase = rawName.split(/[/\\]/).pop() ?? "";

  if (rawBase.includes(":")) {
    findings.push({
      code: "NTFS_ADS_FILENAME",
      severity: "critical",
      detail: "Filename contains ':' NTFS Alternate Data Stream syntax that can hide executable extensions on Windows."
    });
  }

  const baseWithoutAds = rawBase.split(":")[0];

  if (/[.\s]$/u.test(baseWithoutAds)) {
    findings.push({
      code: "TRAILING_DOT_OR_SPACE",
      severity: "high",
      detail: "Filename ends with trailing dots or whitespace, which Windows/SMB strips when saving files."
    });
  }

  const trimmedForPaddingCheck = stripTrailingDotsAndSpaces(baseWithoutAds);
  const lastDotIdx = trimmedForPaddingCheck.lastIndexOf(".");
  const hasPaddingBeforeDot =
    lastDotIdx > 0 && /[\s\x00]/u.test(trimmedForPaddingCheck[lastDotIdx - 1]);
  const hasPaddingInsideExt =
    lastDotIdx >= 0 && /[\s\x00]/u.test(trimmedForPaddingCheck.slice(lastDotIdx + 1));

  if (hasPaddingBeforeDot || hasPaddingInsideExt || DECEPTIVE_SPACE_RE.test(rawName)) {
    findings.push({
      code: "EXTENSION_PADDING",
      severity: "high",
      detail: "Filename contains null, whitespace, or deceptive Unicode space padding around the file extension."
    });
  }

  const parts = extractNormalizedParts(baseWithoutAds);
  let ext = parts.length > 1 ? parts[parts.length - 1] : "";
  if (
    !ext &&
    parts.length === 1 &&
    baseWithoutAds.trimStart().startsWith(".") &&
    (BLOCKED_EXTENSIONS.has(parts[0]) ||
      ACTIVE_CONTENT_EXTENSIONS.has(parts[0]) ||
      ARCHIVE_CONTAINER_EXTENSIONS.has(parts[0]))
  ) {
    ext = parts[0];
  }

  // Also inspect pre-null-byte segment for C-string truncation spoofing (`invoice.exe\x00.pdf`)
  let preNullExt = "";
  if (baseWithoutAds.includes("\x00")) {
    const preNullParts = extractNormalizedParts(
      baseWithoutAds.slice(0, baseWithoutAds.indexOf("\x00"))
    );
    preNullExt = preNullParts.length > 1 ? preNullParts[preNullParts.length - 1] : "";
  }

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
      detail: `Blocked executable, script, macro, or disk-image extension '.${ext}'.`
    });
  } else if (ACTIVE_CONTENT_EXTENSIONS.has(ext)) {
    findings.push({
      code: "ACTIVE_CONTENT_EXTENSION",
      severity: "high",
      detail: `Active markup/vector extension '.${ext}' can execute embedded JavaScript when opened locally.`
    });
  } else if (ARCHIVE_CONTAINER_EXTENSIONS.has(ext)) {
    findings.push({
      code: "UNINSPECTED_ARCHIVE_CONTAINER",
      severity: "medium",
      detail: `Archive/container extension '.${ext}' conceals inner files that have not been extracted and inspected.`
    });
  }

  if (preNullExt && preNullExt !== ext) {
    if (BLOCKED_EXTENSIONS.has(preNullExt)) {
      findings.push({
        code: "BLOCKED_EXTENSION",
        severity: "critical",
        detail: `Null-byte prefix hides blocked extension '.${preNullExt}'.`
      });
    } else if (ACTIVE_CONTENT_EXTENSIONS.has(preNullExt)) {
      findings.push({
        code: "ACTIVE_CONTENT_EXTENSION",
        severity: "high",
        detail: `Null-byte prefix hides active-content extension '.${preNullExt}'.`
      });
    }
  }

  if (parts.length >= 3) {
    const penultimate = parts[parts.length - 2];
    if (
      BENIGN_DECOY_EXTENSIONS.has(penultimate) &&
      (BLOCKED_EXTENSIONS.has(ext) || ACTIVE_CONTENT_EXTENSIONS.has(ext))
    ) {
      findings.push({
        code: "DOUBLE_EXTENSION_DECOY",
        severity: "critical",
        detail: `Double extension '.${penultimate}.${ext}' mimics a benign document.`
      });
    }
  }

  if (headBytes !== undefined && headBytes !== null) {
    const buf = normalizeHeadBytes(headBytes);
    if (!buf) {
      findings.push({
        code: "INVALID_HEADER_BYTES",
        severity: "high",
        detail: "headBytes must be a Uint8Array, ArrayBuffer, TypedArray, or byte array."
      });
      return { safe: false, extension: ext || null, findings };
    }

    if (buf.length === 0) {
      findings.push({
        code: "TRUNCATED_OR_EMPTY_BYTES",
        severity: "medium",
        detail: "Header byte buffer is empty (0 bytes); file signature cannot be verified."
      });
      return { safe: false, extension: ext || null, findings };
    }

    const isWindowsPE = startsWithBytes(buf, [0x4D, 0x5A]); // "MZ"
    const isELF = startsWithBytes(buf, [0x7F, 0x45, 0x4C, 0x46]); // "\x7FELF"
    const isMachO =
      startsWithBytes(buf, [0xCF, 0xFA, 0xED, 0xFE]) ||
      startsWithBytes(buf, [0xFE, 0xED, 0xFA, 0xCF]) ||
      startsWithBytes(buf, [0xCE, 0xFA, 0xED, 0xFE]) ||
      startsWithBytes(buf, [0xFE, 0xED, 0xFA, 0xCE]) ||
      startsWithBytes(buf, [0xCA, 0xFE, 0xBA, 0xBE]) ||
      startsWithBytes(buf, [0xCA, 0xFE, 0xBA, 0xBF]);
    const isShebang = startsWithBytes(buf, [0x23, 0x21, 0x2F]); // "#!/"

    if (isWindowsPE || isELF || isMachO || isShebang) {
      findings.push({
        code: "EXECUTABLE_MAGIC_BYTES",
        severity: "critical",
        detail: "File header matches a native executable binary, Java/Mach-O header, or interpreter shebang."
      });
    }

    const isRawArchive =
      startsWithBytes(buf, MAGIC_RAR) ||
      startsWithBytes(buf, MAGIC_7Z) ||
      startsWithBytes(buf, MAGIC_GZIP);
    if (isRawArchive && !ARCHIVE_CONTAINER_EXTENSIONS.has(ext)) {
      findings.push({
        code: "ARCHIVE_MAGIC_MISMATCH",
        severity: "high",
        detail: `File header matches a compressed archive signature despite '.${ext || "none"}' extension.`
      });
    }

    const expectedByExt = {
      pdf: {
        sigs: [MAGIC_PDF],
        code: "PDF_HEADER_MISMATCH",
        detail: "File claims '.pdf' extension but does not begin with '%PDF-' header."
      },
      png: {
        sigs: [MAGIC_PNG],
        code: "PNG_HEADER_MISMATCH",
        detail: "File claims '.png' extension but lacks valid 8-byte PNG signature."
      },
      jpg: {
        sigs: [MAGIC_JPEG],
        code: "JPEG_HEADER_MISMATCH",
        detail: "File claims '.jpg' extension but lacks valid JPEG SOI signature."
      },
      jpeg: {
        sigs: [MAGIC_JPEG],
        code: "JPEG_HEADER_MISMATCH",
        detail: "File claims '.jpeg' extension but lacks valid JPEG SOI signature."
      },
      gif: {
        sigs: [MAGIC_GIF87, MAGIC_GIF89],
        code: "GIF_HEADER_MISMATCH",
        detail: "File claims '.gif' extension but lacks valid GIF87a/GIF89a header."
      },
      docx: {
        sigs: [MAGIC_ZIP, MAGIC_OLE2],
        code: "OOXML_HEADER_MISMATCH",
        detail: "File claims '.docx' extension but lacks PK/OLE2 package signature."
      },
      xlsx: {
        sigs: [MAGIC_ZIP, MAGIC_OLE2],
        code: "OOXML_HEADER_MISMATCH",
        detail: "File claims '.xlsx' extension but lacks PK/OLE2 package signature."
      },
      pptx: {
        sigs: [MAGIC_ZIP, MAGIC_OLE2],
        code: "OOXML_HEADER_MISMATCH",
        detail: "File claims '.pptx' extension but lacks PK/OLE2 package signature."
      }
    };

    if (ext && Object.hasOwn(expectedByExt, ext)) {
      const spec = expectedByExt[ext];
      const status = classifySignatureMatch(buf, spec.sigs);
      if (status === "mismatch") {
        findings.push({
          code: spec.code,
          severity: "high",
          detail: spec.detail
        });
      } else if (status === "truncated") {
        findings.push({
          code: "TRUNCATED_OR_EMPTY_BYTES",
          severity: "medium",
          detail: `Header buffer (${buf.length} byte(s)) is truncated before completing the '.${ext}' magic-byte signature.`
        });
      }
    }

    if (ext === "csv" || ext === "txt") {
      const textSample = decodeTextSample(buf);
      if (
        textSample.includes("<script") ||
        textSample.includes("<!doctype html") ||
        textSample.includes("<html") ||
        textSample.includes("<svg") ||
        textSample.includes("<iframe") ||
        textSample.includes("<hta:")
      ) {
        findings.push({
          code: "HTML_SCRIPT_IN_PLAINTEXT",
          severity: "high",
          detail: `File claims '.${ext}' plaintext format but contains active HTML, SVG, or script markup.`
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
