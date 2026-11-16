const BLOCKED_EXTENSIONS = new Set([
  "exe", "scr", "pif", "bat", "cmd", "com", "msi", "msp", "mst",
  "ps1", "ps1xml", "ps2", "psc1", "psc2", "vbs", "vbe", "vb",
  "js", "jse", "mjs", "cjs", "wsf", "wsh", "wsc", "sct", "hta", "cpl", "msc",
  "jar", "jnlp", "lnk", "scf", "url", "webloc", "website", "desktop", "inf", "reg",
  "iso", "img", "vhd", "vhdx", "dll", "sys", "drv", "ocx", "xll", "wll",
  "app", "pkg", "dmg", "command", "sh", "bash", "zsh", "ksh", "csh",
  "py", "pyc", "pl", "rb", "php", "chm", "hlp",
  "doc", "dot", "wiz", "xls", "xlt", "xla", "xlsb", "ppt", "pot", "ppa", "pps",
  "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm",
  "one", "onepkg",
  "appx", "appxbundle", "msix", "msixbundle", "appinstaller", "application", "xbap",
  "library-ms", "search-ms", "settingcontent-ms", "diagcab", "gadget",
  "iqy", "dqy", "oqy", "rqy", "slk"
]);

const ACTIVE_CONTENT_EXTENSIONS = new Set([
  "svg", "svgz", "html", "htm", "xhtml", "shtml", "htmlz",
  "mht", "mhtml", "xml", "xsl", "xslt", "swf", "eml"
]);

const ARCHIVE_CONTAINER_EXTENSIONS = new Set([
  "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz2",
  "xz", "txz", "zst", "cab", "arj", "lzh", "ace", "cpio", "msg"
]);

const BENIGN_DECOY_EXTENSIONS = new Set([
  "pdf", "csv", "xlsx", "xls", "doc", "docx", "ppt", "pptx",
  "png", "jpg", "jpeg", "gif", "txt", "rtf"
]);

const ZIP_PACKAGE_EXTENSIONS = new Set([
  "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"
]);

const OLE2_PACKAGE_EXTENSIONS = new Set([
  "doc", "dot", "wiz", "xls", "xlt", "xla", "ppt", "pot", "ppa", "pps",
  "msg", "msi", "msp", "mst"
]);

const TEXT_OR_LEGACY_DOC_EXTENSIONS = new Set([
  "csv", "tsv", "txt", "log", "md", "doc", "dot", "xls", "xlt", "ppt", "rtf", "eml"
]);

const BIDI_OVERRIDE_RE = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const CONTROL_CHARS_RE = /[\x00-\x1F\x7F-\x9F]/;
const DECEPTIVE_SPACE_OR_FILLER_RE =
  /[\u00A0\u00AD\u034F\u115F\u1160\u1680\u17B4\u17B5\u180E\u2000-\u200D\u2028\u2029\u202F\u205F\u2060-\u2064\u2800\u3000\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB\u{E0000}-\u{E01EF}]/u;
const DOT_LEADER_SPOOF_RE = /[\u2024\u2025\u3002\uFE52\uFF0E]/;
const WINDOWS_RESERVED_STEM_RE =
  /^(?:con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])$/i;

const MAGIC_PDF = [0x25, 0x50, 0x44, 0x46, 0x2D]; // "%PDF-"
const MAGIC_PNG = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const MAGIC_JPEG = [0xFF, 0xD8, 0xFF];
const MAGIC_GIF87 = [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]; // "GIF87a"
const MAGIC_GIF89 = [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]; // "GIF89a"
const MAGIC_RTF = [0x7B, 0x5C, 0x72, 0x74, 0x66]; // "{\\rtf"
const MAGIC_ZIP_LOCAL = [0x50, 0x4B, 0x03, 0x04]; // "PK\x03\x04"
const MAGIC_ZIP_EMPTY = [0x50, 0x4B, 0x05, 0x06]; // "PK\x05\x06"
const MAGIC_ZIP_SPANNED = [0x50, 0x4B, 0x07, 0x08]; // "PK\x07\x08"
const MAGIC_OLE2 = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const MAGIC_RAR = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]; // "Rar!\x1A\x07"
const MAGIC_7Z = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const MAGIC_GZIP = [0x1F, 0x8B];
const MAGIC_XZ = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]; // "\xFD7zXZ\x00"
const MAGIC_ZSTD = [0x28, 0xB5, 0x2F, 0xFD];
const MAGIC_CAB = [0x4D, 0x53, 0x43, 0x46, 0x00, 0x00, 0x00, 0x00]; // "MSCF\0\0\0\0"

function startsWithBytes(buf, prefix) {
  if (!buf || buf.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (buf[i] !== prefix[i]) return false;
  }
  return true;
}

function hasShebangPrefix(buf) {
  if (!buf || buf.length < 3 || buf[0] !== 0x23 || buf[1] !== 0x21) return false;
  let i = 2;
  const limit = Math.min(buf.length, 18);
  while (i < limit && (buf[i] === 0x20 || buf[i] === 0x09)) {
    i += 1;
  }
  return i < limit && buf[i] === 0x2F; // '/'
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

function isInvisibleOrWhitespaceChar(ch) {
  return ch === "." || ch === "\x00" || /\s/u.test(ch) || DECEPTIVE_SPACE_OR_FILLER_RE.test(ch);
}

function stripTrailingDotsAndSpaces(str) {
  let end = str.length;
  while (end > 0 && isInvisibleOrWhitespaceChar(str[end - 1])) {
    end -= 1;
  }
  return str.slice(0, end);
}

function normalizeSeparatorsAndControls(segment) {
  return segment
    .replace(/[\x00-\x1F\x7F-\x9F]+/g, "")
    .replace(BIDI_OVERRIDE_RE, "")
    .replace(DECEPTIVE_SPACE_OR_FILLER_RE, "")
    .replace(/[\u2024\u2025\u3002\uFE52\uFF0E]/g, ".");
}

function extractNormalizedParts(segment) {
  const cleaned = stripTrailingDotsAndSpaces(normalizeSeparatorsAndControls(segment));
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

/**
 * Detect genuine NTFS Alternate Data Stream syntax (`invoice.pdf:evil.exe`, `file.exe::$DATA`)
 * without false-positiving on benign human filenames containing spaces around colons (`A: Smith.pdf`)
 * or numeric timestamps (`Invoice 10:30.pdf`).
 */
function findNtfsAdsColonIndex(rawBase) {
  if (!rawBase.includes(":")) return -1;
  const doubleColon = rawBase.indexOf("::");
  if (doubleColon !== -1) return doubleColon;

  // Strip a leading drive letter (`C:...`) before inspecting stream colons
  const startOffset = /^[A-Za-z]:(?!\s)/.test(rawBase) ? 2 : 0;
  for (let i = startOffset; i < rawBase.length; i++) {
    if (rawBase[i] !== ":") continue;
    const next = rawBase[i + 1];
    if (!next || /\s/u.test(next)) continue;

    // Pattern 1: `.ext:stream` (e.g. `invoice.pdf:evil.exe` or `doc.txt:123`)
    const before = rawBase.slice(startOffset, i);
    const dotIdx = before.lastIndexOf(".");
    if (dotIdx !== -1 && i - dotIdx - 1 >= 1 && i - dotIdx - 1 <= 16) {
      const maybeExt = before.slice(dotIdx + 1);
      if (/^[A-Za-z0-9]+$/.test(maybeExt)) {
        return i;
      }
    }

    // Pattern 2: `stem:stream` where stream starts with ASCII letter or '$' (excludes `10:30`)
    if (i > startOffset && /[A-Za-z0-9_.)\]]/.test(rawBase[i - 1]) && /[A-Za-z_$]/.test(next)) {
      return i;
    }
  }
  return -1;
}

function decodeTextSample(buf) {
  const slice = buf.subarray(0, 4096);
  if (slice.length >= 2 && slice[0] === 0xFF && slice[1] === 0xFE) {
    return new TextDecoder("utf-16le", { fatal: false }).decode(slice.subarray(2)).toLowerCase();
  }
  if (slice.length >= 2 && slice[0] === 0xFE && slice[1] === 0xFF) {
    return new TextDecoder("utf-16be", { fatal: false }).decode(slice.subarray(2)).toLowerCase();
  }
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

function hasInlineHtmlEventHandler(lowerSample) {
  let i = 0;
  const len = lowerSample.length;
  while (i < len) {
    const lt = lowerSample.indexOf("<", i);
    if (lt === -1 || lt + 2 >= len) break;
    const first = lowerSample.charCodeAt(lt + 1);
    if (first < 97 || first > 122) {
      i = lt + 1;
      continue;
    }
    const gt = lowerSample.indexOf(">", lt + 2);
    const end = gt === -1 ? len : gt;
    const tagSlice = lowerSample.slice(lt + 1, end);
    if (/(?:^|[\s/"'])on[a-z]{2,24}\s*=/.test(tagSlice)) {
      return true;
    }
    i = end + 1;
  }
  return false;
}

function containsActiveMarkupOrMht(textSample) {
  if (
    textSample.includes("<script") ||
    textSample.includes("<!doctype html") ||
    textSample.includes("<html") ||
    textSample.includes("<head") ||
    textSample.includes("<body") ||
    textSample.includes("<svg") ||
    textSample.includes("<iframe") ||
    textSample.includes("<frame") ||
    textSample.includes("<object") ||
    textSample.includes("<embed") ||
    textSample.includes("<applet") ||
    textSample.includes("<hta:") ||
    textSample.includes("<form") ||
    textSample.includes("<base")
  ) {
    return true;
  }
  if (
    textSample.includes("multipart/related") &&
    (textSample.includes("mime-version:") || textSample.includes("content-type:"))
  ) {
    return true;
  }
  return hasInlineHtmlEventHandler(textSample);
}

/**
 * Inspect an untrusted attachment's filename and optional leading file bytes
 * for spoofing, Windows/SMB canonicalization tricks, reserved device names,
 * active HTML/SVG/MHT content, uninspected archives, executable/macro extensions,
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
      detail: "Filename contains ASCII/C1 control or null bytes."
    });
  }

  const trimmedRaw = rawName.trim();
  if (
    rawName.includes("/") ||
    rawName.includes("\\") ||
    trimmedRaw === "." ||
    trimmedRaw === ".." ||
    /^[A-Za-z]:(?!\s)/.test(trimmedRaw)
  ) {
    findings.push({
      code: "PATH_TRAVERSAL_FILENAME",
      severity: "critical",
      detail: "Filename contains directory separators, Windows drive prefixes, or parent-directory traversal."
    });
  }

  const rawBase = rawName.split(/[/\\]/).pop() ?? "";
  const adsColonIdx = findNtfsAdsColonIndex(rawBase);

  let baseWithoutAds = rawBase;
  let adsStreamSegment = "";
  if (adsColonIdx !== -1) {
    findings.push({
      code: "NTFS_ADS_FILENAME",
      severity: "critical",
      detail: "Filename contains NTFS Alternate Data Stream (':stream') syntax that can hide executable payloads on Windows."
    });
    baseWithoutAds = rawBase.slice(0, adsColonIdx);
    adsStreamSegment = rawBase.slice(adsColonIdx + 1).replace(/^:+/, "");
  }

  if (/[.\s]$/u.test(baseWithoutAds)) {
    findings.push({
      code: "TRAILING_DOT_OR_SPACE",
      severity: "high",
      detail: "Filename ends with trailing dots or whitespace, which Windows/SMB strips when saving files."
    });
  }

  if (DOT_LEADER_SPOOF_RE.test(rawName)) {
    findings.push({
      code: "UNICODE_DOT_SPOOF",
      severity: "high",
      detail: "Filename contains Unicode dot-leader or fullwidth period lookalikes that disguise file extensions."
    });
  }

  const trimmedForPaddingCheck = stripTrailingDotsAndSpaces(baseWithoutAds);
  const lastDotIdx = trimmedForPaddingCheck.lastIndexOf(".");
  const hasPaddingBeforeDot =
    lastDotIdx > 0 && /[\s\x00]/u.test(trimmedForPaddingCheck[lastDotIdx - 1]);
  const hasPaddingInsideExt =
    lastDotIdx >= 0 && /[\s\x00]/u.test(trimmedForPaddingCheck.slice(lastDotIdx + 1));

  if (
    hasPaddingBeforeDot ||
    hasPaddingInsideExt ||
    DECEPTIVE_SPACE_OR_FILLER_RE.test(rawName)
  ) {
    findings.push({
      code: "EXTENSION_PADDING",
      severity: "high",
      detail: "Filename contains null, whitespace, or invisible Unicode filler padding around the file extension."
    });
  }

  const normalizedForStem = normalizeSeparatorsAndControls(baseWithoutAds).trim();
  const firstDotInStem = normalizedForStem.indexOf(".");
  const primaryStem = (
    firstDotInStem === -1 ? normalizedForStem : normalizedForStem.slice(0, firstDotInStem)
  ).trim();
  if (primaryStem && WINDOWS_RESERVED_STEM_RE.test(primaryStem)) {
    findings.push({
      code: "WINDOWS_RESERVED_FILENAME",
      severity: "high",
      detail: `Filename stem '${primaryStem}' is a reserved Windows DOS/NT device name.`
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

  // Also inspect pre-null-byte segment (`invoice.exe\x00.pdf`) and ADS stream suffix (`invoice.pdf:evil.exe`)
  const extraExtensions = [];
  if (baseWithoutAds.includes("\x00")) {
    const preNullParts = extractNormalizedParts(
      baseWithoutAds.slice(0, baseWithoutAds.indexOf("\x00"))
    );
    const preNullExt = preNullParts.length > 1 ? preNullParts[preNullParts.length - 1] : "";
    if (preNullExt && preNullExt !== ext) extraExtensions.push(preNullExt);
  }
  if (adsStreamSegment) {
    const streamParts = extractNormalizedParts(adsStreamSegment);
    const streamExt = streamParts.length > 1 ? streamParts[streamParts.length - 1] : "";
    if (streamExt && streamExt !== ext) extraExtensions.push(streamExt);
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
      detail: `Blocked executable, script, package, or macro-capable extension '.${ext}'.`
    });
  } else if (ACTIVE_CONTENT_EXTENSIONS.has(ext)) {
    findings.push({
      code: "ACTIVE_CONTENT_EXTENSION",
      severity: "high",
      detail: `Active markup, web-archive, or message extension '.${ext}' can execute embedded script or active loads when opened locally.`
    });
  } else if (ARCHIVE_CONTAINER_EXTENSIONS.has(ext)) {
    findings.push({
      code: "UNINSPECTED_ARCHIVE_CONTAINER",
      severity: "medium",
      detail: `Archive/container extension '.${ext}' conceals inner files that have not been extracted and inspected.`
    });
  }

  for (const hiddenExt of extraExtensions) {
    if (BLOCKED_EXTENSIONS.has(hiddenExt)) {
      findings.push({
        code: "BLOCKED_EXTENSION",
        severity: "critical",
        detail: `Secondary filename segment hides blocked extension '.${hiddenExt}'.`
      });
    } else if (ACTIVE_CONTENT_EXTENSIONS.has(hiddenExt)) {
      findings.push({
        code: "ACTIVE_CONTENT_EXTENSION",
        severity: "high",
        detail: `Secondary filename segment hides active-content extension '.${hiddenExt}'.`
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
    const isShebang = hasShebangPrefix(buf);

    if (isWindowsPE || isELF || isMachO || isShebang) {
      findings.push({
        code: "EXECUTABLE_MAGIC_BYTES",
        severity: "critical",
        detail: "File header matches a native executable binary, Java/Mach-O header, or interpreter shebang."
      });
    }

    const isZip =
      startsWithBytes(buf, MAGIC_ZIP_LOCAL) ||
      startsWithBytes(buf, MAGIC_ZIP_EMPTY) ||
      startsWithBytes(buf, MAGIC_ZIP_SPANNED);
    const isBzip2 =
      buf.length >= 4 &&
      buf[0] === 0x42 &&
      buf[1] === 0x5A &&
      buf[2] === 0x68 &&
      buf[3] >= 0x31 &&
      buf[3] <= 0x39;
    const isCab =
      startsWithBytes(buf, MAGIC_CAB) ||
      (buf.length >= 4 && buf.length < 8 && startsWithBytes(buf, [0x4D, 0x53, 0x43, 0x46]));
    const isCompressedArchive =
      startsWithBytes(buf, MAGIC_RAR) ||
      startsWithBytes(buf, MAGIC_7Z) ||
      startsWithBytes(buf, MAGIC_GZIP) ||
      startsWithBytes(buf, MAGIC_XZ) ||
      startsWithBytes(buf, MAGIC_ZSTD) ||
      isBzip2 ||
      isCab;

    if (
      (isCompressedArchive && !ARCHIVE_CONTAINER_EXTENSIONS.has(ext)) ||
      (isZip && !ARCHIVE_CONTAINER_EXTENSIONS.has(ext) && !ZIP_PACKAGE_EXTENSIONS.has(ext))
    ) {
      findings.push({
        code: "ARCHIVE_MAGIC_MISMATCH",
        severity: "high",
        detail: `File header matches a compressed/ZIP archive signature despite '.${ext || "none"}' extension.`
      });
    }

    if (startsWithBytes(buf, MAGIC_OLE2) && !OLE2_PACKAGE_EXTENSIONS.has(ext)) {
      findings.push({
        code: "OLE2_CONTAINER_MISMATCH",
        severity: "high",
        detail: `File header is a legacy OLE2 Compound File (capable of carrying VBA macros or encrypted streams) despite '.${ext || "none"}' extension.`
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
      rtf: {
        sigs: [MAGIC_RTF],
        code: "RTF_HEADER_MISMATCH",
        detail: "File claims '.rtf' extension but lacks '{\\rtf' header."
      },
      docx: {
        sigs: [MAGIC_ZIP_LOCAL, MAGIC_ZIP_EMPTY, MAGIC_ZIP_SPANNED],
        code: "OOXML_HEADER_MISMATCH",
        detail: "File claims '.docx' extension but lacks valid PK ZIP OOXML package header."
      },
      xlsx: {
        sigs: [MAGIC_ZIP_LOCAL, MAGIC_ZIP_EMPTY, MAGIC_ZIP_SPANNED],
        code: "OOXML_HEADER_MISMATCH",
        detail: "File claims '.xlsx' extension but lacks valid PK ZIP OOXML package header."
      },
      pptx: {
        sigs: [MAGIC_ZIP_LOCAL, MAGIC_ZIP_EMPTY, MAGIC_ZIP_SPANNED],
        code: "OOXML_HEADER_MISMATCH",
        detail: "File claims '.pptx' extension but lacks valid PK ZIP OOXML package header."
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

    if (TEXT_OR_LEGACY_DOC_EXTENSIONS.has(ext)) {
      const textSample = decodeTextSample(buf);
      if (containsActiveMarkupOrMht(textSample)) {
        findings.push({
          code: "HTML_SCRIPT_IN_PLAINTEXT",
          severity: "high",
          detail: `File claims '.${ext}' format but contains active HTML, MHTML, SVG, object, or event-handler markup.`
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
