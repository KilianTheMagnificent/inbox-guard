const BASE_FORMULA_TRIGGERS = new Set([
  "=", "+", "-", "@",
  "\uFF1D", // Fullwidth '='
  "\uFF0B", // Fullwidth '+'
  "\uFF0D", // Fullwidth '-'
  "\uFF20", // Fullwidth '@'
  "\uFE66", // Small '='
  "\uFE62", // Small '+'
  "\uFE63", // Small '-'
  "\uFE6B"  // Small '@'
]);

// Leading ASCII/C1 controls (\x00-\x20, \x7F-\x9F), Unicode whitespace (\s: NBSP, ideographic space
// U+3000, line/paragraph separators U+2028/U+2029, etc.), invisible/zero-width/bidi/filler format
// characters (U+200B..U+200F, U+FEFF, U+3164, U+FE00..U+FE0F), and leading double quotes (`"=1+1"`).
const LEADING_CONTROL_SPACE_OR_QUOTE_RE =
  /^[\x00-\x20\x7F-\x9F\s\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB"]+/u;

const LEADING_UNSAFE_CONTROL_OR_INVISIBLE_RE =
  /^[\x00-\x1F\x7F-\x9F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB]/u;

// Negative numeric balances with optional currency symbol ($, €, £, ¥, ₩, ₹), thousands grouping,
// decimal fraction, scientific exponent (`-1.5E3`), and trailing currency/% sign. Uses literal
// ASCII space (0x20) rather than `\s` so `-\n1+1` and `-\t=1+1` are never exempted, and excludes
// operators/parens/colons/letters so `-$A1`, `-SUM(...)`, and `-1+1` are always flagged.
const SAFE_NEGATIVE_NUMBER_RE =
  /^-\x20?[$€£¥₩₹]?\x20?(?:\d{1,3}(?:[,.\x20]\d{3})+(?:[.,]\d+)?|\d+(?:[.,]\d+)?|\.\d+)(?:[eE]\d{1,3})?\x20?[$€£¥₩₹%]?$/;

function trimTrailingSpaceAndQuotes(str) {
  let end = str.length;
  while (end > 0) {
    const ch = str[end - 1];
    if (ch === '"' || ch === " ") {
      end -= 1;
    } else {
      break;
    }
  }
  return str.slice(0, end);
}

/**
 * Check whether a single spreadsheet/CSV cell could trigger formula or DDE
 * execution when opened in Excel, LibreOffice Calc, or Google Sheets.
 *
 * Covers OWASP CSV Injection triggers (`=`, `+`, `-`, `@`, `|`, plus fullwidth/small
 * Unicode variants `＝`, `＋`, `－`, `＠`), leading control/Unicode-whitespace/invisible
 * prefixes (`\t`, `\r`, `\n`, `\x0B`, `\x0C`, `\x7F`, NBSP, `U+3000`, `U+200B`, `U+2028`,
 * `U+FEFF`), and quote-wrapped triggers (`"=CMD..."`).
 *
 * Negative accounting numbers (`-142.50`, `-$1,250.00`, `-1,250.00€`, `-.50`, `-12.5%`)
 * and parenthesized balances (`($1,250.00)`) are allowed by default so financial exports
 * are not corrupted.
 */
export function isFormulaInjectionCell(
  value,
  { allowNegativeNumbers = true, allowPipeTrigger = false } = {}
) {
  if (typeof value !== "string" || value.length === 0) return false;

  const stripped = value.replace(LEADING_CONTROL_SPACE_OR_QUOTE_RE, "");
  if (stripped.length === 0) return false;

  const first = stripped[0];
  const isTrigger = BASE_FORMULA_TRIGGERS.has(first) || (!allowPipeTrigger && first === "|");
  if (!isTrigger) return false;

  // Never exempt `-` when preceded by control characters, line separators, or invisible format chars
  if (LEADING_UNSAFE_CONTROL_OR_INVISIBLE_RE.test(value)) return true;

  if (first === "-" && allowNegativeNumbers) {
    const candidate = trimTrailingSpaceAndQuotes(stripped);
    if (candidate.length <= 128 && SAFE_NEGATIVE_NUMBER_RE.test(candidate)) {
      return false;
    }
  }

  return true;
}

/**
 * Neutralize a dangerous CSV cell by prefixing a single quote (`'`), following
 * OWASP CSV Injection guidance. Idempotent on cells already prefixed with `'`.
 */
export function sanitizeCsvCell(value, options = {}) {
  const str = String(value ?? "");
  if (isFormulaInjectionCell(str, options)) {
    return `'${str}`;
  }
  return str;
}

/**
 * Scan and sanitize a 2D array of already-parsed CSV cell strings (`string[][]`),
 * returning both the cleaned rows and structured `(row, column)` coordinates of
 * neutralized formula payloads.
 *
 * Note: This function operates on parsed cell arrays, not raw CSV text. Pair with
 * a spec-compliant CSV parser on ingest and `serializeCsvRow` when emitting CSV text.
 */
export function sanitizeCsvRows(rows, options = {}) {
  if (!Array.isArray(rows)) {
    throw new TypeError("sanitizeCsvRows expects a 2D array of parsed CSV rows.");
  }

  const findings = [];
  const cleanedRows = rows.map((row, rowIndex) => {
    if (!Array.isArray(row)) {
      throw new TypeError(`Row at index ${rowIndex} must be an array of cell values.`);
    }
    return row.map((cell, colIndex) => {
      const str = String(cell ?? "");
      if (isFormulaInjectionCell(str, options)) {
        findings.push({
          row: rowIndex,
          column: colIndex,
          originalPreview: str.slice(0, 48)
        });
        return `'${str}`;
      }
      return str;
    });
  });

  return {
    safe: findings.length === 0,
    neutralizedCount: findings.length,
    findings,
    rows: cleanedRows
  };
}

/**
 * Serialize a single array of CSV cells into an RFC-4180-compliant row string
 * (without a trailing line break). Cells are sanitized with `sanitizeCsvCell`
 * by default unless `{ sanitize: false }` is passed, and single-quote-neutralized
 * formula cells are enclosed in double quotes per OWASP CSV guidance.
 */
export function serializeCsvRow(row, options = {}) {
  if (!Array.isArray(row)) {
    throw new TypeError("serializeCsvRow expects an array of cell values.");
  }
  const { sanitize = true, ...sanitizeOptions } = options;

  return row
    .map((cell) => {
      const raw = cell === null || cell === undefined ? "" : String(cell);
      const val = sanitize ? sanitizeCsvCell(raw, sanitizeOptions) : raw;
      if (
        /[,"\r\n\t\x0B\x0C\u2028\u2029]/.test(val) ||
        val.startsWith("'") ||
        val !== val.trim()
      ) {
        return `"${val.replaceAll('"', '""')}"`;
      }
      return val;
    })
    .join(",");
}
