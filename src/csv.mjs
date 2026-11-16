const FORMULA_TRIGGERS = new Set(["=", "+", "-", "@"]);

// Leading ASCII control chars (including \t, \n, \x0B vertical tab, \x0C form feed, \r, \x00),
// spaces, NBSP, BOM, and leading double quotes (`"=CMD..."`).
const LEADING_CONTROL_OR_QUOTE_RE = /^[\x00-\x20\u00A0\uFEFF"]+/;
const LEADING_CONTROL_CHAR_RE = /^[\x00-\x1F\x7F]/;

// Negative numeric balances with optional currency symbol ($, €, £, ¥), thousands commas,
// decimal fraction, and percent sign. Excludes letters, colons, parens, and operators so
// cell references (`-$A1`) and formulas (`-SUM(...)`, `-1+1`) are still flagged.
const SAFE_NEGATIVE_NUMBER_RE = /^-\s?[$€£¥]?(?:\d+(?:,\d{3})*(?:\.\d+)?|\.\d+)%?$/;

/**
 * Check whether a single spreadsheet/CSV cell could trigger formula or DDE
 * execution when opened in Excel, LibreOffice Calc, or Google Sheets.
 *
 * Covers OWASP CSV Injection triggers (`=`, `+`, `-`, `@`), leading control/whitespace
 * prefixes (`\t`, `\r`, `\n`, `\x0B` vertical tab, `\x0C` form feed, `\x00`, BOM, NBSP),
 * and quote-wrapped triggers (`"=CMD..."`).
 *
 * Negative accounting numbers (`-142.50`, `-1,200.00`, `-$1,250.00`) and parenthesized
 * balances (`($1,250.00)`) are allowed by default so financial exports are not corrupted.
 */
export function isFormulaInjectionCell(value, { allowNegativeNumbers = true } = {}) {
  if (typeof value !== "string" || value.length === 0) return false;

  const stripped = value.replace(LEADING_CONTROL_OR_QUOTE_RE, "");
  if (stripped.length === 0) return false;

  const first = stripped[0];
  if (!FORMULA_TRIGGERS.has(first)) return false;

  // Never exempt `-` when preceded by ASCII control characters (\t, \r, \n, \x0B, \x0C, etc.)
  if (LEADING_CONTROL_CHAR_RE.test(value)) return true;

  if (first === "-" && allowNegativeNumbers) {
    const candidate = stripped.replace(/[\s"]+$/, "");
    if (SAFE_NEGATIVE_NUMBER_RE.test(candidate)) {
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
 * by default unless `{ sanitize: false }` is passed.
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
      if (/[,"\r\n\t\x0B\x0C]/.test(val) || val !== val.trim()) {
        return `"${val.replaceAll('"', '""')}"`;
      }
      return val;
    })
    .join(",");
}
