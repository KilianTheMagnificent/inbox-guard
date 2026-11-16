const FORMULA_TRIGGERS = new Set(["=", "+", "-", "@"]);
const PLAIN_NEGATIVE_NUMBER_RE = /^-\d+(?:,\d{3})*(?:\.\d+)?%?$/;

/**
 * Check whether a single spreadsheet/CSV cell could trigger formula or DDE
 * execution when opened in Excel, LibreOffice Calc, or Google Sheets.
 * Plain negative numbers (e.g. "-142.50" or "-1,200.00") are allowed by default
 * so accounting exports do not corrupt legitimate negative balances.
 */
export function isFormulaInjectionCell(value, { allowNegativeNumbers = true } = {}) {
  if (typeof value !== "string" || value.length === 0) return false;
  const trimmedStart = value.replace(/^[\t\r\n ]+/, "");
  if (trimmedStart.length === 0) return false;

  const first = trimmedStart[0];
  if (value[0] === "\t" || value[0] === "\r" || value[0] === "\n") {
    if (FORMULA_TRIGGERS.has(first)) return true;
  }

  if (!FORMULA_TRIGGERS.has(first)) return false;
  if (first === "-" && allowNegativeNumbers && PLAIN_NEGATIVE_NUMBER_RE.test(trimmedStart.trim())) {
    return false;
  }
  return true;
}

/**
 * Neutralize a dangerous CSV cell by prefixing a single quote, following OWASP
 * CSV Injection guidance.
 */
export function sanitizeCsvCell(value, options = {}) {
  const str = String(value ?? "");
  if (isFormulaInjectionCell(str, options)) {
    return `'${str}`;
  }
  return str;
}

/**
 * Scan and sanitize a 2D array of parsed CSV rows, returning both the cleaned
 * rows and structured coordinates of neutralized formula payloads.
 */
export function sanitizeCsvRows(rows, options = {}) {
  const findings = [];
  const cleanedRows = rows.map((row, rowIndex) =>
    row.map((cell, colIndex) => {
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
    })
  );

  return {
    safe: findings.length === 0,
    neutralizedCount: findings.length,
    findings,
    rows: cleanedRows
  };
}
