import { isFormulaInjectionCell, serializeCsvRow } from "./csv.mjs";

// Walk logical records so embedded line breaks never shift reported coordinates.
function* records(text) {
  if (typeof text !== "string") throw new TypeError("Expected CSV text as a string.");
  const special = /[",\r\n]/g;
  let pos = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  if (pos === text.length) return;
  if (/^sep=.[\r\n]?$/i.test(text.slice(pos, pos + 6))) {
    throw new Error("Export comma-separated CSV without a sep= directive.");
  }
  if (text.includes("\0")) throw new Error("Expected UTF-8 CSV without NUL bytes.");

  let rowNumber = 1;
  let width;
  while (pos < text.length) {
    const row = [];
    const quotedFirst = text[pos] === '"';
    for (;;) {
      let value;
      const quoted = text[pos] === '"';
      const start = quoted ? pos + 1 : pos;
      const location = () => `CSV row ${rowNumber}, column ${row.length + 1}`;
      if (quoted) {
        pos = text.indexOf('"', start);
        while (pos >= 0 && text[pos + 1] === '"') pos = text.indexOf('"', pos + 2);
        if (pos < 0) throw new Error(`${location()}: missing closing quote.`);
        value = text.slice(start, pos).replaceAll('""', '"');
        pos++;
      } else {
        special.lastIndex = pos;
        pos = special.exec(text)?.index ?? text.length;
        value = text.slice(start, pos);
      }

      const delimiter = text[pos];
      if (delimiter !== undefined && delimiter !== "," && delimiter !== "\r" && delimiter !== "\n") {
        throw new Error(`${location()}: unexpected character ${quoted ? "after closing quote" : "in unquoted field"}.`);
      }
      row.push(value);
      if (delimiter !== ",") break;
      pos++;
    }
    if (rowNumber === 1 && row.length === 1 && !quotedFirst && /[;\t]/.test(row[0])) {
      throw new Error("Ambiguous CSV delimiter. Export with commas or quote the single field.");
    }
    width ??= row.length;
    if (row.length !== width) {
      throw new Error(`CSV row ${rowNumber}: expected ${width} columns, found ${row.length}.`);
    }
    yield row;
    rowNumber++;
    if (text[pos] === "\r") pos++;
    if (text[pos] === "\n") pos++;
  }
}

/** Report spreadsheet coordinates, counting the header as row 1. */
export function checkCsvText(text) {
  const findings = [];
  let rowCount = 0;
  let columnCount = 0;
  for (const row of records(text)) {
    rowCount++;
    columnCount = row.length;
    row.forEach((cell, i) => {
      if (isFormulaInjectionCell(cell)) findings.push({ row: rowCount, column: i + 1 });
    });
  }
  return { safe: findings.length === 0, rowCount, columnCount, findings };
}

/** Validate the entire export before returning a copy with CRLF record separators. */
export function sanitizeCsvText(text) {
  const lines = [];
  for (const row of records(text)) {
    // Quote every single-field record so an empty field or delimiter-like text stays unambiguous.
    const line = serializeCsvRow(row);
    if (row.length === 1 && !line.startsWith('"')) {
      lines.push(`"${line}"`);
    } else if (/^sep=,$/i.test(line)) {
      lines.push(`"${row[0]}",`);
    } else {
      lines.push(line);
    }
  }
  const bom = text.startsWith("\uFEFF") ? "\uFEFF" : "";
  return lines.length ? bom + lines.join("\r\n") + "\r\n" : bom;
}
