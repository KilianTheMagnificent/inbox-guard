import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkCsvText, sanitizeCsvText } from "../src/index.mjs";

const cli = "./bin/inbox-guard.mjs";
const sample = "./examples/invoices.csv";
const run = (args, input) => spawnSync(process.execPath, [cli, ...args], { input, encoding: "utf8" });

test("the example reports exact logical cells, independent of the line inside a memo", () => {
  const result = run(["check-csv", sample]);
  assert.equal(result.status, 2);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    safe: false, rowCount: 5, columnCount: 4,
    findings: [{ row: 3, column: 4 }, { row: 5, column: 4 }]
  });
});

test("CSV output preserves the BOM, embedded CRLF, quotes, Unicode, negative amounts and empty columns", () => {
  const input = '\uFEFFVendor,Balance,Memo,\r\n"Nord, Co",-42.50,"café\r\nsaid ""yes""",\rTest,0,=2+3,';
  const expected = '\uFEFFVendor,Balance,Memo,\r\n"Nord, Co",-42.50,"café\r\nsaid ""yes""",\r\nTest,0,"\'=2+3",\r\n';
  const cleaned = sanitizeCsvText(input);
  assert.equal(cleaned, expected);
  assert.equal(sanitizeCsvText(cleaned), cleaned);
  assert.deepEqual(checkCsvText(cleaned), { safe: true, rowCount: 3, columnCount: 4, findings: [] });
});

test("empty documents, empty fields and quoted one-column records remain distinguishable", () => {
  for (const [input, records] of [["", 0], ["\uFEFF", 0], ["\n", 1], ['""\n\n', 2], ['"a;b"', 1], ['"sep=",""', 1]]) {
    const cleaned = sanitizeCsvText(input);
    assert.equal(checkCsvText(cleaned).rowCount, records);
    assert.equal(sanitizeCsvText(cleaned), cleaned);
  }
});

test("invalid CSV produces an error without copying source contents or emitting partial results", () => {
  const cases = [
    ['a,b\n1,"private text', /row 2, column 2: missing closing quote/i],
    ['a,b\n1,part"ial', /row 2, column 2: unexpected character/i],
    ['a,b\n1,"ok"trailer', /after closing quote/],
    ['a,b\n1,2\n3', /row 3: expected 2 columns, found 1/i],
    ['a,b\n\n', /row 2: expected 2 columns/],
    ['a;b\nc;d', /delimiter/],
    ['a\tb\nc\td', /delimiter/],
    ['\uFEFFsep=,\r\na,b', /sep= directive/],
    ['a,\0b', /NUL/],
    [Buffer.from([0xc0, 0xaf]), /utf-8/i]
  ];
  for (const [input, error] of cases) {
    const result = run(["sanitize-csv", "-"], input);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, error);
    assert.doesNotMatch(result.stderr, /private text/);
  }
});

test("sanitizing creates a new copy, preserves the source, and refuses existing files and links", () => {
  const dir = mkdtempSync(join(tmpdir(), "csv-output-"));
  try {
    const original = readFileSync(sample, "utf8");
    const source = join(dir, "source.csv");
    const target = join(dir, "clean.csv");
    writeFileSync(source, original);
    const args = ["sanitize-csv", source, "--output", target];
    const created = run(args);
    assert.equal(created.status, 0, created.stderr);
    assert.equal(created.stdout, "");
    const cleaned = readFileSync(target, "utf8");
    assert.equal(cleaned, sanitizeCsvText(original));
    assert.equal(run(["check-csv", target]).status, 0);
    for (const file of [target, source]) {
      const result = run(["sanitize-csv", "-", "--output", file], "replacement");
      assert.equal(result.status, 1);
      assert.match(result.stderr, /already exists/);
    }
    const linked = join(dir, "link.csv");
    symlinkSync(source, linked);
    assert.equal(run(["sanitize-csv", "-", "--output", linked], "replacement").status, 1);
    assert.equal(readFileSync(target, "utf8"), cleaned);
    assert.equal(readFileSync(source, "utf8"), original);
    assert.equal(run(["sanitize-csv", "-", "--output", join(dir, "broken.csv")], 'a,"oops').status, 1);
    assert.deepEqual(readdirSync(dir).sort(), ["clean.csv", "link.csv", "source.csv"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
