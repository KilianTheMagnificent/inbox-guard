# inbox-guard

[![CI](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/ci.yml) [![CodeQL](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/codeql.yml)

Zero-dependency Node.js input screening and session-scoped PII tokenization for untrusted inbound emails, file attachments, and CSV exports.

Designed as a pre-triage filter before untrusted office inputs are sent to an external language model or opened by operations staff.

## Try it on a message

With Git and Node.js 20 or newer installed, run these commands in a terminal on macOS or Linux. Cloning provides everything the command needs.

```sh
git clone https://github.com/KilianTheMagnificent/inbox-guard.git
cd inbox-guard
printf '%s\n' 'Send invoice 42 to orders@example.org.' | node ./bin/inbox-guard.mjs redact -
```

The output will look like this. The six-character suffix varies on each run.

```text
Send invoice 42 to <EMAIL_1_9f2c1a>.
```

On macOS, copy a sample message and run `pbpaste | node ./bin/inbox-guard.mjs redact -` to preview it in the terminal. The command reads the whole message locally and preserves its line breaks. Review the result before sharing it. Names and street addresses can remain in the text.

## Screen a CSV export

From the repository folder, check the included four-invoice example, then create a reviewed copy.

```sh
node ./bin/inbox-guard.mjs check-csv examples/invoices.csv
node ./bin/inbox-guard.mjs sanitize-csv examples/invoices.csv --output reviewed-invoices.csv
node ./bin/inbox-guard.mjs check-csv reviewed-invoices.csv
```

The first command reports row 3 and row 5, both in column 4. Counting starts at 1 and includes the header. The copy prefixes each flagged cell with an apostrophe and preserves the refund of `-42.50`. The last command reports five rows, four columns and zero findings. The report lists positions only. An existing output file is protected from replacement.

Both commands accept `-` for piped input. Omitting `--output` writes the CSV to standard output. For a saved copy, use `--output` so the shell cannot truncate the source by redirecting output to the same path. Screening returns exit code 0 for a clear result, 2 for findings, or 1 for an input or command error. Creating a copy succeeds with exit code 0.

Follow the [hands-on verification guide](docs/checking-a-change.md) to compare the files yourself or reuse the worksheet for another tool.

## Modules

### 1. Attachment screening (`src/attachment.mjs` — `checkAttachment`)

Inspects an untrusted filename and optional leading byte slice (`Uint8Array`, `ArrayBuffer`, `TypedArray`, or byte array):

- **Blocked extensions (`BLOCKED_EXTENSION`):** Rejects executables, scripts, shortcuts, disk images, Windows packages/scriptlets, OneNote packages, spreadsheet add-in/query formats, and macro-capable Office formats (`.exe`, `.scr`, `.bat`, `.ps1`, `.ps1xml`, `.vbs`, `.vb`, `.js`, `.wsc`, `.sct`, `.hta`, `.lnk`, `.iso`, `.dmg`, `.appx`, `.msix`, `.application`, `.library-ms`, `.search-ms`, `.settingcontent-ms`, `.one`, `.doc`, `.dot`, `.xls`, `.xla`, `.xlsb`, `.ppt`, `.docm`, `.xlsm`, `.pptm`, `.xll`, `.iqy`, `.slk`, etc.).
- **Active local markup (`ACTIVE_CONTENT_EXTENSION`):** Rejects `.svg`, `.svgz`, `.html`, `.htm`, `.xhtml`, `.shtml`, `.htmlz`, `.mht`, `.mhtml`, `.xml`, `.xsl`, `.xslt`, `.swf`, and `.eml` files that can execute embedded scripts or active external loads when opened locally.
- **Uninspected archives (`UNINSPECTED_ARCHIVE_CONTAINER`):** Flags `.zip`, `.7z`, `.rar`, `.tar`, `.gz`, `.tgz`, `.bz2`, `.xz`, `.zst`, `.cab`, and `.msg` containers whose inner entries have not been extracted and checked individually.
- **Filename canonicalization & spoofing checks:** Catches Unicode bidirectional controls (`UNICODE_BIDI_SPOOF`), Unicode dot-leader/fullwidth period lookalikes (`UNICODE_DOT_SPOOF`, e.g. `U+2024`), directory separators and Windows drive prefixes (`PATH_TRAVERSAL_FILENAME`, without false-positiving on benign double dots like `Acme Inc..pdf`), NTFS `:stream` / `::$DATA` / trailing `:` Alternate Data Streams (`NTFS_ADS_FILENAME`, without false-positiving on benign timestamps like `Invoice 10:30.pdf` or `A: Smith.pdf`), Windows/shell illegal wildcard or redirection characters (`INVALID_FILENAME_CHARS`: `<`, `>`, `"`, `|`, `?`, `*`), non-alphanumeric or `;version`-suffixed extensions (`MALFORMED_EXTENSION`, e.g. `invoice.exe;1`), Windows reserved DOS/NT device stems (`WINDOWS_RESERVED_FILENAME`: `CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`, including `CON:.pdf`), Windows/SMB trailing dots and whitespace (`TRAILING_DOT_OR_SPACE`), null/whitespace/Unicode-filler padding (`EXTENSION_PADDING`), ASCII/C1 control and null bytes (`CONTROL_CHAR_FILENAME`), and double-extension decoys (`DOUBLE_EXTENSION_DECOY`, e.g. `PO_1042.pdf.exe`).
- **Magic-byte verification:** Detects native `MZ`, `ELF`, `Mach-O`, and `#!` shebang headers (`#!/bin/sh`, `#! /bin/sh`) regardless of extension (`EXECUTABLE_MAGIC_BYTES`), compressed or `PK` ZIP archive headers disguised under non-archive/non-OOXML extensions (`ARCHIVE_MAGIC_MISMATCH`: `PK`, `Rar!`, `7z`, `gzip`, `bzip2`, `xz`, `zstd`, `MSCF` CAB), legacy OLE2 Compound File headers disguised as `.docx`/`.xlsx`/`.pptx` or plaintext (`OLE2_CONTAINER_MISMATCH`), header mismatches on `.pdf`, `.png`, `.jpg`/`.jpeg`, `.gif`, `.rtf`, and `.docx`/`.xlsx`/`.pptx` (`PDF_HEADER_MISMATCH`, `PNG_HEADER_MISMATCH`, `JPEG_HEADER_MISMATCH`, `GIF_HEADER_MISMATCH`, `RTF_HEADER_MISMATCH`, `OOXML_HEADER_MISMATCH`), and HTML/MHTML/SVG/object/inline-event-handler markup (including UTF-16LE/BE BOM streams) inside plaintext or legacy document files (`HTML_SCRIPT_IN_PLAINTEXT`). Short or empty `headBytes` buffers report `TRUNCATED_OR_EMPTY_BYTES` rather than returning false-clean or false-mismatch results.

### 2. CSV formula neutralization (`src/csv.mjs` — `isFormulaInjectionCell`, `sanitizeCsvCell`, `sanitizeCsvRows`, `serializeCsvRow`)

- **OWASP formula/DDE triggers:** Flags cells starting with `=`, `+`, `-`, `@`, or `|` (configurable via `{ allowPipeTrigger: true }`), plus fullwidth/small Unicode variants (`＝`, `＋`, `－`, `＠`), including payloads preceded by ASCII/C1 control characters (`\t`, `\r`, `\n`, `\x0B`, `\x0C`, `\x7F`), Unicode whitespace (`U+00A0`, `U+3000`, `U+2028`, `U+FEFF`), zero-width/filler format characters (`U+200B`, `U+3164`), or leading double quotes (`"=CMD..."`).
- **Accounting negative preservation:** Allows negative numeric balances with optional currency symbols, thousands separators, decimals, scientific notation, and percentages (`-1,420.55`, `-$1,250.00`, `-1,250.00€`, `-.50`, `-12.5%`, `-1.5E3`) as well as parenthesized accounting negatives (`($1,250.00)`), while still flagging formula expressions (`-$A1`, `-SUM(A1:A4)`, `-1+1`, `-\n1+1`, `-\t=1+1`) and control-prefixed values (`\x0B-1250.00`).
- **Parsed array contract & RFC-4180 serialization:** `sanitizeCsvRows(rows)` validates and scans parsed 2D cell arrays (`string[][]`). `serializeCsvRow(row)` sanitizes cells (idempotently prefixing `'`) and formats a single RFC-4180 row with internal `"` doubled and fields containing commas, quotes, line breaks, control whitespace, leading/trailing spaces, or neutralized `'` prefixes enclosed in double quotes.

### 3. Inbound email inspection (`src/email.mjs` — `inspectInboundEmail`)

- **Sender header & comment spoofing:** Parses RFC 5322 `From` and multi-address `Reply-To` headers (distinguishing `<angle-addr>`, quoted strings, `(comment)` blocks, and RFC 2047 `=?...?=` encoded words) to flag `From` display-name or comment spoofing (`FROM_DISPLAY_NAME_SPOOF`, including fullwidth `＠`, HTML `&#64;`, spaced `ceo @ company.com`, and Cyrillic/Greek lookalikes) alongside `Reply-To` domain mismatches across any listed `Reply-To` address (`REPLY_TO_DOMAIN_MISMATCH`).
- **Invisible Unicode stripping (`INVISIBLE_UNICODE_CHARS`):** Strips soft hyphens (`U+00AD`), zero-width spaces/joiners, bidi controls, Hangul/Braille/Khmer fillers (`U+3164`, `U+2800`, `U+FFA0`, `U+17B4..U+17B5`), interlinear annotations (`U+FFF9..U+FFFB`), BMP Variation Selectors (`U+FE00..U+FE0F`), Unicode Tags (`U+E0000..U+E007F`), and Variation Selectors Supplement (`U+E0100..U+E01EF`) — including entity-encoded forms in HTML (`&#8203;`, `&#xE0041;`) — from `sanitizedSubject` and `sanitizedText`.
- **Linear `O(n)` HTML5 & CSS hidden-content scanner (`HIDDEN_HTML_CONTENT`):** Uses a WHATWG HTML5 comment scanner (`<!-->`, `<!--->`, `<!-- ... --!>`, and unclosed `<!--` resilience), arbitrary zero-padded numeric/named HTML entity decoding, CSS `/*...*/` comment stripping, CSS backslash escape decoding, and a linear semicolon-delimited CSS declaration parser (zero backtracking regexes) to detect `display:none`, `visibility:hidden|collapse`, `content-visibility:hidden`, `opacity <= 0.02`, `font-size <= 1px`, `color:transparent` / near-zero alpha `rgba()`, matching foreground/background colors (`color:#fff;background:#fff`), zero-size `overflow:hidden|clip` boxes, off-screen negative offsets (`left:-999px`, `margin-left:-9999px`, `text-indent:-9999em`), near-zero `transform:scale(...)` / `scale:0`, `clip:rect(0,0,0,0)` / `clip-path:circle(0)|inset(50%)`, HTML `hidden`, `aria-hidden="true"`, collapsed `<details>`, `<input type="hidden">`, and `<template>`, while skipping conditional `@media (...)` responsive layout rules in `<style>`.
- **Override phrase heuristics (`INSTRUCTION_OVERRIDE_PATTERN`):** Checks confusable-folded plain text and comment/tag-stripped HTML text for explicit instruction-override phrases.

### 4. Session-scoped PII tokenization (`src/redact.mjs` — `createRedactor`)

- Replaces structured ASCII emails, hyphenated/spaced/dash-separated US SSNs, NANP and `+`-prefixed international E.164/E.123 phone numbers (including `(0)` trunk prefixes and `ext`/`extension`/`x` suffixes), and 12–19 digit contiguous or grouped payment card/account numbers with session-consistent, CSPRNG-nonced placeholders (`<EMAIL_1_9f2c1a>`, `<SSN_1_9f2c1a>`, `<PHONE_1_9f2c1a>`, `<ACCOUNT_1_9f2c1a>`) in a single regex pass.
- Because placeholders carry a random 6-hex-character per-session nonce by default, untrusted senders cannot guess or forge valid restoration tokens even if a downstream language model normalizes obfuscated `<ACCOUNT\u200B_1>` or fullwidth `＜ACCOUNT_1＞` text. Pre-existing token-like strings in untrusted input are additionally isolated as `<LITERAL_n_nonce>`, and `restore()` performs a single-pass regex map lookup so literal token text inside an original PII value never undergoes second-pass substitution. Pass `{ deterministic: true }` only when bare `<EMAIL_1>` tokens without a random nonce are explicitly required.

## Usage

Requires Node.js 20+ (no external dependencies).

```js
import {
  checkAttachment,
  sanitizeCsvRows,
  serializeCsvRow,
  inspectInboundEmail,
  createRedactor
} from "./src/index.mjs";

const attachment = checkAttachment({
  filename: "vendor-invoice.pdf",
  headBytes: new TextEncoder().encode("%PDF-1.7\n")
});
// -> { safe: true, extension: 'pdf', findings: [] }

const csvResult = sanitizeCsvRows([
  ["Vendor", "Balance", "Memo"],
  ["Acme, Inc.", "-$1,250.00", '=CMD|\' /C calc\'!A0']
]);
const csvLine = serializeCsvRow(csvResult.rows[1]);
// -> '"Acme, Inc.","-$1,250.00","\'=CMD|\' /C calc\'!A0"'

const redactor = createRedactor();
const redacted = redactor.redact("Call +44 20 7946 0958 ext. 12 or email ap@acme.example");
// -> "Call <PHONE_1_9f2c1a> or email <EMAIL_1_9f2c1a>" (6-hex per-session random nonce)
const restored = redactor.restore(redacted);
// -> "Call +44 20 7946 0958 ext. 12 or email ap@acme.example"
```

CLI entry point (`./bin/inbox-guard.mjs`):

```bash
node ./bin/inbox-guard.mjs check-attachment ./sample.pdf
node ./bin/inbox-guard.mjs inspect-email ./email.json
node ./bin/inbox-guard.mjs redact ./message.txt
```

## Scope & Known Limitations

1. **Pattern-only PII redaction (`src/redact.mjs`):** Tokenization is strictly regex-based. It covers standard and quoted ASCII RFC 5321/5322 emails, hyphen/space/dash-separated US SSNs (`DDD-DD-DDDD`), NANP 10/11-digit phones, `+`-prefixed ITU-T E.164/E.123 phones (7–15 digits), and 12–19 digit contiguous or `4-4-4-1..7` / `4-4-4-4-1..3` / `4-6-5` grouped account/card numbers. It **does not** detect unstructured person or company names, street addresses, non-ASCII UTF-8/IDN email addresses (`josé@example.com`, `user@bücher.de`) unless converted to ASCII/Punycode upstream, alphanumeric IBANs, 8–11 digit domestic bank account numbers or contiguous 9-digit SSNs/ABA routing numbers (excluded to avoid high false-positive rates on order/invoice IDs; conversely, bare 12–19 digit integers such as 13-digit millisecond Unix timestamps are tokenized as `<ACCOUNT>`), or domestic non-NANP phone numbers written without a `+` country code. Token mappings live only in in-process memory.
2. **Leading-header attachment checks (`src/attachment.mjs`):** `checkAttachment` inspects filenames and leading magic bytes at byte offset 0. It **does not** parse full container structures, unpack archives, run antivirus signatures, detect polyglot payloads appended after a valid `%PDF-` header, or inspect structurally valid PDF streams for `/JavaScript` / `/OpenAction` dictionaries or OOXML `.docx`/`.xlsx` packages for external template relationships. Archive extensions are flagged `UNINSPECTED_ARCHIVE_CONTAINER` and legacy binary Office extensions (`.doc`, `.xls`, `.ppt`) are blocked because macro streams inside OLE2 containers cannot be ruled out from header bytes alone.
3. **Header & HTML email screening (`src/email.mjs`):** `inspectInboundEmail` checks RFC 5322 `From`/`Reply-To` headers and static HTML/CSS hiding constructs, not cryptographic sender authentication (`SPF`, `DKIM`, `DMARC` must be verified by the receiving mail gateway) or full browser layout/cascade computation across separate ancestor/descendant rules (e.g., `color:white` on a child whose white background is inherited from an outer table cell, or `Reply-To` across authorized parent/child subdomains such as `mail.vendor.example` vs `vendor.example`, which still raises a medium-severity domain-mismatch signal for caller review). `INSTRUCTION_OVERRIDE_PATTERN` rules are static phrase heuristics that an adaptive attacker can paraphrase; never rely on them in place of architectural privilege separation, tool allowlists, and human approval gates before external sends or financial actions.
4. **CSV format and import settings.** The commands read UTF-8 comma-separated text in memory. Each record must have the same number of fields. Quoted fields can contain commas, doubled quotes, and embedded line breaks. The output uses CRLF record separators and preserves a UTF-8 byte-order mark when present. Supply spreadsheet exports with comma delimiters and import the result using the same delimiter. Spreadsheet type inference, display of the leading apostrophe and behavior after re-saving depend on the application and import settings. JavaScript callers can use `checkCsvText` and `sanitizeCsvText` for comma-separated text, or `sanitizeCsvRows` for arrays of cells. The raw-text report numbers coordinates from 1. The array API numbers indexes from 0.

## Tests

```bash
npm test
```

## Project status and how this was built

The 0.1 series provides a local command-line tool and a JavaScript library. Andre directs development with AI coding assistants. Codex implemented the piped redaction and CSV file commands and checked them with invented messages and invoices. You can repeat that check using the example above.

Bug reports and documentation feedback are welcome. See the [contribution guide](CONTRIBUTING.md).

## License

MIT © [Andre Romero-Carey](https://kilianthemagnificent.github.io)
