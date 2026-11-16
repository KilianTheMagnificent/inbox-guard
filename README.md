# inbox-guard

[![CI](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/ci.yml) [![CodeQL](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/codeql.yml)

Zero-dependency Node.js input screening and session-scoped PII tokenization for untrusted inbound emails, file attachments, and CSV exports.

Designed as a pre-triage filter before untrusted office inputs are sent to an external language model or opened by operations staff.

## Modules

### 1. Attachment screening (`src/attachment.mjs` — `checkAttachment`)

Inspects an untrusted filename and optional leading byte slice (`Uint8Array`, `ArrayBuffer`, `TypedArray`, or byte array):

- **Blocked extensions (`BLOCKED_EXTENSION`):** Rejects executables, scripts, shortcuts, disk images, macro-enabled Office packages, and spreadsheet add-in/query formats (`.exe`, `.scr`, `.bat`, `.ps1`, `.vbs`, `.js`, `.hta`, `.lnk`, `.iso`, `.dmg`, `.docm`, `.xlsm`, `.pptm`, `.xll`, `.iqy`, `.slk`, etc.).
- **Active local markup (`ACTIVE_CONTENT_EXTENSION`):** Rejects `.svg`, `.svgz`, `.html`, `.htm`, `.xhtml`, `.shtml`, `.mht`, `.mhtml`, `.xml`, `.xsl`, `.xslt`, and `.swf` files that execute JavaScript or external loads when opened locally in a browser.
- **Uninspected archives (`UNINSPECTED_ARCHIVE_CONTAINER`):** Flags `.zip`, `.7z`, `.rar`, `.tar`, `.gz`, `.tgz`, `.bz2`, `.xz`, `.zst`, and `.cab` containers whose inner entries have not been extracted and checked individually.
- **Filename canonicalization & spoofing checks:** Catches Unicode bidirectional overrides (`UNICODE_BIDI_SPOOF`), directory traversal and drive prefixes (`PATH_TRAVERSAL_FILENAME`), NTFS `:` Alternate Data Streams (`NTFS_ADS_FILENAME`), Windows/SMB trailing dots and trailing whitespace (`TRAILING_DOT_OR_SPACE`), null/whitespace padding around extensions (`EXTENSION_PADDING`), control/null bytes including pre-null extension truncation (`CONTROL_CHAR_FILENAME`), and double-extension decoys (`DOUBLE_EXTENSION_DECOY`, e.g. `PO_1042.pdf.exe` or `receipt.pdf.svg`).
- **Magic-byte verification:** Detects native `MZ`, `ELF`, `Mach-O`, and `#!/` headers regardless of extension (`EXECUTABLE_MAGIC_BYTES`), compressed archive headers on non-archive extensions (`ARCHIVE_MAGIC_MISMATCH`), header mismatches on `.pdf`, `.png`, `.jpg`/`.jpeg`, `.gif`, and `.docx`/`.xlsx`/`.pptx` (`PDF_HEADER_MISMATCH`, `PNG_HEADER_MISMATCH`, `JPEG_HEADER_MISMATCH`, `GIF_HEADER_MISMATCH`, `OOXML_HEADER_MISMATCH`), and HTML/SVG/script markup inside `.csv` or `.txt` files (`HTML_SCRIPT_IN_PLAINTEXT`). Short or empty `headBytes` buffers report `TRUNCATED_OR_EMPTY_BYTES` rather than returning false-clean or false-mismatch results.

### 2. CSV formula neutralization (`src/csv.mjs` — `isFormulaInjectionCell`, `sanitizeCsvCell`, `sanitizeCsvRows`, `serializeCsvRow`)

- **OWASP formula/DDE triggers:** Flags cells starting with `=`, `+`, `-`, or `@`, including payloads preceded by spaces, tabs (`\t`), CR/LF (`\r`, `\n`), vertical tab (`\x0B`), form feed (`\x0C`), null/BOM/NBSP characters, or leading double quotes (`"=CMD..."`).
- **Accounting negative preservation:** Allows negative numeric balances with optional currency symbols, thousands separators, decimals, percentages (`-1,420.55`, `-$1,250.00`, `-€99.95`, `-.50`, `-12.5%`), and parenthesized accounting negatives (`($1,250.00)`), while still flagging formula expressions (`-$A1`, `-SUM(A1:A4)`, `-1+1`) and control-prefixed values (`\x0B-1250.00`).
- **Parsed array contract & RFC-4180 serialization:** `sanitizeCsvRows(rows)` operates on parsed 2D cell arrays (`string[][]`). `serializeCsvRow(row)` sanitizes cells (idempotently prefixing `'`) and formats a single RFC-4180 row with internal `"` doubled and fields containing commas, quotes, CR/LF, or control whitespace enclosed in double quotes.

### 3. Inbound email inspection (`src/email.mjs` — `inspectInboundEmail`)

- **Sender header spoofing:** Parses RFC 5322 `From` and `Reply-To` headers (including RFC 2047 encoded words and quoted display strings) to flag `From` display-name spoofing (`FROM_DISPLAY_NAME_SPOOF`, e.g. `"ceo@company.com" <attacker@evil.com>`) alongside `Reply-To` domain mismatches (`REPLY_TO_DOMAIN_MISMATCH`).
- **Invisible Unicode stripping (`INVISIBLE_UNICODE_CHARS`):** Strips soft hyphens (`U+00AD`), zero-width spaces/joiners, bidi controls, Unicode Tags (`U+E0000..U+E007F`), and Variation Selectors Supplement (`U+E0100..U+E01EF`) from `sanitizedSubject` and `sanitizedText`.
- **Hidden HTML/CSS inspection (`HIDDEN_HTML_CONTENT`):** Decodes HTML decimal, hex, and named character references (`&#58;`, `&#x3a;`, `&colon;`), strips CSS `/*...*/` comments, and decodes CSS backslash escapes before checking inline `style` attributes and `<style>` blocks for `display:none`, `visibility:hidden|collapse`, `opacity:0`, `font-size:0`, `color:transparent` / zero-alpha `rgba()`, off-screen negative offsets, `scale(0)`, and `inset(100%)`. Also flags HTML `hidden`, `aria-hidden="true"`, `<input type="hidden">`, and `<template>` elements via a linear `O(n)` tag scanner.
- **Override phrase heuristics (`INSTRUCTION_OVERRIDE_PATTERN`):** Checks normalized plain text and comment/tag-stripped HTML text for explicit instruction-override phrases.

### 4. Session-scoped PII tokenization (`src/redact.mjs` — `createRedactor`)

- Replaces structured emails, hyphenated US SSNs, NANP and `+`-prefixed international E.164/E.123 phone numbers (including `ext`/`extension`/`x` suffixes), and 12–19 digit account/card numbers with deterministic placeholders (`<EMAIL_1>`, `<SSN_1>`, `<PHONE_1>`, `<ACCOUNT_1>`) in a single regex pass.
- Pre-existing `<EMAIL_n>` / `<SSN_n>` / `<PHONE_n>` / `<ACCOUNT_n>` strings in untrusted input are isolated as `<LITERAL_n>` during `redact()`, and `restore()` performs a single-pass regex lookup (`/<(?:EMAIL|SSN|PHONE|ACCOUNT|LITERAL)_\d+>/g`) so an original value containing literal `<PHONE_1>` text never undergoes second-pass substitution.

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
// -> "Call <PHONE_1> or email <EMAIL_1>"
const restored = redactor.restore(redacted);
```

CLI entry point (`./bin/inbox-guard.mjs`):

```bash
node ./bin/inbox-guard.mjs check-attachment ./sample.pdf
node ./bin/inbox-guard.mjs inspect-email ./email.json
node ./bin/inbox-guard.mjs redact ./message.txt
```

## Scope & Known Limitations

1. **Pattern-only PII redaction (`src/redact.mjs`):** Tokenization is strictly regex-based. It covers standard and quoted RFC 5321/5322 emails, hyphenated US SSNs (`DDD-DD-DDDD`), NANP 10/11-digit phones, `+`-prefixed ITU-T E.164/E.123 phones (7–15 digits), and 12–19 digit contiguous or `4-4-4-1..7` / `4-6-5` grouped account/card numbers. It **does not** detect unstructured person or company names, street addresses, alphanumeric IBANs, unhyphenated 9-digit SSNs (excluded to avoid false positives on 9-digit PO and routing numbers), or domestic non-NANP phone numbers written without a `+` country code. Token mappings live only in in-process memory.
2. **Leading-header attachment checks (`src/attachment.mjs`):** `checkAttachment` inspects filenames and leading magic bytes at byte offset 0. It **does not** parse full container structures, unpack archives, run antivirus signatures, detect polyglot payloads appended after a valid `%PDF-` header, or inspect structurally valid PDF streams for `/JavaScript` / `/OpenAction` dictionaries or OOXML `.docx`/`.xlsx` packages for external template injection. Archive extensions are flagged `UNINSPECTED_ARCHIVE_CONTAINER` so callers unpack and screen entries in an isolated sandbox.
3. **Header & HTML email screening (`src/email.mjs`):** `inspectInboundEmail` checks RFC 5322 `From`/`Reply-To` headers and static HTML/CSS hiding constructs, not cryptographic sender authentication (`SPF`, `DKIM`, `DMARC` must be verified by the receiving mail gateway) or full browser CSS cascade/color-contrast rendering (e.g., matching foreground and background colors inherited across nested tables). `INSTRUCTION_OVERRIDE_PATTERN` rules are static phrase heuristics that an adaptive attacker can paraphrase; never rely on them in place of architectural privilege separation, tool allowlists, and human approval gates before external sends or financial actions.
4. **Parsed CSV cell arrays (`src/csv.mjs`):** `sanitizeCsvRows` expects already-parsed 2D cell arrays, not raw CSV byte streams. Parse raw CSV files with an RFC-4180 parser before sanitization and emit rows via `serializeCsvRow`. Prefixing dangerous cells with `'` prevents formula execution in Excel, LibreOffice Calc, and Google Sheets, and leaves a literal leading `'` if the exported CSV is read by non-spreadsheet consumers.

## Tests

```bash
npm test
```

## License

MIT © [Andre Romero-Carey](https://meetkestrel.com)
