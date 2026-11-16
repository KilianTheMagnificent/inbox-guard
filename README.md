# inbox-guard

[![CI](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/ci.yml) [![CodeQL](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/KilianTheMagnificent/inbox-guard/actions/workflows/codeql.yml)

Zero-dependency defensive validation and deterministic PII redaction for back-office workflows that ingest untrusted business emails, attachments, and accounting CSV exports.

Built for human-in-the-loop operational pipelines where inbound mail and spreadsheet exports must be screened before any text reaches an external language model or downstream review queue.

## Defensive checks included

- **Untrusted attachment screening (`checkAttachment`):**
  - Blocks executable, script, disk-image, and macro-enabled Office extensions (`.exe`, `.scr`, `.lnk`, `.xlsm`, `.docm`, `.dmg`, etc.).
  - Flags double-extension decoys (`PO_1042.pdf.exe`), path-traversal filenames (`../../`), and Unicode bidirectional override spoofing (`U+202E`).
  - Verifies leading magic bytes against claimed file types (catches native `MZ` / `ELF` / `Mach-O` binaries renamed to `.pdf`, invalid `%PDF-` / PNG headers, and HTML/script tags hidden inside `.csv` or `.txt` files).
- **CSV / spreadsheet formula-injection neutralization (`sanitizeCsvRows`):**
  - Neutralizes OWASP CSV/DDE payloads (`=`, `+`, `-`, `@`, and tab/newline-prefixed formulas) before exports are opened by finance or operations staff.
  - Preserves genuine negative currency and decimal values (e.g. `-1,250.00`) so accounting figures are not corrupted.
- **Inbound email anomaly & prompt-injection inspection (`inspectInboundEmail`):**
  - Strips invisible zero-width and Unicode Tag characters (`U+E0000..U+E007F`) often used to conceal instructions from human reviewers.
  - Flags CSS-hidden HTML blocks (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`), `From` vs. `Reply-To` domain mismatches, and untrusted instruction-override phrases.
- **Deterministic session-scoped PII redaction (`createRedactor`):**
  - Replaces email addresses, phone numbers, US SSNs, and long account/card numbers with consistent local placeholders (`<EMAIL_1>`, `<PHONE_1>`, `<ACCOUNT_1>`) prior to model calls and restores them locally for human review.

## Quick start

Requires Node.js 20+ (zero external runtime or dev dependencies).

```js
import {
  checkAttachment,
  sanitizeCsvRows,
  inspectInboundEmail,
  createRedactor
} from "./src/index.mjs";

const attachmentCheck = checkAttachment({
  filename: "vendor-invoice.pdf",
  headBytes: new TextEncoder().encode("%PDF-1.7\n")
});
// -> { safe: true, extension: 'pdf', findings: [] }

const redactor = createRedactor();
const safePromptText = redactor.redact("Reply to ap@acme.example or (314) 555-0199");
// -> "Reply to <EMAIL_1> or <PHONE_1>"
```

## Run tests

```bash
npm test
```

## License

MIT © [Andre Romero-Carey](https://meetkestrel.com)
