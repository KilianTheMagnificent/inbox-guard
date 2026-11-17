#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { checkAttachment, inspectInboundEmail, createRedactor } from "../src/index.mjs";

const [cmd, arg] = process.argv.slice(2);

const USAGE_TEXT =
  "Usage:\n" +
  "  inbox-guard check-attachment <path>\n" +
  "  inbox-guard inspect-email <json-file>\n" +
  "  inbox-guard redact <text-file|->\n" +
  "    Use - to read UTF-8 text from standard input.";

if (cmd === "--help" || cmd === "-h") {
  console.log(USAGE_TEXT);
  process.exit(0);
}

function usage() {
  console.error(USAGE_TEXT);
  process.exit(1);
}

if (!cmd || !arg) usage();

try {
  if (cmd === "check-attachment") {
    const bytes = readFileSync(arg);
    const filename = arg.split(/[/\\]/).pop() ?? arg;
    const result = checkAttachment({ filename, headBytes: bytes.subarray(0, 4096) });
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.safe ? 0 : 2);
  } else if (cmd === "inspect-email") {
    const payload = JSON.parse(readFileSync(arg, "utf8"));
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      throw new TypeError("Email JSON file must contain a JSON object.");
    }
    const result = inspectInboundEmail(payload);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.safe ? 0 : 2);
  } else if (cmd === "redact") {
    const fromStdin = arg === "-";
    const raw = readFileSync(fromStdin ? 0 : arg, "utf8");
    const redacted = createRedactor().redact(raw);
    if (fromStdin) {
      process.stdout.write(redacted);
    } else {
      console.log(redacted);
    }
  } else {
    usage();
  }
} catch (err) {
  console.error(`inbox-guard error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
