#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { checkAttachment, inspectInboundEmail, createRedactor } from "../src/index.mjs";

const [cmd, arg] = process.argv.slice(2);

function usage() {
  console.error(
    "Usage:\n" +
      "  inbox-guard check-attachment <path>\n" +
      "  inbox-guard inspect-email <json-file>\n" +
      "  inbox-guard redact <text-file>"
  );
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
    const result = inspectInboundEmail(payload);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.safe ? 0 : 2);
  } else if (cmd === "redact") {
    const raw = readFileSync(arg, "utf8");
    const redactor = createRedactor();
    console.log(redactor.redact(raw));
  } else {
    usage();
  }
} catch (err) {
  console.error(`inbox-guard error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
