import { linkSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

// Publish only complete output. A hard link also refuses an existing destination
// if another process creates it between validation and delivery.
export function writeNewFile(path, data) {
  const scratch = mkdtempSync(join(dirname(path), ".inbox-guard-"));
  try {
    const staged = join(scratch, "output");
    writeFileSync(staged, data, { mode: 0o600 });
    try {
      linkSync(staged, path);
    } catch (error) {
      if (error.code === "EEXIST") throw new Error("Output already exists. Choose a new filename.");
      throw error;
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}
