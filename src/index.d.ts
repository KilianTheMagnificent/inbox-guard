export type FindingSeverity = "low" | "medium" | "high" | "critical";

export interface Finding {
  code: string;
  severity: FindingSeverity;
  detail: string;
}

export type HeadBytesInput = Uint8Array | ArrayBufferView | ArrayBuffer | number[];

export interface CheckAttachmentOptions {
  filename?: string;
  headBytes?: HeadBytesInput | null;
}

export interface AttachmentCheckResult {
  safe: boolean;
  extension: string | null;
  findings: Finding[];
}

export function checkAttachment(options?: CheckAttachmentOptions): AttachmentCheckResult;

export interface CsvFormulaOptions {
  allowNegativeNumbers?: boolean;
  allowPipeTrigger?: boolean;
}

export interface SerializeCsvRowOptions extends CsvFormulaOptions {
  sanitize?: boolean;
}

export interface CsvRowFinding {
  row: number;
  column: number;
  originalPreview: string;
}

export interface SanitizeCsvRowsResult {
  safe: boolean;
  neutralizedCount: number;
  findings: CsvRowFinding[];
  rows: string[][];
}

export function isFormulaInjectionCell(value: unknown, options?: CsvFormulaOptions): boolean;
export function sanitizeCsvCell(value: unknown, options?: CsvFormulaOptions): string;
export function sanitizeCsvRows(rows: unknown[][], options?: CsvFormulaOptions): SanitizeCsvRowsResult;
export function serializeCsvRow(row: unknown[], options?: SerializeCsvRowOptions): string;

export interface CsvTextFinding {
  row: number;
  column: number;
}

export interface CsvTextCheckResult {
  safe: boolean;
  rowCount: number;
  columnCount: number;
  findings: CsvTextFinding[];
}

export function checkCsvText(text: string): CsvTextCheckResult;
export function sanitizeCsvText(text: string): string;

export interface InboundEmailInput {
  from?: string;
  replyTo?: string;
  subject?: string;
  text?: string;
  html?: string;
}

export interface InboundEmailResult {
  safe: boolean;
  sanitizedSubject: string;
  sanitizedText: string;
  findings: Finding[];
}

export function inspectInboundEmail(input?: InboundEmailInput | null): InboundEmailResult;

export interface CreateRedactorOptions {
  deterministic?: boolean;
}

export interface RedactorStats {
  EMAIL: number;
  SSN: number;
  PHONE: number;
  ACCOUNT: number;
  totalUnique: number;
}

export interface Redactor {
  nonce: string | null;
  redact(input: unknown): string;
  restore(redactedText: unknown): string;
  stats(): RedactorStats;
}

export function createRedactor(options?: CreateRedactorOptions): Redactor;
