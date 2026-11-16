import { randomBytes } from "node:crypto";

/**
 * Pattern scope for `createRedactor()`:
 * - EMAIL: Unquoted (`[A-Za-z0-9_%+-]...`, <=64 chars) or RFC 5321 quoted local-parts
 *   (`"..."`, <=62 chars) with standard DNS labels and a 2-24 letter ASCII TLD.
 * - SSN: Hyphenated, single-space, or dash-separated 9-digit US SSNs (`DDD-DD-DDDD`,
 *   `DDD DD DDDD`, `DDD–DD–DDDD`), excluding SSA-unassigned prefixes (`000`, `666`,
 *   `900-999`), group `00`, and serial `0000`. Contiguous 9-digit numbers remain excluded
 *   to avoid false positives on 9-digit ABA routing and PO numbers.
 * - INTL_PHONE: Explicit `+`-prefixed ITU-T E.164 / E.123 numbers (`+1`..`+999` country
 *   code, optional `(0)` trunk marker with or without trailing space, 7-15 digits validated
 *   before tokenization) plus optional extension suffix (`ext`, `ext.`, `extension`, `x`).
 * - ACCOUNT: 12-19 contiguous digits, or space/hyphen/dot-grouped 13-19 digit payment card
 *   numbers (`4-4-4-1..7`, `4-4-4-4-1..3`, and Amex `4-6-5`), bounded away from `+` phones,
 *   currency amounts, dates, and ISBNs.
 * - NANP_PHONE: 10-digit or `1`-prefixed 11-digit North American numbers (`(314) 555-0199`,
 *   `314-555-0199`, `314.555.0199`, `314-5550199`, `1 314 555 0199`, contiguous valid NANP
 *   `3145550199` / `13145550199`) plus optional extension suffix, excluding 4-part dotted
 *   software versions (`1.314.555.0199`).
 * - LITERAL & NONCE: Tokens carry a 6-hex-character CSPRNG per-session suffix by default
 *   (`<EMAIL_1_9f2c1a>`) so untrusted senders cannot forge or guess session placeholders
 *   even if a downstream model normalizes obfuscated `<ACCOUNT\u200B_1>` text; pre-existing
 *   token-shaped literals in input are also isolated as `<LITERAL_n_nonce>`. Pass
 *   `{ deterministic: true }` only when bare `<EMAIL_1>` tokens are explicitly required.
 */

const EXT_SUFFIX_SRC = String.raw`(?:[,;\s]{0,3}(?:[Ee][Xx][Tt]\.?\s{0,3}|[Ee][Xx][Tt][Ee][Nn][Ss][Ii][Oo][Nn]\s{1,3}|[Xx]\s?)\d{1,6}(?![A-Za-z\d]))?`;

const EMAIL_SRC = String.raw`(?:"[^"\\\r\n]{1,62}"|(?<![A-Za-z0-9_%+-]|[A-Za-z0-9]\.)[A-Za-z0-9_%+-][A-Za-z0-9._%+-]{0,63})@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b`;

const SSN_SRC = String.raw`(?<![\dA-Za-z.,$€£¥-])(?!000|666|9\d\d)\d{3}(?:-(?!00)\d{2}-(?!0000)\d{4}| (?!00)\d{2} (?!0000)\d{4}|[\u2010-\u2014](?!00)\d{2}[\u2010-\u2014](?!0000)\d{4})(?![\dA-Za-z]|[-.]\d)`;

const INTL_PHONE_SRC = String.raw`(?<![A-Za-z0-9+])\+[1-9](?:\d{6,14}|\d{0,2}(?:[-.\s]?\(0\))?(?:[-.\s]?\(\d{1,5}\)[-.\s]?\d{2,10}|[-.\s]?\d{1,5})(?:[-.\s]\d{2,10}){1,5})${EXT_SUFFIX_SRC}(?![A-Za-z\d]|\.\d)`;

const ACCOUNT_SRC = String.raw`(?<![+\dA-Za-z.,$€£¥]|\d[-.])(?:\d{12,19}|\d{4}(?:-\d{4}){2}(?:-\d{4}-\d{1,3}|-\d{1,7})|\d{4}(?: \d{4}){2}(?: \d{4} \d{1,3}| \d{1,7})|\d{4}(?:\.\d{4}){2}(?:\.\d{4}\.\d{1,3}|\.\d{1,7})|\d{4}(?:-\d{6}-\d{5}| \d{6} \d{5}))(?![\dA-Za-z]|[.,-]\d)`;

const NANP_PHONE_SRC = String.raw`(?<![+\dA-Za-z.,$€£¥]|\d[-.])(?:(?:1[-\s])?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]?\d{4}|1?[2-9]\d{2}[2-9]\d{6})${EXT_SUFFIX_SRC}(?![A-Za-z\d]|[.-]\d)`;

const LITERAL_TOKEN_SRC = String.raw`<(?:EMAIL|SSN|PHONE|ACCOUNT|LITERAL)_\d+(?:_[0-9a-fA-F]{4,16})?>`;

const REDACT_RE = new RegExp(
  `(?<email>${EMAIL_SRC})|(?<ssn>${SSN_SRC})|(?<intlPhone>${INTL_PHONE_SRC})|(?<account>${ACCOUNT_SRC})|(?<nanpPhone>${NANP_PHONE_SRC})|(?<literal>${LITERAL_TOKEN_SRC})`,
  "g"
);

// Single-pass restoration regex; matches both nonced (`<EMAIL_1_9f2c1a>`) and deterministic
// (`<EMAIL_1>`) tokens, substituting only tokens present in this session's `tokenToValue` map.
const RESTORE_TOKEN_RE = /<(?:EMAIL|SSN|PHONE|ACCOUNT|LITERAL)_\d+(?:_[0-9a-f]{6})?>/g;

const EXT_STRIP_RE = /(?:[,;\s]{0,3}(?:[Ee][Xx][Tt]\.?\s{0,3}|[Ee][Xx][Tt][Ee][Nn][Ss][Ii][Oo][Nn]\s{1,3}|[Xx]\s?)\d{1,6})$/;

function isValidIntlPhone(match) {
  const withoutExt = match.replace(EXT_STRIP_RE, "");
  const digits = withoutExt.replace(/\(0\)/g, "").replace(/\D/g, "");
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Create a session-scoped redactor that replaces structured emails, US SSNs, NANP and
 * `+`-prefixed E.164/E.123 phone numbers (with optional extensions), and 12-19 digit
 * account/card numbers with unguessable per-session placeholders (`<EMAIL_1_9f2c1a>`,
 * `<PHONE_1_9f2c1a>`, etc.) before text leaves a local boundary.
 *
 * Pass `{ deterministic: true }` only if bare `<EMAIL_1>` placeholders without a random
 * session nonce are explicitly desired.
 */
export function createRedactor({ deterministic = false } = {}) {
  const sessionNonce = deterministic ? "" : `_${randomBytes(3).toString("hex")}`;
  const valueToToken = new Map();
  const tokenToValue = new Map();
  const counts = { EMAIL: 0, SSN: 0, PHONE: 0, ACCOUNT: 0 };
  let literalCount = 0;

  function assignToken(kind, rawValue) {
    const normalizedKey =
      kind === "LITERAL" ? `LITERAL:${rawValue}` : `${kind}:${rawValue.toLowerCase()}`;
    if (valueToToken.has(normalizedKey)) {
      return valueToToken.get(normalizedKey);
    }
    let token;
    if (kind === "LITERAL") {
      literalCount += 1;
      token = `<LITERAL_${literalCount}${sessionNonce}>`;
    } else {
      counts[kind] += 1;
      token = `<${kind}_${counts[kind]}${sessionNonce}>`;
    }
    valueToToken.set(normalizedKey, token);
    tokenToValue.set(token, rawValue);
    return token;
  }

  function redact(input) {
    if (input === null || input === undefined) return "";
    const src = String(input);
    return src.replace(REDACT_RE, (match, ...args) => {
      const groups = args[args.length - 1];
      if (groups.email !== undefined) return assignToken("EMAIL", match);
      if (groups.ssn !== undefined) return assignToken("SSN", match);
      if (groups.intlPhone !== undefined) {
        if (!isValidIntlPhone(match)) return match;
        return assignToken("PHONE", match);
      }
      if (groups.account !== undefined) return assignToken("ACCOUNT", match);
      if (groups.nanpPhone !== undefined) return assignToken("PHONE", match);
      if (groups.literal !== undefined) return assignToken("LITERAL", match);
      return match;
    });
  }

  function restore(redactedText) {
    if (redactedText === null || redactedText === undefined) return "";
    const src = String(redactedText);
    return src.replace(RESTORE_TOKEN_RE, (token) =>
      tokenToValue.has(token) ? tokenToValue.get(token) : token
    );
  }

  return {
    nonce: sessionNonce ? sessionNonce.slice(1) : null,
    redact,
    restore,
    stats() {
      return {
        ...counts,
        totalUnique: counts.EMAIL + counts.SSN + counts.PHONE + counts.ACCOUNT
      };
    }
  };
}
