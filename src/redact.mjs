/**
 * Pattern scope for `createRedactor()`:
 * - EMAIL: Unquoted (`[A-Za-z0-9_%+-]...`, <=64 chars) or RFC 5321 quoted local-parts
 *   (`"..."`, <=62 chars) with standard DNS labels and a 2-24 letter ASCII TLD.
 * - SSN: Hyphenated 9-digit US SSNs (`DDD-DD-DDDD`), excluding SSA-unassigned prefixes
 *   (`000`, `666`, `900-999`), group `00`, and serial `0000`. Unhyphenated 9-digit
 *   numbers are excluded to avoid false positives on PO, routing, and invoice IDs.
 * - INTL_PHONE: Explicit `+`-prefixed ITU-T E.164 / E.123 numbers (`+1`..`+999` country
 *   code, optional `(0)` trunk marker, 7-15 digits validated before tokenization) plus
 *   optional extension suffix (`ext`, `ext.`, `extension`, `x` + 1-6 digits).
 * - ACCOUNT: 12-19 contiguous digits, or space/hyphen-grouped 13-19 digit card/account
 *   numbers (`4-4-4-1..7` and `4-6-5`), bounded away from `+` phones and decimals.
 * - NANP_PHONE: 10-digit or `1`-prefixed 11-digit North American numbers (`(314) 555-0199`,
 *   `(314)555-0199`, `314-555-0199`, `314.555.0199`) plus optional extension suffix.
 * - LITERAL: Pre-existing `<EMAIL_n>` / `<SSN_n>` / `<PHONE_n>` / `<ACCOUNT_n>` / `<LITERAL_n>`
 *   placeholders in untrusted input are tokenized as `<LITERAL_n>` in the same single pass
 *   so untrusted text cannot collide with or exfiltrate session tokens during `restore()`.
 */

const EXT_SUFFIX_SRC = String.raw`(?:[,;\s]{0,3}(?:[Ee][Xx][Tt]\.?\s{0,3}|[Ee][Xx][Tt][Ee][Nn][Ss][Ii][Oo][Nn]\s{1,3}|[Xx]\s?)\d{1,6}(?![A-Za-z\d]))?`;

const EMAIL_SRC = String.raw`(?:"[^"\\\r\n]{1,62}"|(?<![A-Za-z0-9._%+-])[A-Za-z0-9_%+-][A-Za-z0-9._%+-]{0,63})@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b`;

const SSN_SRC = String.raw`\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b`;

const INTL_PHONE_SRC = String.raw`(?<![A-Za-z0-9+])\+[1-9](?:\d{6,14}|\d{0,2}(?:[-.\s]?\(0\))?(?:[-.\s]?\(\d{1,5}\)[-.\s]?\d{2,6}|[-.\s]\d{1,5})(?:[-.\s]\d{2,6}){0,4})${EXT_SUFFIX_SRC}(?![A-Za-z\d])`;

const ACCOUNT_SRC = String.raw`(?<![+\d]|\d\.)(?:\d{12,19}|\d{4}(?:-\d{4}-\d{4}-\d{1,7}| \d{4} \d{4} \d{1,7})|\d{4}(?:-\d{6}-\d{5}| \d{6} \d{5}))(?!\d|\.\d)`;

const NANP_PHONE_SRC = String.raw`(?<![+\dA-Za-z]|\d\.)(?:1[-.\s])?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]\d{4}${EXT_SUFFIX_SRC}(?![A-Za-z\d])`;

const LITERAL_TOKEN_SRC = String.raw`<(?:EMAIL|SSN|PHONE|ACCOUNT|LITERAL)_\d{1,10}>`;

const REDACT_RE = new RegExp(
  `(?<email>${EMAIL_SRC})|(?<ssn>${SSN_SRC})|(?<intlPhone>${INTL_PHONE_SRC})|(?<account>${ACCOUNT_SRC})|(?<nanpPhone>${NANP_PHONE_SRC})|(?<literal>${LITERAL_TOKEN_SRC})`,
  "g"
);

// Single-pass restoration regex; matches known placeholder families without re-scanning replacements.
const RESTORE_TOKEN_RE = /<(?:EMAIL|SSN|PHONE|ACCOUNT|LITERAL)_\d+>/g;

const EXT_STRIP_RE = /(?:[,;\s]{0,3}(?:[Ee][Xx][Tt]\.?\s{0,3}|[Ee][Xx][Tt][Ee][Nn][Ss][Ii][Oo][Nn]\s{1,3}|[Xx]\s?)\d{1,6})$/;

function isValidIntlPhone(match) {
  const withoutExt = match.replace(EXT_STRIP_RE, "");
  const digits = withoutExt.replace(/\(0\)/g, "").replace(/\D/g, "");
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Create a deterministic, session-scoped redactor that replaces structured emails,
 * hyphenated US SSNs, NANP and `+`-prefixed E.164/E.123 phone numbers (with optional
 * extensions), and 12-19 digit account/card numbers with stable placeholders
 * (`<EMAIL_1>`, `<PHONE_1>`, etc.) before text leaves a local boundary.
 */
export function createRedactor() {
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
      token = `<LITERAL_${literalCount}>`;
    } else {
      counts[kind] += 1;
      token = `<${kind}_${counts[kind]}>`;
    }
    valueToToken.set(normalizedKey, token);
    tokenToValue.set(token, rawValue);
    return token;
  }

  function redact(input) {
    const src = String(input ?? "");
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
    const src = String(redactedText ?? "");
    return src.replace(RESTORE_TOKEN_RE, (token) =>
      tokenToValue.has(token) ? tokenToValue.get(token) : token
    );
  }

  return {
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
