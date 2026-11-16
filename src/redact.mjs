const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const SSN_RE = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const PHONE_RE = /(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?!\d)/g;
const LONG_ACCOUNT_RE = /\b\d{12,19}\b/g;

/**
 * Create a deterministic, session-scoped redactor that replaces emails, US SSNs,
 * phone numbers, and long account/card numbers with stable placeholders
 * (`<EMAIL_1>`, `<PHONE_1>`, etc.) before text leaves a local boundary.
 */
export function createRedactor() {
  const valueToToken = new Map();
  const tokenToValue = new Map();
  const counts = { EMAIL: 0, SSN: 0, PHONE: 0, ACCOUNT: 0 };

  function assignToken(kind, rawValue) {
    const normalizedKey = `${kind}:${rawValue.toLowerCase()}`;
    if (valueToToken.has(normalizedKey)) {
      return valueToToken.get(normalizedKey);
    }
    counts[kind] += 1;
    const token = `<${kind}_${counts[kind]}>`;
    valueToToken.set(normalizedKey, token);
    tokenToValue.set(token, rawValue);
    return token;
  }

  function redact(input) {
    let out = String(input ?? "");
    out = out.replace(EMAIL_RE, (m) => assignToken("EMAIL", m));
    out = out.replace(SSN_RE, (m) => assignToken("SSN", m));
    out = out.replace(LONG_ACCOUNT_RE, (m) => assignToken("ACCOUNT", m));
    out = out.replace(PHONE_RE, (m) => assignToken("PHONE", m));
    return out;
  }

  function restore(redactedText) {
    let out = String(redactedText ?? "");
    for (const [token, original] of tokenToValue.entries()) {
      out = out.replaceAll(token, original);
    }
    return out;
  }

  return {
    redact,
    restore,
    stats() {
      return { ...counts, totalUnique: tokenToValue.size };
    }
  };
}
