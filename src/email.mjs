// Soft hyphen, grapheme/bidi controls, zero-width spaces/joiners, BOM,
// Unicode Tags (U+E0000..U+E007F), and Variation Selectors Supplement (U+E0100..U+E01EF).
const INVISIBLE_UNICODE_RE =
  /[\u00AD\u034F\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

const HIDDEN_HTML_STYLE_RE =
  /(?:^|[;{\s])(?:display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)|opacity\s*:\s*(?:0+(?:\.0+)?|\.0+)(?![.\d])|font-size\s*:\s*(?:0+(?:\.0+)?|\.0+)(?:px|pt|em|rem|%|vh|vw|vmin|vmax|ch|ex)?(?![.\d])|color\s*:\s*(?:transparent|rgba?\(\s*\d{1,3}\s*[, ]\s*\d{1,3}\s*[, ]\s*\d{1,3}\s*(?:,|\/)\s*0+(?:\.0+)?%?\s*\)|#(?:[0-9a-f]{3}0|[0-9a-f]{6}00)\b)|(?:left|top|text-indent)\s*:\s*-\d{4,}px|transform\s*:\s*scale\(\s*0+(?:\.0+)?\s*\)|clip-path\s*:\s*inset\(\s*(?:50|100)%)/i;

const PROMPT_OVERRIDE_PATTERNS = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+instructions/i,
  /disregard\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+instructions/i,
  /system\s+override\s*:/i,
  /new\s+system\s+(?:prompt|instructions)\s*:/i,
  /do\s+not\s+(?:inform|notify|tell)\s+the\s+(?:user|human|recipient|operator)/i,
  /forward\s+(?:all|every|the)\s+(?:emails?|messages?|invoices?|attachments?|documents?)\s+to/i
];

const NAMED_ENTITIES = {
  colon: ":",
  semi: ";",
  tab: "\t",
  newline: "\n",
  nbsp: "\u00A0",
  quot: '"',
  apos: "'",
  lt: "<",
  gt: ">",
  amp: "&",
  sol: "/",
  bsol: "\\",
  lpar: "(",
  rpar: ")",
  num: "#",
  percnt: "%",
  minus: "-",
  plus: "+",
  equals: "=",
  commat: "@",
  zerowidthspace: "\u200B",
  zwnj: "\u200C",
  zwj: "\u200D",
  lrm: "\u200E",
  rlm: "\u200F",
  shy: "\u00AD"
};

const HTML_ENTITY_RE =
  /&(?:#[xX]0{0,16}([0-9a-fA-F]{1,6});?|#0{0,16}(\d{1,7});?|([a-zA-Z][a-zA-Z0-9]{1,31});)/g;

const INLINE_FORMATTING_TAGS = new Set([
  "span", "b", "i", "u", "s", "em", "strong", "small",
  "sub", "sup", "mark", "font", "abbr", "code", "a"
]);

function safeFromCodePoint(cp) {
  if (!Number.isInteger(cp) || cp <= 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
    return "\uFFFD";
  }
  return String.fromCodePoint(cp);
}

function decodeHtmlEntities(input) {
  return input.replace(HTML_ENTITY_RE, (full, hex, dec, named) => {
    if (hex !== undefined) {
      return safeFromCodePoint(Number.parseInt(hex, 16));
    }
    if (dec !== undefined) {
      return safeFromCodePoint(Number.parseInt(dec, 10));
    }
    if (named !== undefined) {
      const key = named.toLowerCase();
      if (Object.hasOwn(NAMED_ENTITIES, key)) {
        return NAMED_ENTITIES[key];
      }
    }
    return full;
  });
}

function stripCssComments(css, replacement = " ") {
  let out = "";
  let i = 0;
  while (i < css.length) {
    if (css[i] === "/" && css[i + 1] === "*") {
      const closeIdx = css.indexOf("*/", i + 2);
      out += replacement;
      if (closeIdx === -1) break;
      i = closeIdx + 2;
    } else {
      out += css[i];
      i += 1;
    }
  }
  return out;
}

function decodeCssEscapes(css) {
  return css.replace(
    /\\(?:([0-9a-fA-F]{1,6})\s?|([^\r\n\f0-9a-fA-F]))/g,
    (_, hex, ch) => (hex !== undefined ? safeFromCodePoint(Number.parseInt(hex, 16)) : ch)
  );
}

function containsHiddenCssDeclaration(rawCss) {
  const entityDecoded = decodeHtmlEntities(rawCss);
  const spaced = decodeCssEscapes(stripCssComments(entityDecoded, " "));
  if (HIDDEN_HTML_STYLE_RE.test(spaced)) return true;
  const collapsed = decodeCssEscapes(stripCssComments(entityDecoded, ""));
  return HIDDEN_HTML_STYLE_RE.test(collapsed);
}

function extractStyleBlocks(html) {
  const blocks = [];
  const lower = html.toLowerCase();
  let cursor = 0;
  while (cursor < html.length) {
    const start = lower.indexOf("<style", cursor);
    if (start === -1) break;
    const afterName = lower[start + 6];
    if (afterName && !/[\s>/]/.test(afterName)) {
      cursor = start + 6;
      continue;
    }
    const openEnd = lower.indexOf(">", start + 6);
    if (openEnd === -1) break;
    const closeStart = lower.indexOf("</style", openEnd + 1);
    if (closeStart === -1) {
      blocks.push(html.slice(openEnd + 1));
      break;
    }
    blocks.push(html.slice(openEnd + 1, closeStart));
    cursor = closeStart + 7;
  }
  return blocks;
}

/**
 * Linear O(n) HTML opening-tag and attribute scanner.
 * Avoids regex backtracking on malformed/unclosed attributes while inspecting
 * inline `style`, `hidden`, `aria-hidden`, `<template>`, and `<input type="hidden">`.
 */
function scanHtmlHiddenSignals(html) {
  for (const styleBlock of extractStyleBlocks(html)) {
    if (containsHiddenCssDeclaration(styleBlock)) return true;
  }

  let i = 0;
  const len = html.length;
  while (i < len) {
    const lt = html.indexOf("<", i);
    if (lt === -1) break;

    // Skip HTML comments <!-- ... -->
    if (html.startsWith("<!--", lt)) {
      const commentEnd = html.indexOf("-->", lt + 4);
      if (commentEnd === -1) break;
      i = commentEnd + 3;
      continue;
    }

    const firstChar = html[lt + 1];
    if (!firstChar || !/[A-Za-z]/.test(firstChar)) {
      i = lt + 1;
      continue;
    }

    let cur = lt + 1;
    while (cur < len && /[A-Za-z0-9:-]/.test(html[cur])) cur += 1;
    const tagName = html.slice(lt + 1, cur).toLowerCase();
    if (tagName === "template") return true;

    while (cur < len) {
      while (cur < len && /\s/.test(html[cur])) cur += 1;
      if (cur >= len || html[cur] === ">") {
        cur += 1;
        break;
      }
      if (html[cur] === "/") {
        cur += 1;
        continue;
      }

      const attrStart = cur;
      while (cur < len && !/[\s=>/"']/.test(html[cur])) cur += 1;
      if (cur === attrStart) {
        cur += 1;
        continue;
      }
      const attrName = html.slice(attrStart, cur).toLowerCase();

      while (cur < len && /\s/.test(html[cur])) cur += 1;
      let attrValue = "";
      if (cur < len && html[cur] === "=") {
        cur += 1;
        while (cur < len && /\s/.test(html[cur])) cur += 1;
        if (cur < len && (html[cur] === '"' || html[cur] === "'")) {
          const quote = html[cur];
          const valStart = cur + 1;
          const closeQuote = html.indexOf(quote, valStart);
          if (closeQuote === -1) {
            attrValue = html.slice(valStart);
            cur = len;
          } else {
            attrValue = html.slice(valStart, closeQuote);
            cur = closeQuote + 1;
          }
        } else {
          const valStart = cur;
          while (cur < len && !/[\s>]/.test(html[cur])) cur += 1;
          attrValue = html.slice(valStart, cur);
        }
      }

      const decodedAttrVal = decodeHtmlEntities(attrValue);
      if (attrName === "hidden") {
        return true;
      }
      if (attrName === "aria-hidden" && decodedAttrVal.trim().toLowerCase() === "true") {
        return true;
      }
      if (
        tagName === "input" &&
        attrName === "type" &&
        decodedAttrVal.trim().toLowerCase() === "hidden"
      ) {
        return true;
      }
      if (attrName === "style" && containsHiddenCssDeclaration(attrValue)) {
        return true;
      }
    }

    i = cur;
  }

  return false;
}

function extractHtmlTextForInspection(rawHtml) {
  let out = "";
  let i = 0;
  const len = rawHtml.length;

  while (i < len) {
    const lt = rawHtml.indexOf("<", i);
    if (lt === -1) {
      out += rawHtml.slice(i);
      break;
    }
    out += rawHtml.slice(i, lt);

    if (rawHtml.startsWith("<!--", lt)) {
      const commentEnd = rawHtml.indexOf("-->", lt + 4);
      if (commentEnd === -1) break;
      i = commentEnd + 3;
      continue;
    }

    let nameStart = lt + 1;
    if (rawHtml[nameStart] === "/") nameStart += 1;
    let nameEnd = nameStart;
    while (nameEnd < len && /[A-Za-z0-9:-]/.test(rawHtml[nameEnd])) nameEnd += 1;
    const tagName = rawHtml.slice(nameStart, nameEnd).toLowerCase();

    // Advance past '>' while respecting quoted attributes
    let cur = nameEnd;
    while (cur < len && rawHtml[cur] !== ">") {
      if (rawHtml[cur] === '"' || rawHtml[cur] === "'") {
        const q = rawHtml[cur];
        const nextQ = rawHtml.indexOf(q, cur + 1);
        if (nextQ === -1) {
          cur = len;
          break;
        }
        cur = nextQ + 1;
      } else {
        cur += 1;
      }
    }

    if (!INLINE_FORMATTING_TAGS.has(tagName)) {
      out += " ";
    }
    i = cur < len ? cur + 1 : len;
  }

  return decodeHtmlEntities(out);
}

function decodeRfc2047Words(str) {
  return str.replace(
    /=\?([A-Za-z0-9_-]+)\?([BbQq])\?([^?\s]*)\?=/g,
    (full, _charset, encoding, payload) => {
      try {
        if (encoding.toUpperCase() === "B") {
          return Buffer.from(payload, "base64").toString("utf8");
        }
        const qp = payload
          .replaceAll("_", " ")
          .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
            String.fromCharCode(Number.parseInt(hex, 16))
          );
        return Buffer.from(qp, "latin1").toString("utf8");
      } catch {
        return full;
      }
    }
  );
}

const HEADER_EMAIL_TOKEN_RE =
  /[a-z0-9_%+-][a-z0-9._%+-]{0,63}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

function extractDomainFromAddress(addr) {
  const atIdx = addr.lastIndexOf("@");
  if (atIdx === -1) return null;
  const domain = addr.slice(atIdx + 1).toLowerCase().trim();
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/.test(domain)) {
    return domain;
  }
  return null;
}

/**
 * Parse an RFC 5322 `From` or `Reply-To` header value, locating `<mailbox@domain>`
 * outside quoted display-name strings so `"ceo@company.com" <attacker@evil.com>`
 * resolves `address = "attacker@evil.com"` and `displayName = "ceo@company.com"`.
 */
function parseMailboxHeader(rawHeader) {
  const cleaned = decodeRfc2047Words(String(rawHeader ?? "")).replace(INVISIBLE_UNICODE_RE, "");
  let inQuotes = false;
  let openAngle = -1;
  let lastAngleStart = -1;
  let lastAngleEnd = -1;

  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (ch === "\\" && inQuotes) {
      i += 1;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (!inQuotes) {
      if (ch === "<") {
        openAngle = i;
      } else if (ch === ">" && openAngle !== -1) {
        lastAngleStart = openAngle;
        lastAngleEnd = i;
        openAngle = -1;
      }
    }
  }

  if (lastAngleStart !== -1 && lastAngleEnd > lastAngleStart) {
    const address = cleaned.slice(lastAngleStart + 1, lastAngleEnd).trim().toLowerCase();
    const displayRaw = `${cleaned.slice(0, lastAngleStart)} ${cleaned.slice(lastAngleEnd + 1)}`.trim();
    const displayName = displayRaw.replace(/\\(.)/g, "$1");
    return {
      displayName,
      address,
      domain: extractDomainFromAddress(address)
    };
  }

  const bareMatches = cleaned.match(HEADER_EMAIL_TOKEN_RE);
  const address = bareMatches ? bareMatches[bareMatches.length - 1].toLowerCase() : "";
  return {
    displayName: "",
    address,
    domain: extractDomainFromAddress(address)
  };
}

/**
 * Inspect an untrusted inbound email (headers + plain/HTML body) before
 * passing text to an automated triage or drafting step.
 *
 * Strips invisible Unicode characters and flags `From` display-name spoofing,
 * `Reply-To` domain mismatches, hidden HTML/CSS content (including entity-encoded
 * styles, CSS comments/escapes, `<style>` blocks, `hidden`, `aria-hidden="true"`,
 * and `<template>`), and embedded instruction-override patterns.
 */
export function inspectInboundEmail({
  from = "",
  replyTo = "",
  subject = "",
  text = "",
  html = ""
} = {}) {
  const findings = [];
  const safeFrom = String(from ?? "");
  const safeReplyTo = String(replyTo ?? "");
  const safeSubject = String(subject ?? "");
  const safeText = String(text ?? "");
  const safeHtml = String(html ?? "");

  const parsedFrom = parseMailboxHeader(safeFrom);
  const parsedReplyTo = parseMailboxHeader(safeReplyTo);

  if (parsedFrom.displayName && parsedFrom.address) {
    const spoofedMatches = parsedFrom.displayName.match(HEADER_EMAIL_TOKEN_RE) ?? [];
    const mismatchedDisplayEmail = spoofedMatches.find(
      (candidate) => candidate.toLowerCase() !== parsedFrom.address
    );
    if (mismatchedDisplayEmail) {
      findings.push({
        code: "FROM_DISPLAY_NAME_SPOOF",
        severity: "high",
        detail: `From display name embeds '${mismatchedDisplayEmail.toLowerCase()}' while actual sender address is '${parsedFrom.address}'.`
      });
    }
  }

  if (
    parsedFrom.domain &&
    parsedReplyTo.domain &&
    parsedFrom.domain !== parsedReplyTo.domain
  ) {
    findings.push({
      code: "REPLY_TO_DOMAIN_MISMATCH",
      severity: "medium",
      detail: `Sender domain '${parsedFrom.domain}' differs from Reply-To domain '${parsedReplyTo.domain}'.`
    });
  }

  const decodedHtml = safeHtml ? decodeHtmlEntities(safeHtml) : "";
  const combinedForUnicode = `${safeFrom}\n${safeReplyTo}\n${safeSubject}\n${safeText}\n${decodedHtml}`;
  const invisibleMatches = combinedForUnicode.match(INVISIBLE_UNICODE_RE);
  if (invisibleMatches && invisibleMatches.length > 0) {
    findings.push({
      code: "INVISIBLE_UNICODE_CHARS",
      severity: invisibleMatches.length >= 8 ? "high" : "low",
      detail: `Detected ${invisibleMatches.length} invisible or Unicode tag character(s) capable of hiding text from human reviewers.`
    });
  }

  if (safeHtml && scanHtmlHiddenSignals(safeHtml)) {
    findings.push({
      code: "HIDDEN_HTML_CONTENT",
      severity: "high",
      detail: "HTML email contains hidden DOM content (CSS display/visibility/opacity/font-size/offscreen rules, <style> blocks, hidden/aria-hidden attributes, or <template>)."
    });
  }

  const normalizedPlain = `${safeSubject}\n${safeText}`.replace(INVISIBLE_UNICODE_RE, "");
  const normalizedHtmlText = safeHtml
    ? extractHtmlTextForInspection(safeHtml).replace(INVISIBLE_UNICODE_RE, "")
    : "";

  for (const pattern of PROMPT_OVERRIDE_PATTERNS) {
    if (pattern.test(normalizedPlain) || (normalizedHtmlText && pattern.test(normalizedHtmlText))) {
      findings.push({
        code: "INSTRUCTION_OVERRIDE_PATTERN",
        severity: "high",
        detail: `Inbound content matches untrusted instruction-override pattern (${pattern.source}).`
      });
      break;
    }
  }

  return {
    safe: findings.length === 0,
    sanitizedSubject: safeSubject.replace(INVISIBLE_UNICODE_RE, ""),
    sanitizedText: safeText.replace(INVISIBLE_UNICODE_RE, ""),
    findings
  };
}
