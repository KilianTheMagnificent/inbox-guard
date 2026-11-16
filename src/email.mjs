// Soft hyphen, grapheme/bidi controls, Hangul/Braille/Khmer fillers, zero-width spaces/joiners,
// BMP Variation Selectors (U+FE00..U+FE0F), BOM, interlinear annotations (U+FFF9..U+FFFB),
// Unicode Tags (U+E0000..U+E007F), and Variation Selectors Supplement (U+E0100..U+E01EF).
const INVISIBLE_UNICODE_RE =
  /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

const PROMPT_OVERRIDE_PATTERNS = [
  /ignore\s+(?:(?:all|any|the)\s+)?(?:previous|prior|above|earlier|system)\s+instructions/i,
  /disregard\s+(?:(?:all|any|the)\s+)?(?:previous|prior|above|earlier|system)\s+instructions/i,
  /system\s+override\s*:/i,
  /new\s+system\s+(?:prompt|instructions)\s*:/i,
  /do\s+not\s+(?:inform|notify|tell)\s+the\s+(?:user|human|recipient|operator)/i,
  /forward\s+(?:all|every|the)\s+(?:emails?|messages?|invoices?|attachments?|documents?)\s+to/i
];

const NAMED_ENTITIES = {
  colon: ":",
  semi: ";",
  period: ".",
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

// Possessive-equivalent numeric entity branches: consumes all hex/decimal digits in one pass
// regardless of leading-zero count, avoiding both zero-padding truncation and backtracking.
const HTML_ENTITY_RE =
  /&(?:#[xX]([0-9a-fA-F]+);?|#(\d+);?|([a-zA-Z][a-zA-Z0-9]{1,31});)/g;

const INLINE_FORMATTING_TAGS = new Set([
  "span", "b", "i", "u", "s", "em", "strong", "small",
  "sub", "sup", "mark", "font", "abbr", "code", "a"
]);

const BASIC_NAMED_COLORS = {
  white: "#ffffff",
  black: "#000000",
  red: "#ff0000",
  green: "#008000",
  lime: "#00ff00",
  blue: "#0000ff",
  yellow: "#ffff00",
  cyan: "#00ffff",
  aqua: "#00ffff",
  magenta: "#ff00ff",
  fuchsia: "#ff00ff",
  gray: "#808080",
  grey: "#808080",
  silver: "#c0c0c0",
  maroon: "#800000",
  olive: "#808000",
  purple: "#800080",
  teal: "#008080",
  navy: "#000080",
  ivory: "#fffff0",
  snow: "#fffafa",
  ghostwhite: "#f8f8ff",
  whitesmoke: "#f5f5f5"
};

const CONFUSABLE_CHAR_MAP = new Map([
  ["\u0430", "a"], ["\u0410", "a"], // Cyrillic a
  ["\u0432", "b"], ["\u0412", "b"], // Cyrillic ve
  ["\u0441", "c"], ["\u0421", "c"], // Cyrillic es
  ["\u0501", "d"],                  // Cyrillic komi de
  ["\u0435", "e"], ["\u0415", "e"], // Cyrillic ie
  ["\u04BB", "h"], ["\u04BA", "h"], // Cyrillic shha
  ["\u0456", "i"], ["\u0406", "i"], // Cyrillic byelorussian-ukrainian i
  ["\u0458", "j"], ["\u0408", "j"], // Cyrillic je
  ["\u043A", "k"], ["\u041A", "k"], // Cyrillic ka
  ["\u043C", "m"], ["\u041C", "m"], // Cyrillic em
  ["\u043D", "h"], ["\u041D", "h"], // Cyrillic en
  ["\u043E", "o"], ["\u041E", "o"], // Cyrillic o
  ["\u0440", "p"], ["\u0420", "p"], // Cyrillic er
  ["\u0455", "s"], ["\u0405", "s"], // Cyrillic dze
  ["\u0442", "t"], ["\u0422", "t"], // Cyrillic te
  ["\u0443", "y"], ["\u0423", "y"], // Cyrillic u
  ["\u0445", "x"], ["\u0425", "x"], // Cyrillic ha
  ["\u03B1", "a"], ["\u0391", "a"], // Greek alpha
  ["\u03B5", "e"], ["\u0395", "e"], // Greek epsilon
  ["\u03B9", "i"], ["\u0399", "i"], // Greek iota
  ["\u03BF", "o"], ["\u039F", "o"], // Greek omicron
  ["\u03C1", "p"], ["\u03A1", "p"], // Greek rho
  ["\u03BA", "k"], ["\u039A", "k"], // Greek kappa
  ["\u03BD", "v"],                  // Greek nu
  ["\u03C4", "t"], ["\u03A4", "t"], // Greek tau
  ["\u03C7", "x"], ["\u03A7", "x"], // Greek chi
  ["\uFE6B", "@"],                  // Small commercial at
  ["\uFF20", "@"],                  // Fullwidth commercial at
  ["\u2024", "."], ["\uFE52", "."], ["\uFF0E", "."], ["\u3002", "."]
]);

function foldConfusables(str) {
  let out = "";
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    // Fullwidth ASCII variants U+FF01..U+FF5E -> U+0021..U+007E
    if (code >= 0xFF01 && code <= 0xFF5E) {
      out += String.fromCharCode(code - 0xFEE0);
      continue;
    }
    const ch = str[i];
    const mapped = CONFUSABLE_CHAR_MAP.get(ch);
    out += mapped !== undefined ? mapped : ch;
  }
  return out;
}

function safeFromCodePoint(cp) {
  if (!Number.isInteger(cp) || cp <= 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
    return "\uFFFD";
  }
  return String.fromCodePoint(cp);
}

function stripLeadingZeros(digits) {
  let idx = 0;
  while (idx < digits.length && digits.charCodeAt(idx) === 48) {
    idx += 1;
  }
  return digits.slice(idx);
}

function decodeHtmlEntities(input) {
  if (!input.includes("&")) return input;
  return input.replace(HTML_ENTITY_RE, (full, hex, dec, named) => {
    if (hex !== undefined) {
      const sig = stripLeadingZeros(hex);
      if (sig.length === 0 || sig.length > 6) return "\uFFFD";
      return safeFromCodePoint(Number.parseInt(sig, 16));
    }
    if (dec !== undefined) {
      const sig = stripLeadingZeros(dec);
      if (sig.length === 0 || sig.length > 7) return "\uFFFD";
      return safeFromCodePoint(Number.parseInt(sig, 10));
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
  if (!css.includes("/*")) return css;
  let out = "";
  let i = 0;
  while (i < css.length) {
    const idx = css.indexOf("/*", i);
    if (idx === -1) {
      out += css.slice(i);
      break;
    }
    out += css.slice(i, idx) + replacement;
    const closeIdx = css.indexOf("*/", idx + 2);
    if (closeIdx === -1) break;
    i = closeIdx + 2;
  }
  return out;
}

function decodeCssEscapes(css) {
  if (!css.includes("\\")) return css;
  return css.replace(
    /\\(?:([0-9a-fA-F]{1,6})\s?|([^\r\n\f0-9a-fA-F]))/g,
    (_, hex, ch) => (hex !== undefined ? safeFromCodePoint(Number.parseInt(hex, 16)) : ch)
  );
}

function isCssSpace(code) {
  return code === 32 || code === 9 || code === 10 || code === 13 || code === 12;
}

function stripImportantSuffix(val) {
  let end = val.length;
  while (end > 0 && isCssSpace(val.charCodeAt(end - 1))) end -= 1;
  if (end >= 9 && val.slice(end - 9, end).toLowerCase() === "important") {
    let bang = end - 9;
    while (bang > 0 && isCssSpace(val.charCodeAt(bang - 1))) bang -= 1;
    if (bang > 0 && val[bang - 1] === "!") {
      return val.slice(0, bang - 1).trim();
    }
  }
  return val.slice(0, end).trim();
}

/**
 * Parse a CSS numeric token plus optional unit in strictly linear O(n) time.
 * Returns `{ num, unit }` or `null` if `token` is not a valid CSS number/dimension.
 */
function parseCssNumberAndUnit(rawToken) {
  const token = rawToken.trim().toLowerCase();
  if (!token) return null;
  let i = 0;
  const len = token.length;
  let sign = 1;
  if (token[i] === "+") {
    i += 1;
  } else if (token[i] === "-") {
    sign = -1;
    i += 1;
  }

  const intStart = i;
  while (i < len && token.charCodeAt(i) >= 48 && token.charCodeAt(i) <= 57) i += 1;
  const intDigits = i - intStart;

  let fracDigits = 0;
  if (i < len && token[i] === ".") {
    i += 1;
    const fracStart = i;
    while (i < len && token.charCodeAt(i) >= 48 && token.charCodeAt(i) <= 57) i += 1;
    fracDigits = i - fracStart;
  }

  if (intDigits === 0 && fracDigits === 0) return null;

  if (i < len && (token[i] === "e" || token[i] === "E")) {
    let expIdx = i + 1;
    if (expIdx < len && (token[expIdx] === "+" || token[expIdx] === "-")) expIdx += 1;
    const expDigitStart = expIdx;
    while (expIdx < len && token.charCodeAt(expIdx) >= 48 && token.charCodeAt(expIdx) <= 57) {
      expIdx += 1;
    }
    if (expIdx > expDigitStart) {
      i = expIdx;
    }
  }

  const numStr = token.slice(0, i);
  const unit = token.slice(i).trim();
  for (let u = 0; u < unit.length; u++) {
    const c = unit.charCodeAt(u);
    if (!(c === 37 || (c >= 97 && c <= 122))) return null;
  }

  // Cap parsed digit slice cleanly while preserving magnitude/zero semantics on 100k-zero inputs
  let num;
  if (numStr.length > 64) {
    const body = token.slice(intStart, i);
    const dotPos = body.indexOf(".");
    const intPart = stripLeadingZeros(dotPos === -1 ? body : body.slice(0, dotPos));
    if (intPart.length > 0) {
      num = sign * (intPart.length > 15 ? 1e15 : Number(intPart));
    } else {
      const fracPart = dotPos === -1 ? "" : body.slice(dotPos + 1, dotPos + 20);
      num = sign * Number(`0.${fracPart || "0"}`);
    }
  } else {
    num = Number(numStr);
  }
  if (!Number.isFinite(num)) return null;
  return { num, unit };
}

function extractCssFuncArgs(inner, maxTokens = 10) {
  const tokens = [];
  let i = 0;
  const len = inner.length;
  while (i < len && tokens.length < maxTokens) {
    const ch = inner.charCodeAt(i);
    if (isCssSpace(ch) || ch === 44) {
      i += 1;
      continue;
    }
    if (ch === 47) {
      tokens.push("/");
      i += 1;
      continue;
    }
    const start = i;
    while (i < len) {
      const c = inner.charCodeAt(i);
      if (isCssSpace(c) || c === 44 || c === 47) break;
      i += 1;
    }
    tokens.push(inner.slice(start, i));
  }
  return tokens;
}

function splitWhitespaceTokens(str, maxTokens = 8) {
  const tokens = [];
  let i = 0;
  const len = str.length;
  while (i < len && tokens.length < maxTokens) {
    while (i < len && isCssSpace(str.charCodeAt(i))) i += 1;
    if (i >= len) break;
    const start = i;
    let paren = 0;
    while (i < len) {
      const c = str.charCodeAt(i);
      if (c === 40) paren += 1;
      else if (c === 41 && paren > 0) paren -= 1;
      else if (paren === 0 && isCssSpace(c)) break;
      i += 1;
    }
    tokens.push(str.slice(start, i));
  }
  return tokens;
}

function isNearZeroAlpha(parsed) {
  if (!parsed) return false;
  if (parsed.unit === "%") return parsed.num >= 0 && parsed.num <= 2;
  if (parsed.unit === "") return parsed.num >= 0 && parsed.num <= 0.02;
  return false;
}

function isHexString(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70))) {
      return false;
    }
  }
  return s.length > 0;
}

function isTransparentCssColor(val) {
  if (val === "transparent") return true;
  if (val.startsWith("#")) {
    const hex = val.slice(1);
    if (hex.length === 4 && isHexString(hex)) {
      return Number.parseInt(hex[3], 16) === 0;
    }
    if (hex.length === 8 && isHexString(hex)) {
      return Number.parseInt(hex.slice(6, 8), 16) <= 5;
    }
    return false;
  }
  const open = val.indexOf("(");
  if (open === -1 || !val.endsWith(")")) return false;
  const fn = val.slice(0, open).trim();
  if (
    fn !== "rgb" &&
    fn !== "rgba" &&
    fn !== "hsl" &&
    fn !== "hsla" &&
    fn !== "oklch" &&
    fn !== "oklab" &&
    fn !== "lab" &&
    fn !== "lch" &&
    fn !== "color"
  ) {
    return false;
  }
  const args = extractCssFuncArgs(val.slice(open + 1, -1), 10);
  const slashIdx = args.indexOf("/");
  if (slashIdx !== -1 && slashIdx + 1 < args.length) {
    return isNearZeroAlpha(parseCssNumberAndUnit(args[slashIdx + 1]));
  }
  if ((fn === "rgb" || fn === "rgba" || fn === "hsl" || fn === "hsla") && args.length === 4) {
    return isNearZeroAlpha(parseCssNumberAndUnit(args[3]));
  }
  return false;
}

function normalizeSolidCssColor(rawToken) {
  const val = rawToken.trim().toLowerCase();
  if (!val) return null;
  if (Object.hasOwn(BASIC_NAMED_COLORS, val)) {
    return BASIC_NAMED_COLORS[val];
  }
  if (val.startsWith("#")) {
    const hex = val.slice(1);
    if (hex.length === 3 && isHexString(hex)) {
      return `#${hex[0]}${hex[0]}${hex[1]}${hex[1]}${hex[2]}${hex[2]}`;
    }
    if (hex.length === 6 && isHexString(hex)) {
      return `#${hex}`;
    }
    if (hex.length === 4 && isHexString(hex) && hex[3] === "f") {
      return `#${hex[0]}${hex[0]}${hex[1]}${hex[1]}${hex[2]}${hex[2]}`;
    }
    if (hex.length === 8 && isHexString(hex) && hex.slice(6, 8) === "ff") {
      return `#${hex.slice(0, 6)}`;
    }
    return null;
  }
  const open = val.indexOf("(");
  if (open !== -1 && val.endsWith(")")) {
    const fn = val.slice(0, open).trim();
    if (fn === "rgb" || fn === "rgba") {
      const args = extractCssFuncArgs(val.slice(open + 1, -1), 8);
      const slashIdx = args.indexOf("/");
      if (slashIdx !== -1 && slashIdx + 1 < args.length) {
        const a = parseCssNumberAndUnit(args[slashIdx + 1]);
        if (!a || (a.unit === "%" ? a.num < 99 : a.num < 0.99)) return null;
      } else if (args.length === 4) {
        const a = parseCssNumberAndUnit(args[3]);
        if (!a || (a.unit === "%" ? a.num < 99 : a.num < 0.99)) return null;
      } else if (args.length !== 3) {
        return null;
      }
      const rgb = [];
      for (let k = 0; k < 3; k++) {
        const p = parseCssNumberAndUnit(args[k]);
        if (!p) return null;
        const channel =
          p.unit === "%"
            ? Math.round(Math.min(100, Math.max(0, p.num)) * 2.55)
            : Math.round(Math.min(255, Math.max(0, p.num)));
        rgb.push(channel.toString(16).padStart(2, "0"));
      }
      return `#${rgb.join("")}`;
    }
  }
  return null;
}

function extractBackgroundSolidColor(val) {
  const direct = normalizeSolidCssColor(val);
  if (direct) return direct;
  for (const tok of splitWhitespaceTokens(val, 8)) {
    const c = normalizeSolidCssColor(tok);
    if (c) return c;
  }
  return null;
}

function isHiddenFontSize(parsed) {
  if (!parsed || parsed.num < 0) return false;
  if (parsed.num === 0) return true;
  if (parsed.unit === "px" || parsed.unit === "pt") return parsed.num <= 1;
  if (parsed.unit === "em" || parsed.unit === "rem" || parsed.unit === "ch" || parsed.unit === "ex") {
    return parsed.num <= 0.08;
  }
  if (parsed.unit === "%") return parsed.num <= 8;
  if (
    parsed.unit === "vw" ||
    parsed.unit === "vh" ||
    parsed.unit === "vmin" ||
    parsed.unit === "vmax"
  ) {
    return parsed.num <= 0.1;
  }
  return false;
}

function isOffscreenNegativeLength(parsed) {
  if (!parsed || parsed.num >= 0) return false;
  if (parsed.unit === "px" || parsed.unit === "pt") return parsed.num <= -500;
  if (
    parsed.unit === "vw" ||
    parsed.unit === "vh" ||
    parsed.unit === "vmin" ||
    parsed.unit === "vmax" ||
    parsed.unit === "em" ||
    parsed.unit === "rem" ||
    parsed.unit === "ch" ||
    parsed.unit === "ex" ||
    parsed.unit === "cm" ||
    parsed.unit === "mm" ||
    parsed.unit === "in"
  ) {
    return parsed.num <= -50;
  }
  if (parsed.unit === "%") return parsed.num <= -100;
  return false;
}

function hasZeroScaleTransform(val) {
  let cursor = 0;
  while (cursor < val.length) {
    const idx = val.indexOf("scale", cursor);
    if (idx === -1) break;
    if (idx > 0) {
      const prev = val.charCodeAt(idx - 1);
      if ((prev >= 97 && prev <= 122) || prev === 45) {
        cursor = idx + 5;
        continue;
      }
    }
    const open = val.indexOf("(", idx + 5);
    if (open === -1) break;
    const suffix = val.slice(idx + 5, open).trim();
    const close = val.indexOf(")", open + 1);
    if (close === -1) break;
    if (suffix === "" || suffix === "x" || suffix === "y" || suffix === "3d") {
      const args = extractCssFuncArgs(val.slice(open + 1, close), 4);
      const checkCount = suffix === "3d" ? Math.min(2, args.length) : Math.min(2, args.length);
      for (let k = 0; k < checkCount; k++) {
        const p = parseCssNumberAndUnit(args[k]);
        if (p) {
          const nearZero = p.unit === "%" ? Math.abs(p.num) <= 2 : Math.abs(p.num) <= 0.02;
          if (nearZero) return true;
        }
      }
    }
    cursor = close + 1;
  }
  return false;
}

function isHiddenClipValue(val) {
  const open = val.indexOf("(");
  if (open === -1 || !val.endsWith(")")) return false;
  const fn = val.slice(0, open).trim();
  const args = extractCssFuncArgs(val.slice(open + 1, -1), 12).filter((t) => t !== "/");
  if (fn === "rect") {
    if (args.length < 4) return false;
    for (let k = 0; k < 4; k++) {
      const p = parseCssNumberAndUnit(args[k]);
      if (!p || Math.abs(p.num) > 1) return false;
    }
    return true;
  }
  if (fn === "circle") {
    if (args.length === 0) return false;
    const p = parseCssNumberAndUnit(args[0]);
    return Boolean(p && p.num >= 0 && (p.num === 0 || ((p.unit === "px" || p.unit === "pt") && p.num <= 1)));
  }
  if (fn === "ellipse") {
    for (let k = 0; k < Math.min(2, args.length); k++) {
      if (args[k] === "at") break;
      const p = parseCssNumberAndUnit(args[k]);
      if (p && p.num === 0) return true;
    }
    return false;
  }
  if (fn === "inset") {
    for (let k = 0; k < Math.min(4, args.length); k++) {
      if (args[k] === "round") break;
      const p = parseCssNumberAndUnit(args[k]);
      if (p && ((p.unit === "%" && p.num >= 50) || ((p.unit === "px" || p.unit === "pt") && p.num >= 9999))) {
        return true;
      }
    }
    return false;
  }
  if (fn === "polygon" && args.length >= 2) {
    return args.every((tok) => {
      const p = parseCssNumberAndUnit(tok);
      return Boolean(p && p.num === 0);
    });
  }
  return false;
}

/**
 * Linear O(n) semicolon-delimited CSS declaration scanner.
 * Never runs backtracking regexes across untrusted attribute or stylesheet text.
 */
function checkCleanedCssDeclarations(css) {
  let hasZeroBoxSize = false;
  let hasClipOverflow = false;
  let fgColor = null;
  let bgColor = null;

  const len = css.length;
  let declStart = 0;
  let firstColon = -1;
  let parenDepth = 0;
  let quoteChar = "";

  for (let i = 0; i <= len; i++) {
    const ch = i < len ? css[i] : ";";
    if (quoteChar) {
      if (ch === "\\" && i + 1 < len) {
        i += 1;
        continue;
      }
      if (ch === quoteChar) quoteChar = "";
      continue;
    }
    if (ch === '"' || ch === "'") {
      quoteChar = ch;
      continue;
    }
    if (ch === "(") {
      parenDepth += 1;
      continue;
    }
    if (ch === ")" && parenDepth > 0) {
      parenDepth -= 1;
      continue;
    }
    if (ch === ":" && parenDepth === 0 && firstColon === -1) {
      firstColon = i;
      continue;
    }
    if (ch !== ";" || parenDepth !== 0) continue;

    const colonIdx = firstColon;
    if (colonIdx !== -1 && colonIdx < i) {
      const prop = css.slice(declStart, colonIdx).trim().toLowerCase();
      if (prop && !prop.startsWith("--")) {
        const val = stripImportantSuffix(css.slice(colonIdx + 1, i)).toLowerCase();
        if (val) {
          if (prop === "display" && val === "none") return true;
          if (prop === "visibility" && (val === "hidden" || val === "collapse")) return true;
          if (prop === "content-visibility" && val === "hidden") return true;

          if (prop === "opacity") {
            if (isNearZeroAlpha(parseCssNumberAndUnit(val))) return true;
          } else if (prop === "filter" && val.includes("opacity(")) {
            const opIdx = val.indexOf("opacity(");
            const clIdx = val.indexOf(")", opIdx + 8);
            if (clIdx !== -1 && isNearZeroAlpha(parseCssNumberAndUnit(val.slice(opIdx + 8, clIdx)))) {
              return true;
            }
          } else if (prop === "font-size") {
            if (isHiddenFontSize(parseCssNumberAndUnit(val))) return true;
          } else if (prop === "font") {
            for (const tok of splitWhitespaceTokens(val, 6)) {
              const sizePart = tok.includes("/") ? tok.slice(0, tok.indexOf("/")) : tok;
              if (isHiddenFontSize(parseCssNumberAndUnit(sizePart))) return true;
            }
          } else if (prop === "color" || prop === "-webkit-text-fill-color") {
            if (isTransparentCssColor(val)) return true;
            const c = normalizeSolidCssColor(val);
            if (c) fgColor = c;
          } else if (prop === "background-color" || prop === "background") {
            const bg = extractBackgroundSolidColor(val);
            if (bg) bgColor = bg;
          } else if (
            prop === "height" ||
            prop === "max-height" ||
            prop === "width" ||
            prop === "max-width" ||
            prop === "block-size" ||
            prop === "max-block-size" ||
            prop === "inline-size" ||
            prop === "max-inline-size"
          ) {
            const p = parseCssNumberAndUnit(val);
            if (p && p.num >= 0 && (p.num === 0 || ((p.unit === "px" || p.unit === "pt") && p.num <= 1))) {
              hasZeroBoxSize = true;
            }
          } else if (
            prop === "overflow" ||
            prop === "overflow-x" ||
            prop === "overflow-y" ||
            prop === "overflow-block" ||
            prop === "overflow-inline"
          ) {
            for (const tok of splitWhitespaceTokens(val, 4)) {
              if (tok === "hidden" || tok === "clip") hasClipOverflow = true;
            }
          } else if (
            prop === "left" ||
            prop === "right" ||
            prop === "top" ||
            prop === "bottom" ||
            prop === "inset" ||
            prop === "inset-inline-start" ||
            prop === "inset-block-start" ||
            prop === "margin-left" ||
            prop === "margin-top" ||
            prop === "margin" ||
            prop === "text-indent"
          ) {
            for (const tok of splitWhitespaceTokens(val, 4)) {
              if (isOffscreenNegativeLength(parseCssNumberAndUnit(tok))) return true;
            }
          } else if (prop === "transform") {
            if (hasZeroScaleTransform(val)) return true;
          } else if (prop === "scale") {
            if (val !== "none") {
              const parts = splitWhitespaceTokens(val, 3);
              for (let k = 0; k < Math.min(2, parts.length); k++) {
                const p = parseCssNumberAndUnit(parts[k]);
                if (p && (p.unit === "%" ? Math.abs(p.num) <= 2 : Math.abs(p.num) <= 0.02)) {
                  return true;
                }
              }
            }
          } else if (prop === "clip" || prop === "clip-path") {
            if (isHiddenClipValue(val)) return true;
          }
        }
      }
    }
    declStart = i + 1;
    firstColon = -1;
  }

  if (hasZeroBoxSize && hasClipOverflow) return true;
  if (fgColor && bgColor && fgColor === bgColor) return true;
  return false;
}

function containsHiddenCssDeclaration(rawCss) {
  const entityDecoded = decodeHtmlEntities(rawCss);
  const spaced = decodeCssEscapes(stripCssComments(entityDecoded, " "));
  if (checkCleanedCssDeclarations(spaced)) return true;
  if (entityDecoded.includes("/*")) {
    const collapsed = decodeCssEscapes(stripCssComments(entityDecoded, ""));
    if (checkCleanedCssDeclarations(collapsed)) return true;
  }
  return false;
}

function scanCleanedStylesheetRules(css) {
  let i = 0;
  const len = css.length;
  while (i < len) {
    while (i < len && (isCssSpace(css.charCodeAt(i)) || css[i] === ";")) i += 1;
    if (i >= len) break;

    // Scan rule prelude up to '{' or ';' (for @import/@charset)
    const preludeStart = i;
    let quoteChar = "";
    let parenDepth = 0;
    while (i < len) {
      const ch = css[i];
      if (quoteChar) {
        if (ch === "\\" && i + 1 < len) i += 1;
        else if (ch === quoteChar) quoteChar = "";
      } else if (ch === '"' || ch === "'") {
        quoteChar = ch;
      } else if (ch === "(") {
        parenDepth += 1;
      } else if (ch === ")" && parenDepth > 0) {
        parenDepth -= 1;
      } else if (parenDepth === 0 && (ch === "{" || ch === ";")) {
        break;
      }
      i += 1;
    }

    if (i >= len) break;
    if (css[i] === ";") {
      i += 1;
      continue;
    }

    const prelude = css.slice(preludeStart, i).trim().toLowerCase();
    const blockStart = i + 1;
    let braceDepth = 1;
    i += 1;
    quoteChar = "";
    while (i < len && braceDepth > 0) {
      const ch = css[i];
      if (quoteChar) {
        if (ch === "\\" && i + 1 < len) i += 1;
        else if (ch === quoteChar) quoteChar = "";
      } else if (ch === '"' || ch === "'") {
        quoteChar = ch;
      } else if (ch === "{") {
        braceDepth += 1;
      } else if (ch === "}") {
        braceDepth -= 1;
        if (braceDepth === 0) break;
      }
      i += 1;
    }

    const blockBody = css.slice(blockStart, i);
    if (i < len && css[i] === "}") i += 1;

    if (prelude.startsWith("@")) {
      if (prelude.startsWith("@media")) {
        // Skip conditional responsive/print media queries (e.g. `(max-width:600px)`, `print`)
        // to avoid false positives on standard responsive email layouts, while still inspecting
        // unconditional `@media all` or `@media screen` blocks.
        const isConditionalMedia =
          prelude.includes("(") || /\b(?:print|speech)\b/.test(prelude);
        if (!isConditionalMedia && scanCleanedStylesheetRules(blockBody)) {
          return true;
        }
      } else if (
        (prelude.startsWith("@supports") || prelude.startsWith("@layer")) &&
        scanCleanedStylesheetRules(blockBody)
      ) {
        return true;
      }
    } else if (checkCleanedCssDeclarations(decodeCssEscapes(blockBody))) {
      return true;
    }
  }
  return false;
}

function containsHiddenStylesheetRule(rawStyleBlock) {
  const entityDecoded = decodeHtmlEntities(rawStyleBlock);
  if (scanCleanedStylesheetRules(stripCssComments(entityDecoded, " "))) return true;
  if (entityDecoded.includes("/*")) {
    if (scanCleanedStylesheetRules(stripCssComments(entityDecoded, ""))) return true;
  }
  return false;
}

/**
 * Linear O(n) WHATWG HTML5 comment scanner (13.2.5.42 - 13.2.5.50).
 * Handles abrupt closures (`<!-->`, `<!--->`), bang closures (`<!-- ... --!>`),
 * standard `<!-- ... -->`, and memoizes absence of closing terminators so
 * repeated unclosed `<!--` sequences never degrade to O(n^2) nor swallow trailing DOM.
 */
function scanHtmlCommentEnd(html, lt, state) {
  const len = html.length;
  let k = lt + 4;
  if (k < len && html[k] === ">") return k + 1;
  if (k + 1 < len && html[k] === "-" && html[k + 1] === ">") return k + 2;
  if (state.noTerminator) return -1;

  while (k < len) {
    let d = html.indexOf("--", k);
    if (d === -1) {
      state.noTerminator = true;
      return -1;
    }
    while (d + 2 < len && html[d + 2] === "-") {
      d += 1;
    }
    if (d + 2 < len && html[d + 2] === ">") {
      return d + 3;
    }
    if (d + 3 < len && html[d + 2] === "!" && html[d + 3] === ">") {
      return d + 4;
    }
    k = d + 2;
  }

  state.noTerminator = true;
  return -1;
}

function extractStyleBlocks(html) {
  const blocks = [];
  const lower = html.toLowerCase();
  const commentState = { noTerminator: false };
  let cursor = 0;
  while (cursor < html.length) {
    const lt = lower.indexOf("<", cursor);
    if (lt === -1) break;
    if (lower.startsWith("<!--", lt)) {
      const end = scanHtmlCommentEnd(lower, lt, commentState);
      cursor = end === -1 ? lt + 4 : end;
      continue;
    }
    if (!lower.startsWith("<style", lt)) {
      cursor = lt + 1;
      continue;
    }
    const afterName = lower[lt + 6];
    if (afterName && !/[\s>/]/.test(afterName)) {
      cursor = lt + 6;
      continue;
    }
    const openEnd = lower.indexOf(">", lt + 6);
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
 * inline `style`, `hidden`, `aria-hidden`, `<template>`, collapsed `<details>`,
 * and `<input type="hidden">`.
 */
function scanHtmlHiddenSignals(html) {
  for (const styleBlock of extractStyleBlocks(html)) {
    if (containsHiddenStylesheetRule(styleBlock)) return true;
  }

  let i = 0;
  const len = html.length;
  const commentState = { noTerminator: false };

  while (i < len) {
    const lt = html.indexOf("<", i);
    if (lt === -1) break;

    if (html.startsWith("<!--", lt)) {
      const commentEnd = scanHtmlCommentEnd(html, lt, commentState);
      i = commentEnd === -1 ? lt + 4 : commentEnd;
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

    let hasOpenAttr = false;

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
      if (attrName === "open") hasOpenAttr = true;

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

    if (tagName === "details" && !hasOpenAttr) {
      return true;
    }

    i = cur;
  }

  return false;
}

function extractHtmlTextForInspection(rawHtml) {
  let out = "";
  let i = 0;
  const len = rawHtml.length;
  const commentState = { noTerminator: false };

  while (i < len) {
    const lt = rawHtml.indexOf("<", i);
    if (lt === -1) {
      out += rawHtml.slice(i);
      break;
    }
    out += rawHtml.slice(i, lt);

    if (rawHtml.startsWith("<!--", lt)) {
      const commentEnd = scanHtmlCommentEnd(rawHtml, lt, commentState);
      i = commentEnd === -1 ? lt + 4 : commentEnd;
      continue;
    }

    let nameStart = lt + 1;
    if (rawHtml[nameStart] === "/") nameStart += 1;
    if (nameStart >= len || !/[A-Za-z]/.test(rawHtml[nameStart])) {
      // Bogus comment / declaration (`<!...>`, `<?...>`): advance to next '>' without quote-trapping
      const gt = rawHtml.indexOf(">", lt + 1);
      if (gt === -1) {
        i = lt + 1;
      } else {
        out += " ";
        i = gt + 1;
      }
      continue;
    }

    let nameEnd = nameStart;
    while (nameEnd < len && /[A-Za-z0-9:-]/.test(rawHtml[nameEnd])) nameEnd += 1;
    const tagName = rawHtml.slice(nameStart, nameEnd).toLowerCase();

    // Advance past '>' while respecting quoted attributes on real element tags
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
  if (!str.includes("=?")) return str;
  const joined = str.replace(/(\?=)[ \t]+(=\?)/g, "$1$2");
  return joined.replace(
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
  /(?<![a-z0-9._%+-])[a-z0-9_%+-][a-z0-9._%+-]{0,63}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

function extractDomainFromAddress(addr) {
  const atIdx = addr.lastIndexOf("@");
  if (atIdx === -1) return null;
  const domain = addr.slice(atIdx + 1).toLowerCase().trim();
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/.test(domain)) {
    return domain;
  }
  return null;
}

function splitTopLevelMailboxes(header) {
  const items = [];
  let start = 0;
  let inQuotes = false;
  let commentDepth = 0;
  let angleDepth = 0;

  for (let i = 0; i < header.length; i++) {
    const ch = header[i];
    if (ch === "\\" && (inQuotes || commentDepth > 0)) {
      i += 1;
      continue;
    }
    if (commentDepth === 0 && ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (!inQuotes) {
      if (ch === "(") {
        commentDepth += 1;
      } else if (ch === ")" && commentDepth > 0) {
        commentDepth -= 1;
      } else if (commentDepth === 0) {
        if (ch === "<") angleDepth += 1;
        else if (ch === ">" && angleDepth > 0) angleDepth -= 1;
        else if ((ch === "," || ch === ";") && angleDepth === 0) {
          const slice = header.slice(start, i).trim();
          if (slice) items.push(slice);
          start = i + 1;
        }
      }
    }
  }
  const tail = header.slice(start).trim();
  if (tail) items.push(tail);
  return items;
}

/**
 * Parse a single RFC 5322 mailbox token, distinguishing quoted display strings,
 * `(comment)` blocks, `<angle-addr>` specifications, and bare `addr-spec` tokens
 * so `attacker@evil.example (ceo@company.com)` resolves `address = "attacker@evil.example"`
 * and exposes `(ceo@company.com)` in `displayLabel` for spoof inspection.
 */
function parseSingleMailbox(rawItem) {
  const cleaned = decodeRfc2047Words(rawItem).replace(INVISIBLE_UNICODE_RE, "");
  let inQuotes = false;
  let commentDepth = 0;
  let angleStart = -1;
  const angles = [];
  const comments = [];
  const quotedStrings = [];
  let commentBuf = "";
  let quoteBuf = "";
  let bareOutside = "";

  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (inQuotes) {
      if (ch === "\\" && i + 1 < cleaned.length) {
        quoteBuf += cleaned[i + 1];
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
        quotedStrings.push(quoteBuf);
        quoteBuf = "";
      } else {
        quoteBuf += ch;
      }
      continue;
    }

    if (commentDepth > 0) {
      if (ch === "\\" && i + 1 < cleaned.length) {
        commentBuf += cleaned[i + 1];
        i += 1;
      } else if (ch === "(") {
        commentDepth += 1;
        commentBuf += ch;
      } else if (ch === ")") {
        commentDepth -= 1;
        if (commentDepth === 0) {
          comments.push(commentBuf);
          commentBuf = "";
        } else {
          commentBuf += ch;
        }
      } else {
        commentBuf += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
      quoteBuf = "";
      bareOutside += " ";
      continue;
    }
    if (ch === "(") {
      commentDepth = 1;
      commentBuf = "";
      bareOutside += " ";
      continue;
    }
    if (ch === "<") {
      angleStart = i;
      continue;
    }
    if (ch === ">" && angleStart !== -1) {
      angles.push({
        start: angleStart,
        end: i,
        content: cleaned.slice(angleStart + 1, i).trim()
      });
      angleStart = -1;
      bareOutside += " ";
      continue;
    }
    if (angleStart === -1) {
      if (ch === "\\" && i + 1 < cleaned.length) {
        bareOutside += cleaned[i + 1];
        i += 1;
      } else {
        bareOutside += ch;
      }
    }
  }

  if (inQuotes && quoteBuf) quotedStrings.push(quoteBuf);
  if (commentDepth > 0 && commentBuf) comments.push(commentBuf);

  if (angles.length > 0) {
    const primary = angles[angles.length - 1];
    const address = primary.content.toLowerCase();
    const earlierAngles = angles.slice(0, -1).map((a) => a.content);
    const displayLabel = [bareOutside.trim(), ...quotedStrings, ...earlierAngles, ...comments]
      .filter(Boolean)
      .join(" ")
      .trim();
    return {
      displayLabel,
      address,
      domain: extractDomainFromAddress(address)
    };
  }

  const bareMatches = bareOutside.includes("@") ? bareOutside.match(HEADER_EMAIL_TOKEN_RE) : null;
  const address = bareMatches ? bareMatches[0].toLowerCase() : "";
  let residualOutside = bareOutside;
  if (bareMatches) {
    const firstIdx = residualOutside.indexOf(bareMatches[0]);
    if (firstIdx !== -1) {
      residualOutside =
        residualOutside.slice(0, firstIdx) + residualOutside.slice(firstIdx + bareMatches[0].length);
    }
  }
  const displayLabel = [residualOutside.trim(), ...quotedStrings, ...comments]
    .filter(Boolean)
    .join(" ")
    .trim();

  return {
    displayLabel,
    address,
    domain: extractDomainFromAddress(address)
  };
}

function parseMailboxList(rawHeader) {
  const str = String(rawHeader ?? "");
  if (!str.trim()) return [];
  const preDecoded = decodeRfc2047Words(str);
  return splitTopLevelMailboxes(preDecoded).map(parseSingleMailbox);
}

function findSpoofedDisplayEmail(displayLabel, actualAddress) {
  if (!displayLabel || !actualAddress) return null;
  const entityDecoded = decodeHtmlEntities(displayLabel).replace(INVISIBLE_UNICODE_RE, "");
  const folded = foldConfusables(entityDecoded);
  if (!folded.includes("@")) return null;

  const compactAt = folded.replace(/[ \t]*@[ \t]*/g, "@");
  const candidates = compactAt.match(HEADER_EMAIL_TOKEN_RE);
  if (!candidates) return null;

  const lowerRaw = entityDecoded.toLowerCase();
  for (const cand of candidates) {
    const lowerCand = cand.toLowerCase();
    if (lowerCand !== actualAddress) {
      return lowerCand;
    }
    // Same folded address only because homoglyphs or spaced '@' were normalized
    if (!lowerRaw.includes(actualAddress)) {
      return lowerCand;
    }
  }
  return null;
}

/**
 * Inspect an untrusted inbound email (headers + plain/HTML body) before
 * passing text to an automated triage or drafting step.
 *
 * Strips invisible Unicode characters and flags `From` display-name/comment spoofing,
 * multi-address `Reply-To` domain mismatches, hidden HTML/CSS content (via linear O(n)
 * HTML5 comment, attribute, and CSS declaration scanners), and instruction-override phrases.
 */
export function inspectInboundEmail(input = {}) {
  const opts = input && typeof input === "object" ? input : {};
  const findings = [];
  const safeFrom = String(opts.from ?? "");
  const safeReplyTo = String(opts.replyTo ?? "");
  const safeSubject = String(opts.subject ?? "");
  const safeText = String(opts.text ?? "");
  const safeHtml = String(opts.html ?? "");

  const fromMailboxes = parseMailboxList(safeFrom);
  const replyToMailboxes = parseMailboxList(safeReplyTo);

  for (const mb of fromMailboxes) {
    const spoofed = findSpoofedDisplayEmail(mb.displayLabel, mb.address);
    if (spoofed) {
      findings.push({
        code: "FROM_DISPLAY_NAME_SPOOF",
        severity: "high",
        detail: `From display name or comment embeds '${spoofed}' while actual sender address is '${mb.address}'.`
      });
      break;
    }
  }

  const fromDomains = new Set(fromMailboxes.map((m) => m.domain).filter(Boolean));
  if (fromDomains.size > 0) {
    const mismatchedReply = replyToMailboxes.find(
      (rt) => rt.domain && !fromDomains.has(rt.domain)
    );
    if (mismatchedReply) {
      const primaryFromDomain = [...fromDomains][0];
      findings.push({
        code: "REPLY_TO_DOMAIN_MISMATCH",
        severity: "medium",
        detail: `Sender domain '${primaryFromDomain}' differs from Reply-To domain '${mismatchedReply.domain}'.`
      });
    }
  }

  const decodedHtml = safeHtml ? decodeHtmlEntities(safeHtml) : "";
  const combinedForUnicode = `${safeFrom}\n${safeReplyTo}\n${safeSubject}\n${safeText}\n${decodedHtml}`;
  const invisibleMatches = combinedForUnicode.match(INVISIBLE_UNICODE_RE);
  if (invisibleMatches && invisibleMatches.length > 0) {
    findings.push({
      code: "INVISIBLE_UNICODE_CHARS",
      severity: invisibleMatches.length >= 8 ? "high" : "low",
      detail: `Detected ${invisibleMatches.length} invisible, variation-selector, or Unicode tag character(s) capable of hiding text from human reviewers.`
    });
  }

  if (safeHtml && scanHtmlHiddenSignals(safeHtml)) {
    findings.push({
      code: "HIDDEN_HTML_CONTENT",
      severity: "high",
      detail: "HTML email contains hidden DOM content (CSS display/visibility/opacity/font-size/offscreen/clip/same-color rules, <style> blocks, hidden/aria-hidden attributes, collapsed <details>, or <template>)."
    });
  }

  const normalizedPlain = foldConfusables(
    `${safeSubject}\n${safeText}`.replace(INVISIBLE_UNICODE_RE, "")
  );
  const normalizedHtmlText = safeHtml
    ? foldConfusables(extractHtmlTextForInspection(safeHtml).replace(INVISIBLE_UNICODE_RE, ""))
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
