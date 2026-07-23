"use strict";

/**
 * norm-core.js — shared pragmatic normalization helper.
 *
 * Used by docs-lint.js (List A) and hygiene-scan.js (List B).
 *
 * Pipeline:
 *   1. NFKC normalization
 *   2. Strip zero-width characters (U+200B/C/D/E/F, U+FEFF)
 *   3. Strip soft hyphen (U+00AD)
 *   4. Fold fullwidth Latin (U+FF21-FF5A) to ASCII
 *   5. Fold common Cyrillic/Greek homoglyphs to Latin (PRAGMATIC, not full TR39)
 *   6. Decode %-encodings loop-to-stable (handles double/triple encoding)
 *   7. Collapse whitespace to single space
 *
 * FOR DOCS-LINT ONLY (normalizeForDocsLint):
 *   8. Neutralize intra-token markdown emphasis (pr*oven* → proven)
 *   9. Neutralize intra-token hyphenation (pro-ven → proven)
 *  10. Neutralize intra-token underscores (exactly_once → exactlyonce)
 *
 * This is a PRAGMATIC confusables set, not full Unicode TR39.
 * Common Cyrillic/Greek → Latin homoglyph coverage:
 *   Cyrillic: а→a  е→e  о→o  р→p  с→c  х→x  у→y  к→k  м→m  н→n  т→t  в→b  г→g
 *   Greek:    α→a  ε→e  ο→o  ρ→p  τ→t  κ→k  ν→n  χ→x  υ→y  β→b
 *
 * Zero deps. CommonJS. Deterministic.
 */

// --- Character-level confusable map (single-character → replacement) -----------

const ZW_CHARS_RE = /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD]/g;

const FULLWIDTH_LATIN_MAP = {
  "\uFF10": "0", "\uFF11": "1", "\uFF12": "2", "\uFF13": "3", "\uFF14": "4",
  "\uFF15": "5", "\uFF16": "6", "\uFF17": "7", "\uFF18": "8", "\uFF19": "9",
  "\uFF21": "A", "\uFF22": "B", "\uFF23": "C", "\uFF24": "D", "\uFF25": "E",
  "\uFF26": "F", "\uFF27": "G", "\uFF28": "H", "\uFF29": "I", "\uFF2A": "J",
  "\uFF2B": "K", "\uFF2C": "L", "\uFF2D": "M", "\uFF2E": "N", "\uFF2F": "O",
  "\uFF30": "P", "\uFF31": "Q", "\uFF32": "R", "\uFF33": "S", "\uFF34": "T",
  "\uFF35": "U", "\uFF36": "V", "\uFF37": "W", "\uFF38": "X", "\uFF39": "Y",
  "\uFF3A": "Z",
  "\uFF41": "a", "\uFF42": "b", "\uFF43": "c", "\uFF44": "d", "\uFF45": "e",
  "\uFF46": "f", "\uFF47": "g", "\uFF48": "h", "\uFF49": "i", "\uFF4A": "j",
  "\uFF4B": "k", "\uFF4C": "l", "\uFF4D": "m", "\uFF4E": "n", "\uFF4F": "o",
  "\uFF50": "p", "\uFF51": "q", "\uFF52": "r", "\uFF53": "s", "\uFF54": "t",
  "\uFF55": "u", "\uFF56": "v", "\uFF57": "w", "\uFF58": "x", "\uFF59": "y",
  "\uFF5A": "z",
};

const HOMOGLYPH_MAP = {
  // Cyrillic → Latin
  "\u0430": "a", // а
  "\u0435": "e", // е
  "\u043E": "o", // о
  "\u0440": "p", // р
  "\u0441": "c", // с
  "\u0445": "x", // х
  "\u0443": "y", // у
  "\u043A": "k", // к
  "\u043C": "m", // м
  "\u043D": "n", // н
  "\u0442": "t", // т
  "\u0432": "b", // в
  "\u0433": "g", // г
  // Greek → Latin
  "\u03B1": "a", // α
  "\u03B5": "e", // ε
  "\u03BF": "o", // ο
  "\u03C1": "p", // ρ
  "\u03C4": "t", // τ
  "\u03BA": "k", // κ
  "\u03BD": "n", // ν
  "\u03C7": "x", // χ
  "\u03C5": "y", // υ
  "\u03B2": "b", // β
};

const HOMOGLYPH_RE = /[\u0430\u0435\u043E\u0440\u0441\u0445\u0443\u043A\u043C\u043D\u0442\u0432\u0433\u03B1\u03B5\u03BF\u03C1\u03C4\u03BA\u03BD\u03C7\u03C5\u03B2]/g;
const FULLWIDTH_RE = /[\uFF10-\uFF19\uFF21-\uFF3A\uFF41-\uFF5A]/g;

// --- normalization pipeline ---------------------------------------------------

/**
 * Base normalization: NFKC → strip ZW → fold fullwidth → fold homoglyphs →
 * decode %-encodings loop-to-stable → collapse whitespace.
 * Returns lowercased result.
 */
function baseNormalize(s) {
  if (typeof s !== "string") return "";

  // 1. NFKC
  let t = s.normalize("NFKC");

  // 2. Strip zero-width chars and soft hyphen
  t = t.replace(ZW_CHARS_RE, "");

  // 3. Fold fullwidth Latin to ASCII
  t = t.replace(FULLWIDTH_RE, function (ch) { return FULLWIDTH_LATIN_MAP[ch] || ch; });

  // 4. Fold Cyrillic/Greek homoglyphs to Latin
  t = t.replace(HOMOGLYPH_RE, function (ch) { return HOMOGLYPH_MAP[ch] || ch; });

  // 5. Decode %-encodings loop-to-stable
  let prev = "";
  while (prev !== t) {
    prev = t;
    try { t = decodeURIComponent(t); } catch (e) { break; }
  }

  // 6. Collapse whitespace to single space, lowercase
  t = t.replace(/\s+/g, " ").trim().toLowerCase();

  return t;
}

/**
 * Docs-lint normalization: base + neutralize intra-token markdown emphasis,
 * hyphenation, and underscores so a bare over-claim can't trivially evade.
 *
 * Examples:
 *   pr*oven*   → proven   (markdown italic emphasis)
 *   **proven** → proven   (markdown bold emphasis — word body intact already,
 *                          but the neutralizer strips ** between word chars)
 *   pro-ven    → proven   (hyphenation)
 *   exactly_once → exactlyonce (underscore)
 */
function neutralizeProse(s) {
  if (typeof s !== "string") return "";
  let t = s;
  // Strip markdown emphasis markers (*, **, _, __) that appear between word chars.
  // We repeat until stable to handle nested emphasis like *pr*oven* or _exactly_once_.
  let prev2 = "";
  while (prev2 !== t) {
    prev2 = t;
    t = t.replace(/([a-zA-Z\u00C0-\u024F])\*{1,2}([a-zA-Z\u00C0-\u024F])/g, "$1$2");
    t = t.replace(/([a-zA-Z\u00C0-\u024F])_{1,2}([a-zA-Z\u00C0-\u024F])/g, "$1$2");
  }
  // Strip hyphens between word characters (pro-ven → proven)
  t = t.replace(/([a-zA-Z\u00C0-\u024F])-([a-zA-Z\u00C0-\u024F])/g, "$1$2");
  // Strip underscores between word characters (exactly_once → exactlyonce)
  // (also catches _emphasis_ markers but that's fine)
  t = t.replace(/([a-zA-Z\u00C0-\u024F])_([a-zA-Z\u00C0-\u024F])/g, "$1$2");
  return t;
}

function normalizeForDocsLint(s) {
  return baseNormalize(neutralizeProse(s));
}

/**
 * Hygiene filename normalization: base normalization then strip non-alphanumeric.
 */
function normalizeFilename(s) {
  let t = baseNormalize(s);
  t = t.replace(/[^a-z0-9]/g, "");
  return t;
}

module.exports = {
  baseNormalize,
  normalizeForDocsLint,
  normalizeFilename,
  neutralizeProse,
};