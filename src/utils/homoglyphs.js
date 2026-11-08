/**
 * Homoglyph, Punycode, Typosquatting, and Entropy Analysis Utilities
 */

// Mapping of common Cyrillic, Greek, and Unicode lookalikes to Latin characters
const HOMOGLYPH_MAP = {
  // Cyrillic lookalikes
  '\u0430': 'a', // Cyrillic small letter a
  '\u0410': 'A',
  '\u0441': 'c', // Cyrillic small letter es
  '\u0421': 'C',
  '\u0435': 'e', // Cyrillic small letter ie
  '\u0415': 'E',
  '\u0456': 'i', // Cyrillic small letter byelorussian-ukrainian i
  '\u0406': 'I',
  '\u0458': 'j', // Cyrillic small letter je
  '\u0408': 'J',
  '\u043E': 'o', // Cyrillic small letter o
  '\u041E': 'O',
  '\u0440': 'p', // Cyrillic small letter er
  '\u0420': 'P',
  '\u0455': 's', // Cyrillic small letter dze
  '\u0405': 'S',
  '\u0445': 'x', // Cyrillic small letter ha
  '\u0425': 'X',
  '\u0443': 'y', // Cyrillic small letter u
  '\u0423': 'Y',

  // Greek lookalikes
  '\u03B1': 'a', // Greek small letter alpha
  '\u0391': 'A',
  '\u03B2': 'b', // Greek small letter beta
  '\u0392': 'B',
  '\u03B5': 'e', // Greek small letter epsilon
  '\u0395': 'E',
  '\u03B7': 'n', // Greek small letter eta
  '\u0399': 'I', // Greek capital letter iota
  '\u03BF': 'o', // Greek small letter omicron
  '\u039F': 'O',
  '\u03C1': 'p', // Greek small letter rho
  '\u03A1': 'P',
  '\u03C4': 't', // Greek small letter tau
  '\u03A4': 'T',
  '\u03C5': 'u', // Greek small letter upsilon
  '\u03A5': 'Y',
  '\u03C7': 'x', // Greek small letter chi
  '\u03A7': 'X',

  // Number substitutes frequently used in leetspeak typosquatting
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '8': 'b',
  '@': 'a',
  '$': 's',
  'vv': 'w',
  'rn': 'm'
};

/**
 * Standard Punycode decoding algorithm (RFC 3492)
 */
function decodePunycode(input) {
  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  const delimiter = '-';

  function adapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tmin) * tmax) >> 1) {
      delta = Math.floor(delta / (base - tmin));
      k += base;
    }
    return k + Math.floor(((base - tmin + 1) * delta) / (delta + skew));
  }

  function decodeDigit(cp) {
    if (cp >= 48 && cp <= 57) return cp - 22; // 0-9 -> 26-35
    if (cp >= 65 && cp <= 90) return cp - 65; // A-Z -> 0-25
    if (cp >= 97 && cp <= 122) return cp - 97; // a-z -> 0-25
    return base;
  }

  const output = [];
  const inputLower = input.toLowerCase();
  const lastDelim = inputLower.lastIndexOf(delimiter);

  if (lastDelim > 0) {
    for (let j = 0; j < lastDelim; ++j) {
      const code = inputLower.charCodeAt(j);
      if (code >= 128) return input; // invalid basic code point
      output.push(inputLower.charAt(j));
    }
  }

  let i = 0;
  let n = initialN;
  let bias = initialBias;
  let pos = lastDelim > 0 ? lastDelim + 1 : 0;

  while (pos < inputLower.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (pos >= inputLower.length) return input;
      const digit = decodeDigit(inputLower.charCodeAt(pos++));
      if (digit >= base) return input;
      i += digit * w;
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, String.fromCodePoint(n));
    i++;
  }

  return output.join('');
}

/**
 * Normalizes an IDN or punycode domain into its UTF-8 decoded form
 */
function toUnicodeDomain(domain) {
  if (!domain) return '';
  return domain
    .split('.')
    .map(label => {
      if (label.toLowerCase().startsWith('xn--')) {
        try {
          return decodePunycode(label.slice(4));
        } catch {
          return label;
        }
      }
      return label;
    })
    .join('.');
}

/**
 * Detects if a domain uses IDN Homograph or Confusable characters
 */
function analyzeHomoglyphs(domain) {
  const unicodeDomain = toUnicodeDomain(domain);
  const detectedHomoglyphs = [];
  let normalizedAscii = '';

  for (let i = 0; i < unicodeDomain.length; i++) {
    const char = unicodeDomain[i];
    const codePoint = char.codePointAt(0);

    // Check if character is non-ASCII or in homoglyph dictionary
    if (HOMOGLYPH_MAP[char]) {
      detectedHomoglyphs.push({
        char,
        codePoint: `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`,
        replacement: HOMOGLYPH_MAP[char],
        position: i
      });
      normalizedAscii += HOMOGLYPH_MAP[char];
    } else {
      normalizedAscii += char;
    }
  }

  const isPunycode = domain.toLowerCase().includes('xn--');
  const hasMixedScripts = detectedHomoglyphs.length > 0;

  return {
    original: domain,
    unicodeDomain,
    normalizedAscii,
    isPunycode,
    hasMixedScripts,
    homoglyphsFound: detectedHomoglyphs,
    riskFactor: isPunycode || hasMixedScripts ? 0.85 : 0
  };
}

/**
 * Calculates Damerau-Levenshtein distance between two strings
 * (Accounts for insertions, deletions, substitutions, and transpositions)
 */
function damerauLevenshteinDistance(source, target) {
  if (!source || !target) return (source || target || '').length;

  const s = source.toLowerCase();
  const t = target.toLowerCase();
  const m = s.length;
  const n = t.length;

  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1, // deletion
        d[i][j - 1] + 1, // insertion
        d[i - 1][j - 1] + cost // substitution
      );

      // Transposition
      if (i > 1 && j > 1 && s[i - 1] === t[j - 2] && s[i - 2] === t[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }

  return d[m][n];
}

/**
 * Shannon Entropy calculation for a string
 * High entropy (> 3.8 for domains) often indicates algorithmic / DGA generation
 */
function calculateShannonEntropy(str) {
  if (!str) return 0;
  const cleanStr = str.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  if (cleanStr.length === 0) return 0;

  const freqs = {};
  for (const ch of cleanStr) {
    freqs[ch] = (freqs[ch] || 0) + 1;
  }

  let entropy = 0;
  const len = cleanStr.length;
  for (const ch in freqs) {
    const p = freqs[ch] / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

module.exports = {
  HOMOGLYPH_MAP,
  decodePunycode,
  toUnicodeDomain,
  analyzeHomoglyphs,
  damerauLevenshteinDistance,
  calculateShannonEntropy
};
