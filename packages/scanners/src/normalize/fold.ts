/** Zero-width, bidi, and invisible Unicode characters stripped before analysis. */
export const ZERO_WIDTH_CHARS =
  /[\u200b-\u200f\u2028\u2029\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad]/g;

export function stripZeroWidth(input: string): string {
  return input.replace(ZERO_WIDTH_CHARS, "");
}

/** A small set of visually-confusable homoglyphs (Cyrillic, full-width, etc.). */
export const HOMOGLYPH_MAP: Readonly<Record<string, string>> = {
  "\u0430": "a", // а
  "\u0435": "e", // е
  "\u043e": "o", // о
  "\u0440": "p", // р
  "\u0441": "c", // с
  "\u0445": "x", // х
  "\u0443": "y", // у
  "\u0456": "i", // і
  "\u0455": "s", // ѕ
  "\u04bb": "h", // һ
  "\u0458": "j", // ј
  "\u0472": "w", // Ѳ
  "\uff10": "0",
  "\uff11": "1",
  "\uff12": "2",
  "\uff13": "3",
  "\uff14": "4",
  "\uff15": "5",
  "\uff16": "6",
  "\uff17": "7",
  "\uff18": "8",
  "\uff19": "9",
  "\uff41": "a",
  "\uff4c": "l",
  "\uff4f": "o",
  "\u03bf": "o", // ο greek omicron
  "\u03b9": "i", // ι
  "\u03bd": "v", // ν
  "\u1d20": "p", // ᴘ
};

export function foldHomoglyphs(input: string): string {
  let out = "";
  for (const ch of input) {
    out += HOMOGLYPH_MAP[ch] ?? ch;
  }
  return out;
}

/** NFKC normalization + zero-width strip + homoglyph fold. */
export function fold(input: string): string {
  return foldHomoglyphs(stripZeroWidth(input.normalize("NFKC")));
}
