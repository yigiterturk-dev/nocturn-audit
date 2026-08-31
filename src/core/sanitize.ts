/**
 * Blanks out the regions that are NOT code: comments and regex literals.
 *
 * Length and line breaks are PRESERVED — every character becomes a space in
 * the same position. Line and column numbers therefore stay intact, and the
 * result is the same however a rule scans (ctx.grep or its own loop).
 *
 * Why this is needed: running the tool on itself, two of the three remaining
 * HIGH findings were the rule's own search pattern (`/child_process|exec\(/`),
 * and the third was a COMMENT line (`* A05 — Access-Control-Allow-Origin: *`).
 * Neither is code. This is not peculiar to us: the same happens in any project
 * with an input validator, a log scrubber, or a comment saying "never do this".
 *
 * String literals are PRESERVED — a genuinely leaked key lives in one.
 */

const BOSLUK = (text: string): string =>
  text.replace(/[^\n]/g, " ");

/**
 * Is a string literal plain TEXT (a message or description), or a VALUE (a key,
 * komut, yol)?
 *
 * The test is word count: secrets and commands are single tokens, not sentences.
 */
function isPlainText(dize: string): boolean {
  const content = dize.slice(1, -1);
  if (content.length < 25) return false;
  const kelimeler = content.trim().split(/\s+/);
  if (kelimeler.length < 4) return false;
  // Strings containing template interpolation can carry code; left untouched.
  if (/\$\{/.test(content)) return false;
  return true;
}

/** Blanks out comments, regex literals and plain-text strings. */
export function blankNonCode(source: string): string {
  let out = "";
  let i = 0;
  // A regex literal can only begin after certain characters; otherwise `a / b`
  // would be mistaken for one.
  let regexBaslayabilir = true;

  while (i < source.length) {
    const c = source[i];
    const sonraki = source[i + 1];

    // SQL line comments (`--`). SQL files are cleaned too: in one project's RLS
    // file the word `service_role` appeared inside a COMMENT and was reported
    // as a leaked key.
    if (c === "-" && sonraki === "-") {
      const son = source.indexOf("\n", i);
      const bitis = son === -1 ? source.length : son;
      out += BOSLUK(source.slice(i, bitis));
      i = bitis;
      continue;
    }
    // Line comment
    if (c === "/" && sonraki === "/") {
      const son = source.indexOf("\n", i);
      const bitis = son === -1 ? source.length : son;
      out += BOSLUK(source.slice(i, bitis));
      i = bitis;
      continue;
    }
    // Blok yorumu
    if (c === "/" && sonraki === "*") {
      const son = source.indexOf("*/", i + 2);
      const bitis = son === -1 ? source.length : son + 2;
      out += BOSLUK(source.slice(i, bitis));
      i = bitis;
      continue;
    }
    // String / template — CONTENTS PRESERVED (a real secret may live here).
    if (c === '"' || c === "'" || c === "`") {
      const tirnak = c;
      let j = i + 1;
      while (j < source.length) {
        if (source[j] === "\\") { j += 2; continue; }
        if (source[j] === tirnak) { j += 1; break; }
        j += 1;
      }
      const dize = source.slice(i, j);
      // PLAIN TEXT strings are blanked out too.
      //
      // A secret, a command or a header name is never four words long. Message
      // catalogues, i18n files and prose are exactly that — and they contain
      // words that look dangerous ("running child_process", "reflecting
      // Access-Control-Allow-Origin"). The rules were reading those as code.
      //
      // Short strings with no spaces are PRESERVED: a real leaked key is one.
      out += isPlainText(dize) ? BOSLUK(dize) : dize;
      i = j;
      regexBaslayabilir = false;
      continue;
    }
    // Regex literal
    if (c === "/" && regexBaslayabilir) {
      let j = i + 1;
      let sinifIcinde = false;
      let kapandi = false;
      while (j < source.length && source[j] !== "\n") {
        if (source[j] === "\\") { j += 2; continue; }
        if (source[j] === "[") sinifIcinde = true;
        else if (source[j] === "]") sinifIcinde = false;
        else if (source[j] === "/" && !sinifIcinde) { j += 1; kapandi = true; break; }
        j += 1;
      }
      if (kapandi) {
        while (j < source.length && /[gimsuyd]/.test(source[j])) j += 1;
        out += BOSLUK(source.slice(i, j));
        i = j;
        regexBaslayabilir = false;
        continue;
      }
    }

    out += c;
    if (!/\s/.test(c)) regexBaslayabilir = /[=(,:[!&|?{};+\-*%<>~^]/.test(c);
    i += 1;
  }
  return out;
}
