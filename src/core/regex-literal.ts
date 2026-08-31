/**
 * Tells whether a match sits inside a REGEX literal.
 *
 * `/child_process|exec\(/` is not a call, it is a DETECTOR. The same thing exists
 * in every project: input validators, log scrubbers and routing rules all carry
 * dangerous-looking words as patterns. When a rule reads those as code it
 * reports "command execution" or "CORS reflection".
 *
 * Running the tool on itself, all three HIGH findings were exactly this: the
 * kendi arama deseni.
 */

/**
 * The ranges of the regex literals on a line.
 *
 * To avoid confusion with division, a literal can only begin after certain
 * characters (`=`, `(`, `,`, `:`, `[`, `!`, `&`, `|`, `?`, `{`, `;`, whitespace or
 * the start of the line) — `a / b` is not a literal.
 */
function regexAraliklari(line: string): Array<[number, number]> {
  const araliklar: Array<[number, number]> = [];
  const kalip = /(^|[=(,:[!&|?{};]\s*|\breturn\s+|\btest\s*\(\s*|\bmatch\s*\(\s*)\/(?![*/])((?:\\.|\[(?:\\.|[^\]\n])*\]|[^/\\\n])+)\/[gimsuyd]*/g;
  let m: RegExpExecArray | null;
  while ((m = kalip.exec(line)) !== null) {
    const bas = m.index + m[1].length;
    araliklar.push([bas, kalip.lastIndex]);
  }

  // `new RegExp("...")` — patterns built from strings are detectors too.
  const yapici = /new\s+RegExp\s*\(\s*(["'`])(?:\\.|(?!\1)[^\\])*\1/g;
  while ((m = yapici.exec(line)) !== null) {
    araliklar.push([m.index, yapici.lastIndex]);
  }
  return araliklar;
}

/** Is the given column inside a pattern definition on this line? */
export function isInsideRegexLiteral(line: string, sutun: number): boolean {
  return regexAraliklari(line).some(([bas, son]) => sutun >= bas && sutun < son);
}
