/**
 * USER-FACING LANGUAGE — `NOCTURN_LANG=tr|en`, default "en".
 *
 * The tool speaks two languages: rule logic and code comments stay as written,
 * but the REPORT surface (scores, labels, gap notes) follows this setting.
 * Default is English because the public audience decides it; Turkish users set
 * the env once and keep their alphabet.
 */
export type Lang = "tr" | "en";

export function userLang(): Lang {
  const v = (process.env.NOCTURN_LANG ?? "").toLowerCase();
  return v.startsWith("tr") ? "tr" : "en";
}

/** Pick the right string for the active language. */
export function dil(lang: Lang, tr: string, en: string): string {
  return lang === "tr" ? tr : en;
}
