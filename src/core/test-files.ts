/**
 * Recognises test and fixture files.
 *
 * This surfaced while running a security scanner on itself: the rule's own
 * search patterns ("service_role", "child_process") and the fixtures exercising
 * them were reported as CERTAIN CRITICAL findings. The tool mistook its own
 * detector for a leak.
 *
 * But this is not a peculiar problem: every project that keeps a fake key in its
 * fixtures gets the same false critical — and that is a very common pattern. Test
 * data is NOT PRODUCTION SURFACE; a fake key there is a scenario, not a leak.
 * senaryodur.
 *
 * Handling it rule by rule was tried and failed: only 19 of 38 rule files
 * skipped test files. The decision belongs in the engine, in one place.
 */
const TEST_YOLU =
  /(^|\/)(__tests__|__mocks__|__fixtures__|tests?|spec|specs|fixtures?|e2e|cypress|playwright|stories)(\/|$)/i;

const TEST_FILE_RE = /\.(test|spec|stories|fixture|mock)\.[jt]sx?$/i;

/** Is this file test or fixture surface? */
export function isTestOrFixture(file: string): boolean {
  const f = file.replace(/\\/g, "/");
  return TEST_YOLU.test(f) || TEST_FILE_RE.test(f);
}
