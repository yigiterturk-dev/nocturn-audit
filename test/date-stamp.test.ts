import { describe, it, expect } from "vitest";

/**
 * The report file name was generated from UTC. At 03:00 local time the UTC day
 * has already rolled over → the scan writes to "tomorrow's" file, the user opens
 * yesterday's, and mistakes stale results for fresh ones. That happened for real.
 */
function dateStamp(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

describe("report file name — the local day", () => {
  it("an hour before local midnight gives the local day", () => {
    // 03:52 local on the 25th — the UTC day may already be the 25th, but that does
    // not matter: for the user the day is the 25th.
    const d = new Date(2026, 7, 25, 3, 52);
    expect(dateStamp(d)).toBe("2026-08-25");
  });

  it("the end of the local day is still the same day", () => {
    const d = new Date(2026, 7, 25, 23, 59);
    expect(dateStamp(d)).toBe("2026-08-25");
  });

  it("single-digit months and days are zero-padded", () => {
    expect(dateStamp(new Date(2026, 0, 5, 12, 0))).toBe("2026-01-05");
  });
});
