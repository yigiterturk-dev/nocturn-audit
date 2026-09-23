import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A09 — a schema/DDL error swallowed by a bare `except` → silent schema drift.
 *
 * Flask/SQLite projects without Django often do a "poor man's migration" like
 * this:
 *     try:
 *         cursor.execute("ALTER TABLE t ADD COLUMN c TEXT")
 *     except:            # ya da: except Exception:
 *         pass
 * The goal is idempotence: skip if the column already exists. BUT a bare except
 * swallows not only the expected "duplicate column" case but REAL errors such
 * as a LOCKED (busy) database, a full disk or a corrupt table. When that
 * happens the column is never added and something FAR downstream fails with
 * "no such column" — hard to diagnose, because the error surfaces where the
 * column is READ while the place that ADDS it stays silent. init_db reports
 * success while the schema is actually broken ("the system says it is fine
 * and it is not").
 *
 * Real case: an init_db ran 16 separate `try: ALTER... except: pass` blocks;
 * if another writer held the lock during the startup migration, ALTER would
 * throw "database is locked" and be swallowed silently. The fix: catch only
 * 'duplicate column' and RE-RAISE the rest.
 *
 * This rule flags a bare except (`except:` or `except Exception:`) whose body is
 * only `pass`, inside a try block that wraps a DDL statement (ALTER TABLE /
 * CREATE INDEX / ADD COLUMN). A narrowed except
 * (except sqlite3.OperationalError...) is not flagged.
 */

const DDL = /\b(ALTER\s+TABLE|ADD\s+COLUMN|CREATE\s+(UNIQUE\s+)?INDEX|DROP\s+(TABLE|INDEX))\b/i;
// Bare: `except:` or `except Exception[ as e]:` — no specific error type.
const BARE_EXCEPT = /^\s*except\s*(Exception(\s+as\s+\w+)?\s*)?:\s*(pass\s*)?$/;
const isSourceLike = (f: string) =>
  /\.py$/.test(f) && !/(test|spec|conftest)/.test(f);

export const swallowedDdlError: StaticRule = {
  id: "a09-swallowed-ddl-error",
  title: "Schema/DDL error swallowed by a bare except (silent schema drift)",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "low",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    // Look only at files that mention DDL.
    const ddlHits = ctx.grep(DDL);
    const files = new Set(ddlHits.map((m) => m.file).filter(isSourceLike));

    for (const file of files) {
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const l = lines[i] ?? "";
        // BARE_EXCEPT matches only `except:` and `except Exception[ as e]:`;
        // a narrowed one (except sqlite3.OperationalError:) does not match -> skipped.
        if (!BARE_EXCEPT.test(l)) continue;

        // Is the body only `pass`? (inline `except: pass` or on the next line)
        const inline = /:\s*pass\s*$/.test(l);
        if (!inline) {
          // the next non-empty line must be `pass`
          let j = i + 1;
          while (j < lines.length && (lines[j] ?? "").trim() === "") j++;
          if ((lines[j] ?? "").trim() !== "pass") continue;
        }

        // Does the try block wrapping this except contain DDL? Scan ~12 lines up.
        // `try:`e ulasinca dur.
        let hasDdl = false;
        for (let k = i - 1; k >= Math.max(0, i - 12); k--) {
          const u = lines[k] ?? "";
          if (DDL.test(u)) { hasDdl = true; }
          if (/^\s*try\s*:/.test(u)) break;
          if (/^\s*(def |class )/.test(u)) break;
        }
        if (!hasDdl) continue;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "low",
          description:
            `${file}:${i + 1} bir DDL ifadesini (ALTER/CREATE INDEX) saran ` +
            `The try block uses a bare \`except: pass\`. That swallows not only the expected ` +
            `"column already exists" case but REAL errors such as a locked database or a full ` +
            `disk. The DDL fails silently, the schema stays broken, and downstream code ` +
            `explodes with "no such column" while init_db reports success.`,
          evidence: [fileEvidence(file, i + 1, l.trim().slice(0, 80))],
          remediation:
            "Narrow the except: swallow only the expected case " +
            "(sqlite3.OperationalError plus a 'duplicate column' check) " +
            "and `raise` everything else. Keep that helper in one place " +
            "so repeated DDL blocks stay DRY.",
        });
      }
    }
    return findings;
  },
};
