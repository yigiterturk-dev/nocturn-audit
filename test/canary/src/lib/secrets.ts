// HOLE 10 — a provider key embedded in code (Stripe key shape).
//
// The value is deliberately, visibly fake: when the repository is shared,
// neither a human nor GitHub secret scanning should mistake it for real. The
// rule's pattern (sk_test_ plus 16+ alphanumerics) still matches, so the canary
// does its job.
export const STRIPE = "sk_test_CANARYFAKE000000";

// HOLE 11 — a weak JWT secret: a guessable constant.
export const JWT_SECRET = "secret";

// HOLE 12 — a weak hash: the password is stored with MD5.
import { createHash } from "node:crypto";
export function parolaOzeti(p: string) {
  return createHash("md5").update(p).digest("hex");
}
