import jwt from "jsonwebtoken";

// HOLE 14 — weak JWT verification: decoded without checking the signature, then used for AUTHORISATION.
export function oturumOku(token: string) {
  const yuk = jwt.decode(token) as { sub?: string; role?: string };
  const isAdmin = yuk?.role === "admin";
  return { userId: yuk?.sub, isAdmin };
}

// HOLE 15 — a forgeable client IP in a security decision.
// HOLE 19 — the rate-limit counter lives in module-level memory (on serverless
// every instance starts from zero, so the brake does nothing).
const rateLimitStore = new Map<string, number>();
const RATE_LIMIT_MAX = 5;

export function girisFreni(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0] ?? "yerel";
  const deneme = (rateLimitStore.get(ip) ?? 0) + 1;
  rateLimitStore.set(ip, deneme);
  if (deneme > RATE_LIMIT_MAX) {
    return { limited: true, status: 429, retryAfter: 60 };
  }
  return { limited: false, status: 200, retryAfter: 0 };
}
