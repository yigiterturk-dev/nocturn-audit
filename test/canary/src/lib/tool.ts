import { exec } from "node:child_process";

// HOLE 5 — command injection: request input reaches the shell.
export function yedekAl(req: { query: { dosya: string } }) {
  exec(`tar czf /tmp/yedek.tgz ${req.query.dosya}`);
}

// HOLE 6 — SSRF: the target host comes from the caller and the body is returned.
export async function icerikGetir(hedefUrl: string) {
  const cevap = await fetch(hedefUrl);
  return cevap.text();
}
