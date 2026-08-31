import { writeFileSync } from "node:fs";

// HOLE — malware scanning happens AFTER the file is WRITTEN: the file
// the moment it hits disk another process can read it and serve it. The scan
// must happen BEFORE the write.
export async function dosyaYukle(ad: string, icerik: Buffer) {
  writeFileSync(`/yuklemeler/${ad}`, icerik);
  const temiz = await scanFile(`/yuklemeler/${ad}`);
  if (!temiz) throw new Error("Malicious file");
  return { ok: true };
}

declare function scanFile(yol: string): Promise<boolean>;
