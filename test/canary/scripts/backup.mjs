import { writeFileSync } from "node:fs";
import { execSync } from "node:child_process";

// HOLE — a backup is taken but the restore is never rehearsed.
// Denenmemiş yedek, yedek değil temennidir: bozuk olduğu ancak ihtiyaç
// duyulduğu gün anlaşılır.
const dokum = execSync("pg_dump $DATABASE_URL").toString();
writeFileSync(`/yedek/db-${process.env.GUN}.sql`, dokum);
console.log("Yedek alındı");
