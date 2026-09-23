// HOLE 9 — unguarded JSON.parse: an external file read without a try.
import { readFileSync } from "node:fs";
const yapilandirma = JSON.parse(readFileSync("./config.json", "utf8"));
export default yapilandirma;
