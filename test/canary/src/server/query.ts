import { db } from "../../db/schema";

// HOLE 25 — a SQL column/table name built by string concatenation
// (parameterisation does not protect a column name).
export async function sirala(tablo: string, sutun: string, yon: string) {
  return db.query(`SELECT * FROM ${tablo} ORDER BY ${sutun} ${yon} LIMIT 100`);
}
