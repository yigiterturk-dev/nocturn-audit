// HOLE 30 — the monitor runs but has no alert target: it finds the failure,
// and tells nobody.
export async function nobetTuru() {
  const sonuc = await saglikKontrol();
  if (!sonuc.saglikli) {
    console.error("System unhealthy:", result.reason);
  }
  return sonuc;
}

declare function saglikKontrol(): Promise<{ saglikli: boolean; reason: string }>;
