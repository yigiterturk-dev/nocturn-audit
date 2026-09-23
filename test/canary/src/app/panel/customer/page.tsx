import { getPanelActor } from "../../../lib/panel-actor";

// HOLE — the page uses a NARROWER auth path than the API: the API calls `getUser()`
// ile herkesi tanırken sayfa yalnızca personeli tanıyan `getPanelActor()`
// çağırıyor. Giriş yapmış kiracı kendi portalına giremez ve bu hata API
// testlerinde hiç görünmez.
export default async function MusteriPaneli() {
  const aktor = await getPanelActor();
  if (!aktor) return <p>Yetkisiz</p>;
  return <div>Panel</div>;
}
