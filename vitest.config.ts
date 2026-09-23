import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // CANARY FİKSTÜRLERİ TEST DEĞİLDİR.
    //
    // `test/canary/` kasten açık bırakılmış SAHTE bir projedir; içindeki
    // `tests/*.test.mjs` dosyaları bir kuralın ("test listesi elle sayılmış")
    // fikstürüdür, çalıştırılacak test değil. Vitest onları gerçek test sanıp
    // "No test suite found" diye 4 dosyayı kırmızıya çeviriyordu — ve bu,
    // "Tests: 568 passed" satırına bakan birinin gözünden kaçıyordu.
    // Süitin yeşil GÖRÜNMESİ ile yeşil OLMASI aynı şey değil.
    exclude: ["**/node_modules/**", "**/dist/**", "test/canary/**"],
  },
});
