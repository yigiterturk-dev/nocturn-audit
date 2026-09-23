import { createServer } from "node:http";

/**
 * CANLI CANARY — kasten açık bırakılmış yerel sunucu.
 *
 * Statik kuralları `test/canary/` ile ölçüyoruz; canlı kuralları hiç
 * ölçmüyorduk. Sebebi de kötüydü: kendi sitelerimizin dördü Vercel bot
 * duvarının arkasında, araç oraya hiç ulaşamıyor. Yani aracın YARISI sahada
 * hiç denenmemişti — ve bunu "canlı testler atlandı" satırından biliyorduk
 * ama ölçmüyorduk.
 *
 * Bu sunucu o boşluğu kapatır: güvenlik başlığı yok, .env açıkta, yedek
 * dosyası açıkta, admin ucu kimliksiz, login freni yok ve kullanıcı sayımı
 * sızdırıyor, girdi encode edilmeden yansıyor, sağlık ucu hata dönüyor.
 */
export function startVulnerableServer() {
  const sunucu = createServer((istek, cevap) => {
    const url = new URL(istek.url ?? "/", "http://yerel");
    const yol = url.pathname;

    // AÇIK — hiçbir güvenlik başlığı yok (CSP/HSTS/X-Frame/nosniff/referrer).
    // AÇIK — çerez Secure/HttpOnly/SameSite bayrakları olmadan set ediliyor.
    const temel = {
      "content-type": "text/html; charset=utf-8",
      "set-cookie": "oturum=abc123; Path=/",
    };

    // AÇIK — .env dosyası web kökünden servis ediliyor.
    if (yol === "/.env") {
      cevap.writeHead(200, { "content-type": "text/plain" });
      return cevap.end("SUPABASE_SERVICE_ROLE_KEY=CANARYSAHTEDEGER\nDATABASE_URL=postgres://u:p@h/db\n");
    }

    // AÇIK — veritabanı yedeği açıkta.
    if (yol === "/backup.sql" || yol === "/db.sql.gz" || yol === "/.env.bak") {
      cevap.writeHead(200, { "content-type": "application/octet-stream" });
      return cevap.end("-- pg_dump\nCREATE TABLE kullanicilar (id uuid);\n");
    }

    // AÇIK — .git dizini açıkta.
    if (yol.startsWith("/.git/")) {
      cevap.writeHead(200, { "content-type": "text/plain" });
      return cevap.end("ref: refs/heads/main\n");
    }

    // AÇIK — yönetim/hassas uçlar kimlik doğrulaması olmadan cevap veriyor.
    if (["/admin", "/api/admin", "/api/users", "/api/debug", "/actuator", "/api/config"].includes(yol)) {
      cevap.writeHead(200, { ...temel, "content-type": "application/json" });
      return cevap.end(JSON.stringify({ kullanicilar: [{ id: 1, eposta: "a@b.com" }] }));
    }

    // AÇIK — sağlık ucu 500 dönüyor (bağımlılık ölü ama uç bunu düzgün
    // raporlamıyor, üstelik izleme bunu görmüyor).
    if (yol === "/api/health" || yol === "/healthz") {
      cevap.writeHead(500, { "content-type": "application/json" });
      return cevap.end(JSON.stringify({ status: "error", database: "unreachable" }));
    }

    // AÇIK — login: rate-limit yok, üstelik kullanıcı sayımı sızdırıyor
    // ("böyle bir kullanıcı yok" ile "parola hatalı" ayrı mesaj).
    if (yol === "/api/auth/login") {
      cevap.writeHead(401, { ...temel, "content-type": "application/json" });
      return cevap.end(JSON.stringify({ error: "Böyle bir kullanıcı bulunamadı" }));
    }

    // AÇIK — girdi encode edilmeden yansıyor (yansıyan XSS).
    const q = url.searchParams.get("q");
    if (q !== null) {
      cevap.writeHead(200, temel);
      return cevap.end(`<html><body><h1>Arama: ${q}</h1></body></html>`);
    }

    // AÇIK — strict-dynamic CSP var ama script'lerde nonce YOK.
    //
    // Bu, sessiz ölüm biçimidir: tarayıcı nonce'suz script'i çalıştırmaz,
    // sayfa "yüklendi" görünür ama işlevsizdir. Sunucu 200 döndüğü için
    // hiçbir izleme bunu yakalamaz.
    cevap.writeHead(200, {
      ...temel,
      "content-security-policy":
        "script-src 'strict-dynamic' 'nonce-abc123'; object-src 'none'; base-uri 'self'",
    });
    cevap.end(
      `<html><head><script src="/app.js"></script><script>window.x=1</script></head>` +
        `<body>Canlı canary</body></html>`,
    );
  });

  return new Promise((coz) => {
    sunucu.listen(0, "127.0.0.1", () => {
      const port = sunucu.address().port;
      coz({ port, url: `http://127.0.0.1:${port}`, kapat: () => sunucu.close() });
    });
  });
}
