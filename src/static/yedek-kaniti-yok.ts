import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A08 — Müşteri verisi tutan canlı bir projede HESAP DIŞI yedek izi yok.
 *
 * NEDEN BU BİR BULGU: yönetilen veritabanları (Neon, Supabase, PlanetScale) kendi
 * zaman-içinde-geri-alma özelliğini sunar ve bu, yanlış bir `DELETE` ya da bozuk bir
 * migration için yeterlidir. Ama HESABIN KENDİSİ kaybedilirse — erişim kaybı, proje
 * silinmesi, sağlayıcı sorunu — o yedek de birlikte gider. Müşteri verisi tutan bir
 * üründe en az bir tane hesap dışı kopya olmalıdır.
 *
 * GERÇEK VAKA (bir rezervasyon SaaS, 2026-09-05): ürün canlıydı, satışa hazırlanıyordu ve
 * HİÇBİR yedeği yoktu. Dahası, yedek almayı denediğimizde alınamadığı ortaya çıktı:
 * Neon PostgreSQL 18 çalıştırıyor, yereldeki `pg_dump` 16'ydı ve
 * "aborting because of server version mismatch" verip SIFIR BAYT üretiyordu.
 * "Yedek komutumuz var" sanılan durumda gerçekte hiç yedek yoktu.
 *
 * BU KURALIN SINIRI: yedek bir CI işinde, sağlayıcı panelinde ya da sunucudaki bir
 * cron'da tanımlı olabilir — depoda izi olmayabilir. Bu yüzden bulgu INFO'dur ve
 * "doğrula" der, "yok" demez. Yanlış bir kesinlik iddiası, aracın güvenini bitirir.
 */

const YEDEK_IZI =
  /(pg_dump|pgdump|mysqldump|mongodump|sqlite3\s+\S+\s+["'`]?\.backup|litestream|wal-g|pgbackrest|barman|restic|borgbackup|duplicity|\bbackup\b|\byedek\b|point[-_ ]?in[-_ ]?time|\bPITR\b|snapshot)/i;

/** Yedeğin ZAMANLANDIĞINA dair iz — elle çalıştırılan bir betik tek başına yetmez. */
const ZAMANLAMA_IZI =
  /(cron|crontab|schedule|launchd|systemd|timer|\bdaily\b|\bgunluk\b|\bgünlük\b|workflow_dispatch|"schedule"|- cron:)/i;

/** Kalıcı veri tutulduğunun işaretleri. */
const VERI_IZI =
  /(prisma|drizzle|\bsupabase\b|postgres|postgresql|neon|mysql|mongodb|sqlite|DATABASE_URL)/i;

const isMetin = (f: string) =>
  /\.(ts|tsx|js|jsx|mjs|cjs|sh|bash|yml|yaml|toml|json|md|sql|Dockerfile|env\.example)$/i.test(f) ||
  /(^|\/)(Dockerfile|Makefile|crontab)$/i.test(f);

export const yedekKanitiYok: StaticRule = {
  id: "a08-yedek-kaniti-yok",
  title: "Canlı veri tutan projede hesap dışı yedek izi yok (doğrulanmalı)",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "info",
  kind: "static",
  requires: [],
  run(ctx): Finding[] {
    // Yalnız SAHİP OLUNAN ve CANLI projeler: başkasının deposu ya da yayında
    // olmayan bir deneme için yedek aramak gürültüdür.
    if (!ctx.project.owned || !ctx.project.url) return [];

    // Kalıcı veri var mı?
    const veriVar = ctx.grep(VERI_IZI).length > 0;
    if (!veriVar) return [];

    let yedekDosyasi: string | null = null;
    let zamanlama = false;

    for (const file of ctx.files.filter(isMetin)) {
      const content = ctx.read(file);
      if (!content) continue;
      if (!YEDEK_IZI.test(content) && !YEDEK_IZI.test(file)) continue;
      // "backup" kelimesi bir bağımlılık adında ya da düz metinde geçebilir;
      // gerçek bir yedek ARACI arıyoruz.
      const gercekArac =
        /(pg_dump|mysqldump|mongodump|litestream|wal-g|pgbackrest|barman|restic|borgbackup|duplicity)/i.test(content) ||
        /(^|\/)(backup|yedek)[^/]*\.(sh|ts|js|sql|yml|yaml)$/i.test(file);
      if (!gercekArac) continue;
      yedekDosyasi ??= file;
      if (ZAMANLAMA_IZI.test(content)) zamanlama = true;
    }

    if (yedekDosyasi && zamanlama) return [];   // hem araç hem zamanlama var

    const aciklama = yedekDosyasi
      ? `Projede bir yedek betiği var (${yedekDosyasi}) ama ZAMANLANDIĞINA dair iz yok ` +
        `(cron/systemd/CI zamanlaması). Elle çalıştırılan bir yedek, çalıştırılmadığı gün yoktur.`
      : `Proje canlı (${ctx.project.url}) ve kalıcı veri tutuyor, ama depoda hesap dışı ` +
        `yedeğe dair bir iz yok (pg_dump/mysqldump/litestream vb.).`;

    return [{
      ruleId: this.id,
      title: this.title,
      owasp: this.owasp,
      severity: "info",
      confidence: "likely",
      description:
        aciklama +
        ` Sağlayıcının kendi geri-alma özelliği (Neon/Supabase PITR) yanlış bir DELETE için ` +
        `yeterlidir ama HESABIN kaybı hâlinde yedek de birlikte gider. NOT: yedek sağlayıcı ` +
        `panelinde ya da sunucudaki bir cron'da tanımlı olabilir — bu bulgu "yedek yok" demez, ` +
        `"doğrula" der.`,
      evidence: [fileEvidence(yedekDosyasi ?? "package.json", 1, yedekDosyasi ? "yedek betiği var, zamanlama yok" : "yedek izi yok")],
      remediation:
        "Hesap dışı bir kopya alın ve ZAMANLAYIN (sunucuda cron ya da CI). İki şeyi ayrıca " +
        "doğrulayın: (1) istemci sürümü sunucudan eski olmasın — `pg_dump` sürüm uyuşmazlığı " +
        "sessizce SIFIR BAYT üretir; (2) yedeğin geri YÜKLENDİĞİNİ görün, yazıldığını değil. " +
        "Yedeğin kendisi de izlenmeli: hiç çalışmayan bir yedek işi kendi kendini haber veremez, " +
        "son başarılı yedeğin yaşına bakan ayrı bir bekçi gerekir.",
    }];
  },
};
