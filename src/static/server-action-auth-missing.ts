import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { callsAuthHelper, collectAuthHelpers } from "../core/auth-helpers.js";

/**
 * A01 — `"use server"` fonksiyonu yetki kapısı olmadan veritabanına dokunuyor.
 *
 * NEDEN ÖNEMLİ: bir server action, dosyanın içinde duran sıradan bir fonksiyon
 * gibi görünür ama Next onun için bir HTTP uç noktası yayınlar. Kimlik doğrulaması
 * olmayan bir action, INTERNETTEN DOĞRUDAN çağrılabilir — üstelik hiçbir `app/api/`
 * dosyası olmadığı için "API'm yok ki" diye düşünülür. `a01-api-route-auth-missing`
 * yalnız route dosyalarına bakar; bu boşluk oradan geçer.
 *
 * ÖZELLİKLE TEHLİKELİ HAL: sorgu KİRACI KAPSAMI DIŞINDA çalışıyorsa (RLS'i atlayan
 * bir rol, `service_role`, ya da tenant sarmalayıcısı olmayan doğrudan sorgu). O
 * zaman kapısız tek bir fonksiyon, oturum açan HERKESE bütün müşterilerin verisini
 * açar.
 *
 * GERÇEK VAKA (bir rezervasyon SaaS, 2026-09-05): vendor paneli `lib/admin/*` bilinçli olarak
 * tenant kapsamı dışında çalışıyor (amaç zaten tüm işletmeleri görmek) ve bağlantı
 * rolü RLS'i atlıyor. Oradaki TEK koruma `requireAdmin()`. Denetimde 5/5 fonksiyonun
 * kapıdan geçtiği doğrulandı — ama kapısız bir fonksiyon eklemek tek satırlık bir
 * dalgınlık ve sonucu bütün kiracıların verisi.
 *
 * DELEGASYON YANLIŞ ALARMI: yaygın ve İYİ bir desen, `actions.ts`'in kapı kararını
 * vermeyip `data.ts`'e delege etmesidir (tek kapı, iki yerde gevşeyemez). Yalnız
 * action dosyasına bakan bir kural bunu "kapısız" sanır. Bu yüzden çağrılan yerel
 * modüller de kontrol edilir.
 */

const isJsTs = (f: string) =>
  /\.(ts|tsx|js|jsx|mjs)$/.test(f) && !/(\.test\.|\.spec\.|\.d\.ts$|__tests__|\/tests?\/)/.test(f);

const USE_SERVER = /^\s*["']use server["']\s*;?/m;

const DB_ACCESS =
  /(prisma\.|\bdb\.|drizzle|mongoose|sequelize|\bknex\b|\.from\(\s*["'`]?\w|\.query\s*\(|sql`|\.findMany\(|\.findUnique\(|\.insert\(|\.update\(|\.delete\(|\.upsert\(|\.collection\(|createClient\s*\()/i;

/** Kiracı kapsamının DIŞINA çıkıldığının işaretleri. */
const KAPSAM_DISI =
  /(service_role|BYPASSRLS|neondb_owner|SECURITY DEFINER|serviceRoleKey|SUPABASE_SERVICE)/i;

/**
 * KİMLİK ÖNCESİ AKIŞLAR — bu kuralın konusu DEĞİL.
 *
 * Giriş, kayıt, parola sıfırlama, e-posta doğrulama ve davet kabulü TANIM GEREĞİ
 * oturumsuz çalışır: kullanıcı henüz giremiyordur. Bunlara "yetki kapısı yok"
 * demek, doğru yazılmış kodu suçlamaktır.
 *
 * Gerçek vaka: stackcrm'in `forgot-password/actions.ts` dosyası bu kuralın ilk
 * taramasında 2 bulgu üretti. Kod aslında ÖRNEK niteliğindeydi — hesap yoksa bile
 * aynı yanıtı dönerek kullanıcı sayımı saldırısını engelliyor, eski jetonları
 * geçersiz kılıyordu. Böyle bir dosyayı işaretlemek aracın güvenini bitirir.
 *
 * Bu akışların KENDİ koruması vardır (tek kullanımlık jeton, hız freni) ve onları
 * ayrı kurallar denetler.
 */
const KIMLIK_ONCESI_YOL =
  /(^|\/)(sign-?in|sign-?up|log-?in|log-?out|register|kayit|giris|cikis|forgot-password|reset-password|new-password|verify(-email)?|dogrula|confirm|magic-link|invite|davet|accept|onboarding|password)(\/|-|\.|$)/i;
const KIMLIK_ONCESI_AD =
  /^(sign(In|Up|Out)|log(In|Out)|register|kayitOl|girisYap|request|reset|forgot|verify|confirm|accept|resend)\w*|(\w*(PasswordReset|ResetPassword|ForgotPassword|VerifyEmail|Invite|Signup|Signin|Login|Logout))\w*$/;

/** Tek kullanımlık jeton doğrulaması da bir kapıdır (oturum olmasa bile). */
const JETON_KAPISI =
  /(token[\s\S]{0,80}(hash|compare|timingSafeEqual|findUnique|findFirst)|used_at|expires_?at|expiresAt)/i;

/** Kiracı sarmalayıcısı — varsa sorgu kapsam içindedir. */
const TENANT_SARMAL = /\b(withTenant|forTenant|tenantScoped|scopedDb|withOrg|withWorkspace)\s*\(/;

/** Dosyadaki dışa açık async fonksiyonlar (server action adayları). */
function disaAcikFonksiyonlar(kod: string): { ad: string; index: number }[] {
  const out: { ad: string; index: number }[] = [];
  const re = /export\s+async\s+function\s+(\w+)|export\s+const\s+(\w+)\s*=\s*async\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(kod)) !== null) out.push({ ad: m[1] || m[2], index: m.index });
  return out;
}

/** Yorumları boşlukla değiştir (satır numarası korunur). */
function yorumsuz(kod: string): string {
  return kod
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .split(/\r?\n/)
    .map((l) => l.replace(/\/\/.*$/, ""))
    .join("\n");
}

export const serverActionAuthMissing: StaticRule = {
  id: "a01-server-action-auth-missing",
  title: "Server action writes to the database without an authorization gate",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const helpers = collectAuthHelpers(ctx);

    for (const file of ctx.files.filter(isJsTs)) {
      const raw = ctx.read(file);
      if (!raw) continue;
      const kod = yorumsuz(raw);
      if (!USE_SERVER.test(kod)) continue;          // yalnız server action dosyaları
      if (!DB_ACCESS.test(kod)) continue;           // veriye dokunmuyorsa risk yok
      if (KIMLIK_ONCESI_YOL.test(file)) continue;   // giriş/kayıt/parola sıfırlama

      // Dosyanın tamamı bir kapıdan geçiyorsa (modül seviyesinde ortak guard) sorun yok.
      const dosyaKapisi = callsAuthHelper(kod, helpers);

      for (const fn of disaAcikFonksiyonlar(kod)) {
        const govde = kod.slice(fn.index, fn.index + 1500);
        if (!DB_ACCESS.test(govde) && !/\w+\s*\(/.test(govde)) continue;
        if (callsAuthHelper(govde, helpers)) continue;   // kendi kapısı var
        if (KIMLIK_ONCESI_AD.test(fn.ad)) continue;     // kimlik öncesi akış
        if (JETON_KAPISI.test(govde)) continue;         // tek kullanımlık jeton doğrulaması

        // DELEGASYON: gövdedeki çağrılar yerel bir modülden geliyorsa, o modülde
        // kapı var mı? (actions.ts → data.ts deseni yanlış alarm üretmemeli.)
        const yerelImportlar = [...kod.matchAll(/from\s+["'](\.[^"']+|@\/[^"']+)["']/g)].map((m) => m[1]);
        let delegeKapi = false;
        for (const imp of yerelImportlar) {
          const taban = imp.split("/").pop() ?? "";
          if (!taban) continue;
          const hedef = ctx.files.find(
            (f) => isJsTs(f) && new RegExp(`(^|/)${taban}\\.(ts|tsx|js|jsx|mjs)$`).test(f)
          );
          if (!hedef) continue;
          const hedefKod = ctx.read(hedef);
          if (hedefKod && callsAuthHelper(yorumsuz(hedefKod), helpers)) { delegeKapi = true; break; }
        }
        if (delegeKapi || dosyaKapisi) continue;

        const kapsamDisi = KAPSAM_DISI.test(kod) || (!TENANT_SARMAL.test(kod) && KAPSAM_DISI.test(raw));
        const satir = kod.slice(0, fn.index).split("\n").length;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: kapsamDisi ? "high" : "medium",
          confidence: "likely",
          description:
            `${file}:${satir} — \`${fn.ad}\` bir server action ("use server") ve veritabanına ` +
            `dokunuyor, ama ne kendisinde ne delege ettiği modülde tanınabilir bir yetki ` +
            `kontrolü var. Server action'lar Next tarafından HTTP uç noktası olarak yayınlanır: ` +
            `dosyanın içinde duran sıradan bir fonksiyon gibi görünse de İNTERNETTEN DOĞRUDAN ` +
            `çağrılabilir.` +
            (kapsamDisi
              ? ` Üstelik bu modülde kiracı kapsamı dışına çıkma işareti var (RLS'i atlayan rol / ` +
                `service_role): kapısız tek bir fonksiyon oturum açan herkese BÜTÜN kiracıların ` +
                `verisini açar.`
              : ``),
          evidence: [fileEvidence(file, satir, `export async function ${fn.ad}`)],
          remediation:
            "Her dışa açık server action'ı bir kapıdan geçirin (oturum/rol doğrulaması). " +
            "Kapıyı TEK yerde tutun — action'lar kararı veri katmanına delege etsin, iki ayrı " +
            "kapı biri gevşediğinde yanlış güven verir. Kiracı kapsamı dışında çalışan modüllerde " +
            "kapıyı ayrıca yapısal bir testle kilitleyin: yeni eklenen fonksiyon unutulursa " +
            "sessizce bütün veriyi açar.",
        });
      }
    }
    return findings;
  },
};
