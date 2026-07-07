import type { Confidence, Finding, OwaspCategory } from "./finding.js";
import type { Severity } from "./severity.js";

/** Projenin registry.json'daki (targets.json) kaydı. */
export interface Project {
  name: string;
  /** Mutlak, genişletilmiş (tilde açılmış) yol. */
  path: string;
  url?: string;
  owned: boolean;
  stack: Stack;
}

export interface Stack {
  framework?: "next" | "vite" | "node" | "unknown";
  db?: "supabase" | "neon" | "postgres" | "prisma" | "unknown";
  auth?: "clerk" | "supabase" | "next-auth" | "custom" | "unknown";
}

export interface GrepMatch {
  file: string;
  line: number;
  column: number;
  text: string;
}

/**
 * Statik kural bağlamı — kod okuma yardımcıları.
 */
export interface StaticContext {
  project: Project;
  /** Proje kök dizini (mutlak). */
  root: string;
  /** Taranabilir kaynak dosya listesi (köke göre relatif). */
  files: string[];
  /** Relatif yol → içerik (yoksa null). */
  read(relPath: string): string | null;
  /**
   * Regex ile satır-bazlı arama.
   * @param regex her satıra uygulanır (global flag otomatik eklenir)
   * @param include yalnızca bu glob'lara uyan dosyalarda ara (opsiyonel)
   */
  grep(regex: RegExp, include?: (file: string) => boolean): GrepMatch[];
  /** Belirli bir dosya var mı. */
  exists(relPath: string): boolean;
  /**
   * Dosya git tarafından izleniyor mu (git ls-files).
   * Git deposu değilse ya da dosya izlenmiyorsa false döner.
   * Sır/`.env` kurallarının "gerçekten commit'lenmiş mi" ayrımı için kullanılır.
   */
  isTracked(relPath: string): boolean;
  /** Proje bir git çalışma ağacı mı (isTracked'in anlamlı olup olmadığını bilmek için). */
  isGitRepo: boolean;
}

/** Canlı prob sonucu (kanıt üretmek için). */
export interface ProbeResult {
  ok: boolean;
  url: string;
  method: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  bodySnippet: string;
  /** İnsan-okunur istek özeti (kanıt). */
  requestLine: string;
  /** İnsan-okunur yanıt özeti (kanıt). */
  responseLine: string;
  error?: string;
}

/**
 * Canlı kural bağlamı — yalnızca owned:true projeler için çalışır.
 * Tüm problar düşük yoğunluklu ve yıkıcı değildir.
 */
export interface LiveContext {
  project: Project;
  baseUrl: string;
  /**
   * Yıkıcı olmayan HTTP prob. GET/HEAD/POST destekler.
   * Yönlendirmeleri takip etmez (redirect zincirini kanıt için görmek isteriz).
   */
  probe(path: string, init?: RequestInit): Promise<ProbeResult>;
}

/** npm audit sarmalayıcısı için bağlam. */
export interface DepsContext {
  project: Project;
  root: string;
  exists(relPath: string): boolean;
}

export type RuleKind = "static" | "live" | "deps";

interface BaseRule {
  id: string;
  title: string;
  owasp: OwaspCategory;
  /** Baz severity — bulguya göre override edilebilir. */
  severity: Severity;
  kind: RuleKind;
  description?: string;
  /** İlgili CWE kimliği (ör. "CWE-311"). Geriye-uyumlu, opsiyonel ek alan. */
  cwe?: string;
  /**
   * Kuralın varsayılan güven seviyesi. Bir bulgu kendi `confidence` değerini
   * belirtmezse engine bunu (o da yoksa "olası") atar. Geriye-uyumlu, opsiyonel.
   */
  confidence?: Confidence;
}

export interface StaticRule extends BaseRule {
  kind: "static";
  run(ctx: StaticContext): Finding[] | Promise<Finding[]>;
}

export interface LiveRule extends BaseRule {
  kind: "live";
  run(ctx: LiveContext): Promise<Finding[]>;
}

export interface DepsRule extends BaseRule {
  kind: "deps";
  run(ctx: DepsContext): Promise<Finding[]>;
}

export type Rule = StaticRule | LiveRule | DepsRule;
