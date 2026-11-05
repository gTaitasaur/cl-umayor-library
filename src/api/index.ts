/**
 * ============================================================================
 * Club de Lectura · Archivo Editorial 3D
 * API Backend: Cloudflare Workers + Cloudflare D1 (SQLite Serverless)
 *
 * Módulo de Seguridad AppSec sin Fricción Visual:
 *  1. Anti-Bot y Anti-Spam Invisible: Trampa Honeypot en segundo plano
 *  2. Rate Limiting por IP: 1 req / 30s y máx 5 req / 1h (Memoria + D1)
 *  3. Moderación Editorial: Filtro de profanidad, insultos y contenido sexual
 *  4. Filtro Heurístico contra Enlaces Maliciosos y Phishing
 *  5. Sanitización Estricta contra XSS Stored (Codificación de entidades HTML)
 *  6. Política Restrictiva de CORS y Cabeceras de Seguridad HTTP
 *  7. Blindaje D1: Sentencias 100% parametrizadas (.prepare().bind())
 * ============================================================================
 */

// Tipos e interfaces para Cloudflare Workers, D1 y contexto de ejecución
export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[]; success: boolean }>;
  run(): Promise<{ success: boolean; meta?: unknown }>;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

export interface Fetcher {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

export interface Env {
  DB: D1Database;
  ASSETS?: Fetcher;
  ALLOWED_ORIGINS?: string;
  IP_HASH_SALT?: string;
}

// ============================================================================
// CONSTANTES Y CONFIGURACIÓN DE SEGURIDAD
// ============================================================================

const MAX_PAYLOAD_BYTES = 10 * 1024; // 10 KB límite estricto de payload
const DEFAULT_SALT = 'cl-umayor-reader-sec-salt-2025';

// Orígenes predeterminados autorizados para CORS
const DEFAULT_ALLOWED_ORIGINS = [
  'https://cl-umayor-library.gtaitasaur.workers.dev',
  'http://localhost:4321',
  'http://localhost:8787',
  'http://127.0.0.1:4321',
  'http://127.0.0.1:8787',
];

// Cabeceras de seguridad AppSec (Hardening global)
const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Cache-Control': 'no-store, no-cache, must-revalidate',
};

// Caché en memoria del Worker (primer escudo de ráfagas antes de consultar D1)
const inMemoryRateLimit = new Map<string, number>();

// ============================================================================
// MODERACIÓN EDITORIAL: LISTA NEGRA DE INSULTOS, GROSERÍAS Y CONTENIDO SEXUAL
// ============================================================================

const PROFANITY_PATTERNS: RegExp[] = [
  // 1. Modismos y groserías chilenas y regionales de alta agresividad
  /\b(weon|weona|aweonao|aweona|huevon|huevona|culiao|culia|culi|qliao|qlo|conchetumadre|conchesumadre|conchatumadre|concha ?tu ?madre|concha ?de ?tu ?madre|ctm|csm|sacowea|chupalo|maricon|marica|chucha|poto|tula|raja)\b/i,

  // 2. Insultos y descalificaciones directas
  /\b(mierda|puta|puto|puterio|hijo ?de ?puta|hdp|malparido|malparida|cabron|cabrona)\b/i,

  // 3. Vocabulario anatómico/sexual explícito, pornografía y comercio sexual
  /\b(porno|pornografia|xxx|onlyfans|sexo|pene|vagina|tetas|verga|pija|follar|cojer|orgasmo|masturbar|masturbacion|prostituta|escort|scort|pedofilia|zoofilia)\b/i,

  // 4. Expresiones de acoso y hostilidad directa
  /\b(matate|suicidate|muerete)\b/i,
];

/**
 * Normaliza el texto para detectar intentos de evasión (leetspeak, tildes, separación por puntos).
 * Mantiene intactas palabras legítimas como 'computadora', 'reputación', 'disputar'.
 */
function normalizeForModeration(text: string): string {
  if (!text) return '';
  let norm = text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // Quita tildes / diacríticos
    .replace(/[@4]/g, 'a')
    .replace(/[3]/g, 'e')
    .replace(/[1!|]/g, 'i')
    .replace(/[0]/g, 'o')
    .replace(/[$5]/g, 's')
    .replace(/(.)\1{2,}/g, '$1$1'); // Reduce repeticiones excesivas ("puuuuta" -> "puuta")

  // Unir letras individuales deliberadamente separadas por puntos o espacios (ej. "p.u.t.a")
  norm = norm.replace(/\b([a-z])[\s._\-]+([a-z])[\s._\-]+([a-z])[\s._\-]+([a-z])\b/g, '$1$2$3$4');
  norm = norm.replace(/\b([a-z])[\s._\-]+([a-z])[\s._\-]+([a-z])[\s._\-]+([a-z])[\s._\-]+([a-z])\b/g, '$1$2$3$4$5');

  // Normalizar separadores a espacios simples
  return norm.replace(/[\s._\-*/\\+,;:]+/g, ' ');
}

/**
 * Evalúa si el texto contiene vocabulario soez, insultos o contenido sexual no permitido.
 */
function containsProfanityOrInappropriateContent(text: string): boolean {
  if (!text) return false;
  const normalized = normalizeForModeration(text);
  return PROFANITY_PATTERNS.some((regex) => regex.test(normalized));
}

// ============================================================================
// FUNCIONES AUXILIARES DE CIBERSEGURIDAD
// ============================================================================

/**
 * Valida si el origen de la petición pertenece a la lista blanca autorizada o es Same-Origin.
 */
function isOriginAllowed(origin: string | null, env: Env, requestUrl?: string): boolean {
  if (!origin) return false;

  const lowerOrigin = origin.toLowerCase().trim().replace(/\/+$/, '');

  // 1. Same-Origin automático: Si el navegador navega en el mismo origen del Worker
  if (requestUrl) {
    try {
      const currentHostOrigin = new URL(requestUrl).origin.toLowerCase().replace(/\/+$/, '');
      if (lowerOrigin === currentHostOrigin) {
        return true;
      }
    } catch {}
  }

  // 2. Orígenes configurados en variables de entorno o predeterminados
  const configured = env.ALLOWED_ORIGINS
    ? env.ALLOWED_ORIGINS.split(',').map((o) => o.trim().toLowerCase().replace(/\/+$/, ''))
    : DEFAULT_ALLOWED_ORIGINS.map((o) => o.toLowerCase().replace(/\/+$/, ''));

  if (configured.includes(lowerOrigin)) return true;

  // 3. Permitir cualquier subdominio de Cloudflare Workers o Pages (*.workers.dev y *.pages.dev)
  // Soporta subdominios anidados como: cl-umayor-library.gtaitasaur.workers.dev
  if (/^https:\/\/([a-z0-9-]+\.)*(pages|workers)\.dev$/.test(lowerOrigin)) {
    return true;
  }

  return false;
}

/**
 * Genera el conjunto de cabeceras CORS dinámicas y cabeceras de seguridad HTTP.
 */
function getSecurityAndCorsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get('Origin');
  const headers: Record<string, string> = {
    ...SECURITY_HEADERS,
    Vary: 'Origin',
  };

  if (origin && isOriginAllowed(origin, env, request.url)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With';
    headers['Access-Control-Max-Age'] = '86400';
  }

  return headers;
}

/**
 * Obtiene la dirección IP real del cliente a través de las cabeceras de Cloudflare Edge.
 */
function getClientIp(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('x-real-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    '127.0.0.1'
  );
}

/**
 * Genera un hash SHA-256 anónimo con salt para trazabilidad sin almacenar la IP en texto claro.
 * Cumple estrictamente con normativas de privacidad (GDPR / Ley 19.628 de Protección de Datos Personales).
 */
async function generateAnonymousIpHash(ip: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${salt}:${ip}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

/**
 * Filtro Heurístico contra enlaces maliciosos, URLs promocionales y patrones de spam.
 */
function containsMaliciousOrSpamContent(text: string): boolean {
  if (!text) return false;

  // 1. Detección de esquemas de URL, hipervínculos y protocolos
  const urlRegex = /(https?:\/\/|ftp:\/\/|www\.)[^\s/$.?#].[^\s]*/i;
  if (urlRegex.test(text)) return true;

  // 2. Enlaces directos a canales de mensajería externa (Telegram, WhatsApp, Discord)
  const messagingRegex = /(t\.me|telegram\.me|wa\.me|chat\.whatsapp\.com|discord\.(gg|com\/invite))\//i;
  if (messagingRegex.test(text)) return true;

  // 3. TLDs frecuentemente abusados en campañas de spam masivo
  const spamTldsRegex = /\b[a-z0-9-]+(\.xyz|\.top|\.click|\.link|\.download|\.work|\.casino|\.bet|\.ru|\.cn|\.buzz|\.site|\.shop|\.club)\b/i;
  if (spamTldsRegex.test(text)) return true;

  // 4. Palabras clave de spam comercial, casinos, criptomonedas y estafas
  const commercialSpamRegex = /\b(casino|apuestas|slots|tragamonedas|crypto|bitcoin|ethereum|forex|viagra|cialis|inversiones seguras|ganar dinero rápido|préstamos inmediatos|prestamos rapidos|trabajo desde casa)\b/i;
  if (commercialSpamRegex.test(text)) return true;

  // 5. Captación mediante números telefónicos o instrucciones de contacto
  const contactSpamRegex = /\b(whatsapp|telegram|contactar al|escribe al|escribeme al|info al)\s*[:\-]?\s*\+?\d[\d\s-]{7,}\b/i;
  if (contactSpamRegex.test(text)) return true;

  return false;
}

/**
 * Codifica entidades HTML y elimina caracteres de control nulos para neutralizar Stored XSS.
 */
function sanitizeHtmlEntities(str: string): string {
  return str
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, '') // Elimina caracteres no imprimibles y nulos
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .replace(/`/g, '&#96;')
    .trim();
}

interface RateLimitResult {
  allowed: boolean;
  retryAfter?: number;
  error?: string;
}

/**
 * Comprobación de Rate Limiting Adaptativo de Dos Niveles:
 * 1. Nivel Dispositivo (Device Token + User Agent):
 *    - Cooldown anti-ráfaga: 1 reseña cada 15 segundos por dispositivo.
 *    - Límite horario personal: máx. 15 reseñas por hora por dispositivo.
 * 2. Nivel Red / Campus (IP Pública):
 *    - Límite horario global: máx. 60 reseñas por hora por IP.
 *    Permite que decenas de estudiantes en una misma red Wi-Fi o biblioteca
 *    comenten simultáneamente sin bloquear a sus compañeros.
 */
async function evaluateRateLimits(
  db: D1Database,
  deviceHash: string,
  networkHash: string,
  nowMs: number
): Promise<RateLimitResult> {
  const devKey = `dev_${deviceHash}`;
  const netKey = `net_${networkHash}`;

  // 1. Escudo ultrarrápido en memoria RAM del Worker isolate (cooldown de 15 segundos)
  const lastSubmission = inMemoryRateLimit.get(devKey);
  if (lastSubmission && nowMs - lastSubmission < 15_000) {
    const waitSec = Math.max(1, Math.ceil((15_000 - (nowMs - lastSubmission)) / 1000));
    return {
      allowed: false,
      retryAfter: waitSec,
      error: `Has publicado recientemente. Por favor espera ${waitSec} segundos antes de enviar otra reseña.`,
    };
  }

  try {
    // 2. Cooldown persistente en D1 por dispositivo (15 segundos)
    const recentDev = await db
      .prepare(
        "SELECT COUNT(*) as count FROM rate_limits WHERE ip_hash = ? AND created_at >= datetime('now', '-15 seconds')"
      )
      .bind(devKey)
      .first<{ count: number }>();

    if ((recentDev?.count ?? 0) > 0) {
      return {
        allowed: false,
        retryAfter: 15,
        error: 'Has publicado recientemente. Por favor espera 15 segundos antes de publicar otra reseña.',
      };
    }

    // 3. Límite horario por dispositivo (máx. 15 reseñas por hora por persona/dispositivo)
    const hourlyDev = await db
      .prepare(
        "SELECT COUNT(*) as count FROM rate_limits WHERE ip_hash = ? AND created_at >= datetime('now', '-1 hour')"
      )
      .bind(devKey)
      .first<{ count: number }>();

    if ((hourlyDev?.count ?? 0) >= 15) {
      return {
        allowed: false,
        retryAfter: 3600,
        error: 'Has alcanzado el límite de 15 reseñas por hora para este dispositivo. ¡Gracias por tu participación!',
      };
    }

    // 4. Límite de seguridad para la red pública compartida / campus Wi-Fi (máx. 60 por hora)
    const hourlyNet = await db
      .prepare(
        "SELECT COUNT(*) as count FROM rate_limits WHERE ip_hash = ? AND created_at >= datetime('now', '-1 hour')"
      )
      .bind(netKey)
      .first<{ count: number }>();

    if ((hourlyNet?.count ?? 0) >= 60) {
      return {
        allowed: false,
        retryAfter: 1800,
        error: 'Se ha alcanzado temporalmente el límite de seguridad para esta red institucional. Por favor intenta más tarde.',
      };
    }
  } catch (e) {
    console.warn('[RateLimit] Advertencia al consultar tabla rate_limits en D1:', e);
  }

  return { allowed: true };
}

// ============================================================================
// CONTROLADOR PRINCIPAL DEL WORKER (FETCH HANDLER)
// ============================================================================

export default {
  async fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Endpoint de API protegido para reseñas del Club de Lectura
    if (url.pathname === '/api/reviews') {
      const corsHeaders = getSecurityAndCorsHeaders(request, env);
      const origin = request.headers.get('Origin');

      // Rechazar orígenes cruzados no autorizados en solicitudes con cabecera Origin
      if (origin && !isOriginAllowed(origin, env, request.url)) {
        return Response.json(
          { error: 'Origen no autorizado por la política de seguridad CORS.' },
          { status: 403, headers: { ...SECURITY_HEADERS, 'Content-Type': 'application/json' } }
        );
      }

      // 1. Manejo de Preflight OPTIONS
      if (request.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
      }

      // 2. Restricción estricta de métodos HTTP permitidos
      if (request.method !== 'GET' && request.method !== 'POST') {
        return Response.json(
          { error: `Método ${request.method} no permitido.` },
          {
            status: 405,
            headers: {
              ...corsHeaders,
              Allow: 'GET, POST, OPTIONS',
              'Content-Type': 'application/json',
            },
          }
        );
      }

      // ----------------------------------------------------------------------
      // GET /api/reviews: Consulta de reseñas aprobadas y promedios
      // ----------------------------------------------------------------------
      if (request.method === 'GET') {
        const bookParam = url.searchParams.get('book');
        const slugParam = url.searchParams.get('slug');

        if (!env.DB) {
          return Response.json(
            { reviews: [], averageRating: null, totalReviews: 0 },
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        try {
          // Filtrado estricto por is_visible = 1 para no exponer comentarios en moderación o spam
          let query = 'SELECT id, book_slug, book_index, name, email, rating, comment, created_at FROM reviews WHERE is_visible = 1';
          const params: (string | number)[] = [];

          if (slugParam) {
            query += ' AND book_slug = ? ORDER BY created_at DESC';
            params.push(slugParam.trim());
          } else if (bookParam !== null) {
            query += ' AND book_index = ? ORDER BY created_at DESC';
            params.push(Number(bookParam));
          } else {
            query += ' ORDER BY created_at DESC LIMIT 100';
          }

          const { results } = await env.DB.prepare(query).bind(...params).all();
          const reviews = (results || []).map((r: any) => ({
            id: r.id,
            bookSlug: r.book_slug,
            bookIndex: r.book_index,
            name: r.name,
            email: r.email || null,
            rating: Number(r.rating),
            comment: r.comment || '',
            createdAt: r.created_at,
          }));

          const totalReviews = reviews.length;
          const averageRating =
            totalReviews > 0
              ? Number(
                  (
                    reviews.reduce(
                      (acc: number, curr: { rating: number }) => acc + curr.rating,
                      0
                    ) / totalReviews
                  ).toFixed(1)
                )
              : null;

          return Response.json(
            { reviews, averageRating, totalReviews },
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        } catch (err: any) {
          return Response.json(
            { error: 'Error interno al consultar las opiniones del club.' },
            { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
      }

      // ----------------------------------------------------------------------
      // POST /api/reviews: Registro seguro de nuevas valoraciones
      // ----------------------------------------------------------------------
      if (request.method === 'POST') {
        if (!env.DB) {
          return Response.json(
            { error: 'Base de datos D1 no disponible.' },
            { status: 503, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // A. Validación de Content-Type
        const contentType = request.headers.get('content-type') || '';
        if (!contentType.toLowerCase().includes('application/json')) {
          return Response.json(
            { error: 'Cabecera Content-Type inválida. Debe ser application/json.' },
            { status: 415, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // B. Validación del tamaño de la petición (Límite 10 KB)
        const contentLength = Number(request.headers.get('content-length') || 0);
        if (contentLength > MAX_PAYLOAD_BYTES) {
          return Response.json(
            { error: 'El tamaño de la petición excede el límite permitido de 10 KB.' },
            { status: 413, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // C. Lectura y deserialización del cuerpo JSON
        let body: any;
        try {
          const rawText = await request.text();
          if (rawText.length > MAX_PAYLOAD_BYTES) {
            return Response.json(
              { error: 'El cuerpo de la petición supera los 10 KB permitidos.' },
              { status: 413, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
          }
          body = JSON.parse(rawText);
        } catch {
          return Response.json(
            { error: 'Formato JSON malformado o payload inválido.' },
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // D. TRAMPA HONEYPOT ANTI-BOT (100% invisible para humanos)
        const honeypot = body.hp_security_check ?? body.hp_security_code ?? body.website ?? body.hp_website;
        if (honeypot && typeof honeypot === 'string' && honeypot.trim().length > 0) {
          return Response.json(
            { error: 'Solicitud rechazada por filtros de seguridad.' },
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // E. EVALUACIÓN DE RATE LIMITING ADAPTATIVO (Dispositivo vs Red Universitaria)
        const clientIp = getClientIp(request);
        const userAgent = (request.headers.get('user-agent') || 'Unknown').slice(0, 200);
        const salt = env.IP_HASH_SALT || DEFAULT_SALT;
        const networkHash = await generateAnonymousIpHash(clientIp, salt);

        // Identificador de dispositivo para diferenciar múltiples alumnos en el mismo Wi-Fi
        const rawDeviceToken = typeof body?.device_token === 'string' ? body.device_token.trim() : '';
        const sanitizedDeviceToken = rawDeviceToken.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
        const deviceSeed = sanitizedDeviceToken || clientIp;
        const deviceHash = await generateAnonymousIpHash(`${deviceSeed}:${userAgent}`, salt);

        const nowMs = Date.now();
        const rateLimitCheck = await evaluateRateLimits(env.DB, deviceHash, networkHash, nowMs);
        if (!rateLimitCheck.allowed) {
          return Response.json(
            { error: rateLimitCheck.error },
            {
              status: 429,
              headers: {
                ...corsHeaders,
                'Retry-After': String(rateLimitCheck.retryAfter || 15),
                'Content-Type': 'application/json',
              },
            }
          );
        }

        // F. VALIDACIÓN ESTRICTA DE TIPOS Y LONGITUDES MÁXIMAS
        const { bookSlug, bookIndex, name, email, rating, comment } = body || {};

        // 1. Nombre: Obligatorio, entre 2 y 70 caracteres
        if (!name || typeof name !== 'string') {
          return Response.json(
            { error: 'El nombre es obligatorio.' },
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
        const trimmedName = name.trim();
        if (trimmedName.length < 2 || trimmedName.length > 70) {
          return Response.json(
            { error: 'El nombre debe tener entre 2 y 70 caracteres.' },
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // 2. Calificación: Entero estricto entre 1 y 5
        const parsedRating = Number(rating);
        if (!Number.isInteger(parsedRating) || parsedRating < 1 || parsedRating > 5) {
          return Response.json(
            { error: 'La calificación debe ser un número entero entre 1 y 5 estrellas.' },
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // 3. Comentario: Opcional, máximo 600 caracteres
        const trimmedComment = typeof comment === 'string' ? comment.trim() : '';
        if (trimmedComment.length > 600) {
          return Response.json(
            { error: 'El comentario no puede exceder los 600 caracteres.' },
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // 4. Correo: Opcional, máximo 100 caracteres con formato RFC seguro
        let cleanEmail: string | null = null;
        if (email && typeof email === 'string' && email.trim().length > 0) {
          const trimmedEmail = email.trim();
          if (trimmedEmail.length > 100) {
            return Response.json(
              { error: 'El correo electrónico no puede exceder los 100 caracteres.' },
              { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
          }
          const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
          if (!emailRegex.test(trimmedEmail)) {
            return Response.json(
              { error: 'El formato del correo electrónico es inválido.' },
              { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
          }
          cleanEmail = trimmedEmail;
        }

        // 5. Identificadores de libro
        const cleanSlug = typeof bookSlug === 'string' ? bookSlug.trim().slice(0, 80) : '';
        const cleanIndex = Number.isInteger(Number(bookIndex)) ? Math.max(0, Number(bookIndex)) : 0;

        // G. FILTRO CONTRA ENLACES MALICIOSOS Y PATRONES DE SPAM
        if (
          containsMaliciousOrSpamContent(trimmedName) ||
          containsMaliciousOrSpamContent(trimmedComment) ||
          (cleanEmail && containsMaliciousOrSpamContent(cleanEmail))
        ) {
          return Response.json(
            {
              error:
                'Por motivos de seguridad y convivencia del Club, no se permiten enlaces ni contenido promocional en las opiniones.',
            },
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // H. MODERACIÓN EDITORIAL: LISTA NEGRA DE INSULTOS Y VOCABULARIO SOEZ O SEXUAL
        if (
          containsProfanityOrInappropriateContent(trimmedName) ||
          containsProfanityOrInappropriateContent(trimmedComment) ||
          (cleanEmail && containsProfanityOrInappropriateContent(cleanEmail))
        ) {
          return Response.json(
            {
              error:
                'Tu comentario contiene vocabulario o expresiones no permitidas en el Club de Lectura. Por favor mantén un tono respetuoso.',
            },
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // I. SANITIZACIÓN Y CODIFICACIÓN DE ENTIDADES HTML CONTRA XSS STORED
        const cleanName = sanitizeHtmlEntities(trimmedName);
        const cleanComment = sanitizeHtmlEntities(trimmedComment);

        // J. INSERCIÓN EN D1 CON SENTENCIAS PREPARADAS (.prepare().bind())
        try {
          await env.DB.prepare(
            `INSERT INTO reviews (book_slug, book_index, name, email, rating, comment, ip_hash, user_agent, is_visible, is_flagged)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)`
          )
            .bind(
              cleanSlug,
              cleanIndex,
              cleanName,
              cleanEmail,
              parsedRating,
              cleanComment,
              networkHash,
              userAgent
            )
            .run();

          // Registrar evento en rate_limits (nivel dispositivo y nivel red universitaria)
          const devKey = `dev_${deviceHash}`;
          const netKey = `net_${networkHash}`;
          inMemoryRateLimit.set(devKey, nowMs);

          // Limpieza preventiva de caché en memoria si supera los 1000 elementos
          if (inMemoryRateLimit.size > 1000) {
            const cutoff = nowMs - 120_000;
            for (const [k, v] of inMemoryRateLimit.entries()) {
              if (v < cutoff) inMemoryRateLimit.delete(k);
            }
          }

          await Promise.all([
            env.DB.prepare('INSERT INTO rate_limits (ip_hash, action) VALUES (?, ?)').bind(devKey, 'create_review').run(),
            env.DB.prepare('INSERT INTO rate_limits (ip_hash, action) VALUES (?, ?)').bind(netKey, 'create_review').run(),
          ]);

          // Tarea en segundo plano: limpieza ocasional de rate_limits antiguos (> 2 horas)
          if (Math.random() < 0.08 && ctx) {
            ctx.waitUntil(
              env.DB.prepare("DELETE FROM rate_limits WHERE created_at < datetime('now', '-2 hours')").run()
            );
          }

          // Calcular promedio y total actualizado solo con reseñas visibles
          const { results: agg } = await env.DB.prepare(
            'SELECT COUNT(*) as total, AVG(rating) as avg FROM reviews WHERE is_visible = 1 AND book_index = ?'
          )
            .bind(cleanIndex)
            .all();

          const total = (agg?.[0] as any)?.total || 1;
          const avg = Number(((agg?.[0] as any)?.avg || parsedRating).toFixed(1));

          return Response.json(
            { success: true, averageRating: avg, totalReviews: total },
            { status: 201, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        } catch (dbErr: any) {
          console.error('[Database Error]', dbErr);
          return Response.json(
            { error: 'Error al registrar la opinión en la base de datos editorial.' },
            { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
      }
    }

    // Servir activos estáticos generados por Astro
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Página no encontrada', { status: 404 });
  },
};
