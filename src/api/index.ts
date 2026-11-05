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
  /\b(weon|weona|aweonao|aweona|huevon|huevona|culiao|culia|culi|qliao|qlo|conchetumadre|conchesumadre|conchatumadre|concha ?tu ?madre|concha ?de ?tu ?madre|ctm|csm|sacowea|chupalo|maricon|marica|chucha)\b/i,

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
 * Valida si el origen de la petición pertenece a la lista blanca autorizada.
 */
function isOriginAllowed(origin: string | null, env: Env): boolean {
  if (!origin) return false;

  const configured = env.ALLOWED_ORIGINS
    ? env.ALLOWED_ORIGINS.split(',').map((o) => o.trim().toLowerCase())
    : DEFAULT_ALLOWED_ORIGINS.map((o) => o.toLowerCase());

  const lowerOrigin = origin.toLowerCase();
  if (configured.includes(lowerOrigin)) return true;

  // Permitir subdominios de vista previa seguros de Cloudflare Pages y Workers
  if (/^https:\/\/[a-z0-9-]+\.(pages|workers)\.dev$/.test(lowerOrigin)) {
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

  if (origin && isOriginAllowed(origin, env)) {
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

/**
 * Comprobación de Rate Limiting por IP:
 * - Regla 1: Máximo 1 reseña cada 30 segundos
 * - Regla 2: Máximo 5 reseñas por hora
 */
async function evaluateIpRateLimit(
  db: D1Database,
  ipHash: string,
  nowMs: number
): Promise<{ allowed: boolean; retryAfter?: number; error?: string }> {
  // 1. Escudo ultrarrápido en memoria RAM del Worker isolate
  const lastSubmission = inMemoryRateLimit.get(ipHash);
  if (lastSubmission && nowMs - lastSubmission < 30_000) {
    const waitSec = Math.max(1, Math.ceil((30_000 - (nowMs - lastSubmission)) / 1000));
    return {
      allowed: false,
      retryAfter: waitSec,
      error: `Has publicado recientemente. Por favor espera ${waitSec} segundos antes de enviar otra reseña.`,
    };
  }

  // 2. Comprobación persistente en base de datos D1 (Regla: 1 cada 30s)
  try {
    const recent30s = await db
      .prepare(
        "SELECT COUNT(*) as count FROM rate_limits WHERE ip_hash = ? AND created_at >= datetime('now', '-30 seconds')"
      )
      .bind(ipHash)
      .first<{ count: number }>();

    if ((recent30s?.count ?? 0) > 0) {
      return {
        allowed: false,
        retryAfter: 30,
        error: 'Has publicado una reseña recientemente. Por favor espera 30 segundos antes de publicar otra.',
      };
    }

    // 3. Comprobación persistente en base de datos D1 (Regla: máx 5 por hora)
    const hourly = await db
      .prepare(
        "SELECT COUNT(*) as count FROM rate_limits WHERE ip_hash = ? AND created_at >= datetime('now', '-1 hour')"
      )
      .bind(ipHash)
      .first<{ count: number }>();

    if ((hourly?.count ?? 0) >= 5) {
      return {
        allowed: false,
        retryAfter: 3600,
        error: 'Has alcanzado el límite máximo de 5 reseñas por hora para esta red. Por favor intenta más tarde.',
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
      if (origin && !isOriginAllowed(origin, env)) {
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
          let query = 'SELECT id, book_slug, book_index, name, rating, comment, created_at FROM reviews WHERE is_visible = 1';
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

        // E. EVALUACIÓN DE RATE LIMITING POR IP (30s y 5 req/h)
        const clientIp = getClientIp(request);
        const salt = env.IP_HASH_SALT || DEFAULT_SALT;
        const ipHash = await generateAnonymousIpHash(clientIp, salt);
        const nowMs = Date.now();

        const rateLimitCheck = await evaluateIpRateLimit(env.DB, ipHash, nowMs);
        if (!rateLimitCheck.allowed) {
          return Response.json(
            { error: rateLimitCheck.error },
            {
              status: 429,
              headers: {
                ...corsHeaders,
                'Retry-After': String(rateLimitCheck.retryAfter || 30),
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
        const userAgent = (request.headers.get('user-agent') || 'Unknown').slice(0, 200);

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
              ipHash,
              userAgent
            )
            .run();

          // Registrar evento en rate_limits y caché local de ráfagas
          inMemoryRateLimit.set(ipHash, nowMs);
          await env.DB.prepare(
            'INSERT INTO rate_limits (ip_hash, action) VALUES (?, ?)'
          )
            .bind(ipHash, 'create_review')
            .run();

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
