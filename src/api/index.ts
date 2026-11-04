// Declaraciones de tipos para Cloudflare Workers y D1 en entornos Astro estrictos
export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[]; success: boolean }>;
  run(): Promise<{ success: boolean }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

export interface Fetcher {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export interface Env {
  DB: D1Database;
  ASSETS?: Fetcher;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Endpoint de API para reseñas y calificaciones del Club
    if (url.pathname === '/api/reviews') {
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };

      if (request.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
      }

      // GET /api/reviews?book=0 o ?slug=2025-01
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
          let query = 'SELECT id, book_slug, book_index, name, rating, comment, created_at FROM reviews';
          const params: (string | number)[] = [];

          if (slugParam) {
            query += ' WHERE book_slug = ? ORDER BY created_at DESC';
            params.push(slugParam);
          } else if (bookParam !== null) {
            query += ' WHERE book_index = ? ORDER BY created_at DESC';
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
              ? Number((reviews.reduce((acc: number, curr: { rating: number }) => acc + curr.rating, 0) / totalReviews).toFixed(1))
              : null;

          return Response.json(
            { reviews, averageRating, totalReviews },
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        } catch (err: any) {
          return Response.json(
            { error: err.message },
            { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
      }

      // POST /api/reviews
      if (request.method === 'POST') {
        if (!env.DB) {
          return Response.json(
            { error: 'Base de datos D1 no configurada.' },
            { status: 503, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        try {
          const body = (await request.json()) as any;
          const { bookSlug, bookIndex, name, email, rating, comment } = body || {};

          if (!name || typeof name !== 'string' || !name.trim()) {
            return Response.json(
              { error: 'El nombre es obligatorio.' },
              { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
          }

          const parsedRating = Number(rating);
          if (!parsedRating || parsedRating < 1 || parsedRating > 5) {
            return Response.json(
              { error: 'La calificación debe ser entre 1 y 5 estrellas.' },
              { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
          }

          const cleanName = name.trim().slice(0, 100);
          const cleanEmail =
            email && typeof email === 'string' && email.trim() ? email.trim().slice(0, 150) : null;
          const cleanComment =
            comment && typeof comment === 'string' ? comment.trim().slice(0, 1000) : '';
          const cleanSlug = String(bookSlug || '');
          const cleanIndex = Number(bookIndex ?? 0);

          await env.DB.prepare(
            'INSERT INTO reviews (book_slug, book_index, name, email, rating, comment) VALUES (?, ?, ?, ?, ?, ?)'
          )
            .bind(cleanSlug, cleanIndex, cleanName, cleanEmail, parsedRating, cleanComment)
            .run();

          // Calcular nuevo promedio agregado para el libro
          const { results: agg } = await env.DB.prepare(
            'SELECT COUNT(*) as total, AVG(rating) as avg FROM reviews WHERE book_index = ?'
          )
            .bind(cleanIndex)
            .all();

          const total = (agg?.[0] as any)?.total || 1;
          const avg = Number(((agg?.[0] as any)?.avg || parsedRating).toFixed(1));

          return Response.json(
            { success: true, averageRating: avg, totalReviews: total },
            { status: 201, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        } catch (err: any) {
          return Response.json(
            { error: err.message },
            { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
      }
    }

    // Servir archivos estáticos generados por Astro
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Página no encontrada', { status: 404 });
  },
};
