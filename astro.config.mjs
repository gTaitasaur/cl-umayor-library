import { defineConfig } from 'astro/config';

export default defineConfig({
  output: 'static',
  build: {
    assets: '_astro',
  },
  compressHTML: true,
  vite: {
    plugins: [
      {
        name: 'dev-api-reviews-mock',
        configureServer(server) {
          // Middleware para interceptar /api/reviews durante 'pnpm dev' (astro dev)
          // y evitar errores 404 en la consola local cuando no está corriendo wrangler
          server.middlewares.use((req, res, next) => {
            if (req.url && req.url.startsWith('/api/reviews')) {
              res.setHeader('Content-Type', 'application/json');
              res.setHeader('Access-Control-Allow-Origin', '*');
              res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
              res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

              if (req.method === 'OPTIONS') {
                res.statusCode = 204;
                res.end();
                return;
              }

              if (req.method === 'GET') {
                res.statusCode = 200;
                res.end(
                  JSON.stringify({
                    reviews: [],
                    averageRating: null,
                    totalReviews: 0,
                  })
                );
                return;
              }

              if (req.method === 'POST') {
                res.statusCode = 201;
                res.end(
                  JSON.stringify({
                    success: true,
                    averageRating: 5,
                    totalReviews: 1,
                  })
                );
                return;
              }
            }
            next();
          });
        },
      },
    ],
  },
});
