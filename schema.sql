-- =====================================================================
-- Esquema Cloudflare D1 (SQLite Serverless) para el Club de Lectura
-- Blindaje AppSec: Auditoría, Moderación y Rate Limiting Persistente
-- =====================================================================

-- 1. Tabla principal de reseñas y valoraciones de lectores
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  book_slug TEXT NOT NULL,
  book_index INTEGER NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
  comment TEXT,
  -- Campos de auditoría AppSec y Moderación (cumplimiento privacidad)
  ip_hash TEXT NOT NULL,
  user_agent TEXT,
  is_visible INTEGER NOT NULL DEFAULT 1,
  is_flagged INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices optimizados para consulta pública (filtrando siempre is_visible = 1)
CREATE INDEX IF NOT EXISTS idx_reviews_book_slug_visible ON reviews(book_slug, is_visible);
CREATE INDEX IF NOT EXISTS idx_reviews_book_index_visible ON reviews(book_index, is_visible);
CREATE INDEX IF NOT EXISTS idx_reviews_ip_hash ON reviews(ip_hash);
CREATE INDEX IF NOT EXISTS idx_reviews_created_at ON reviews(created_at);

-- 2. Tabla para Rate Limiting y Control de Abuso por IP (Persistencia Edge)
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'create_review',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índice compuesto para comprobación rápida de ventanas de 30s y 1h
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_time ON rate_limits(ip_hash, created_at);

-- =====================================================================
-- COMANDOS DE MIGRACIÓN PARA BASES DE DATOS D1 EXISTENTES:
-- Ejecutar en terminal: npx wrangler d1 execute cl-umayor-library-db --remote --command="<COMANDO>"
--
-- ALTER TABLE reviews ADD COLUMN ip_hash TEXT DEFAULT 'legacy';
-- ALTER TABLE reviews ADD COLUMN user_agent TEXT DEFAULT 'legacy';
-- ALTER TABLE reviews ADD COLUMN is_visible INTEGER NOT NULL DEFAULT 1;
-- ALTER TABLE reviews ADD COLUMN is_flagged INTEGER NOT NULL DEFAULT 0;
-- CREATE INDEX IF NOT EXISTS idx_reviews_book_slug_visible ON reviews(book_slug, is_visible);
-- CREATE INDEX IF NOT EXISTS idx_reviews_book_index_visible ON reviews(book_index, is_visible);
-- CREATE INDEX IF NOT EXISTS idx_reviews_ip_hash ON reviews(ip_hash);
-- =====================================================================
