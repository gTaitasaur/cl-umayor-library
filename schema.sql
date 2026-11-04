-- Esquema Cloudflare D1 para opiniones y valoraciones del Club de Lectura
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  book_slug TEXT NOT NULL,
  book_index INTEGER NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
  comment TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reviews_book_slug ON reviews(book_slug);
CREATE INDEX IF NOT EXISTS idx_reviews_book_index ON reviews(book_index);
