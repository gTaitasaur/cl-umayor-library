import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

/**
 * Script de Sincronización y Purga de Reseñas Huérfanas en Cloudflare D1
 *
 * Lee la colección de libros activos en `src/content/libros/` y elimina de la
 * base de datos Cloudflare D1 cualquier reseña o dato asociado a libros
 * que hayan sido eliminados del sitio web.
 *
 * Uso:
 *   node scripts/purge-orphaned-reviews.mjs --remote   (Base de datos en producción)
 *   node scripts/purge-orphaned-reviews.mjs --local    (Base de datos local de desarrollo)
 */

const LIBROS_DIR = path.resolve(process.cwd(), 'src/content/libros');

if (!fs.existsSync(LIBROS_DIR)) {
  console.error(`[Error] Directorio no encontrado: ${LIBROS_DIR}`);
  process.exit(1);
}

const files = fs.readdirSync(LIBROS_DIR).filter((f) => f.endsWith('.md'));
const activeSlugs = files.map((f) => f.replace(/\.md$/, ''));

console.log(`[D1 Sync] Libros activos detectados en Astro (${activeSlugs.length}):`);
console.log(`  -> ${activeSlugs.join(', ')}\n`);

if (activeSlugs.length === 0) {
  console.warn('[D1 Sync] Advertencia: No se encontraron libros en src/content/libros/.');
  console.warn('Operación de purga abortada para evitar borrado accidental de toda la base de datos.');
  process.exit(1);
}

const isRemote = process.argv.includes('--remote');
const targetFlag = isRemote ? '--remote' : '--local';
const envLabel = isRemote ? 'PRODUCCIÓN (Cloudflare Remote)' : 'DESARROLLO (Local .wrangler)';

console.log(`[D1 Sync] Entorno seleccionado: ${envLabel}`);

// Construir consulta SQL parametrizada de limpieza
const formattedList = activeSlugs.map((slug) => `'${slug.replace(/'/g, "''")}'`).join(', ');
const sqlQuery = `DELETE FROM reviews WHERE book_slug NOT IN (${formattedList});`;

console.log(`[D1 Sync] Ejecutando purga de reseñas huérfanas en D1...`);
console.log(`  SQL: ${sqlQuery}\n`);

try {
  execSync(
    `npx wrangler d1 execute cl-umayor-library-db ${targetFlag} --command="${sqlQuery}"`,
    { stdio: 'inherit' }
  );
  console.log('\n✓ ¡Comentarios huérfanos eliminados con éxito en D1!');
} catch (error) {
  console.error('\n✕ Error al ejecutar la purga en D1:', error.message);
  process.exit(1);
}
