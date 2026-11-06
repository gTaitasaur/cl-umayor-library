import { execSync } from 'node:child_process';

/**
 * Script de Reinicio y Purgado de Datos de Prueba en Cloudflare D1
 *
 * Limpia todas las reseñas de prueba, valoraciones, contadores de rate limiting
 * y reinicia los IDs autonuméricos a 1 para dejar la base de datos impecable
 * para el lanzamiento oficial.
 *
 * Uso:
 *   pnpm run db:reset          (Desarrollo local en .wrangler - Seguro por defecto)
 *   pnpm run db:reset:remote   (Producción en Cloudflare D1 - Solo deliberado)
 */

const isRemote = process.argv.includes('--remote');
const targetFlag = isRemote ? '--remote' : '--local';
const envLabel = isRemote ? 'PRODUCCIÓN (Cloudflare Remote)' : 'DESARROLLO (Local .wrangler)';

console.log('===========================================================');
console.log(`[D1 Reset] REINICIO DE BASE DE DATOS PARA LANZAMIENTO OFICIAL`);
console.log(`[D1 Reset] Entorno: ${envLabel}`);
console.log('===========================================================\n');

const sql = `
DELETE FROM reviews;
DELETE FROM rate_limits;
DELETE FROM sqlite_sequence WHERE name IN ('reviews', 'rate_limits');
`.trim().replace(/\n/g, ' ');

try {
  console.log('-> Vaciando tabla reviews...');
  console.log('-> Vaciando tabla rate_limits...');
  console.log('-> Reiniciando IDs autonuméricos a 1...\n');

  execSync(
    `npx wrangler d1 execute cl-umayor-library-db ${targetFlag} --command="${sql}"`,
    { stdio: 'inherit' }
  );

  console.log('\n✓ ¡Base de datos reiniciada con éxito!');
  console.log('✓ La base de datos está 100% limpia y lista para el lanzamiento oficial.\n');
} catch (error) {
  console.error('\n✕ Error al ejecutar el reinicio en D1:', error.message);
  process.exit(1);
}
