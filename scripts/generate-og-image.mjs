import fs from 'node:fs';
import { execSync } from 'node:child_process';

const logoSvg = fs.readFileSync('public/logo.svg', 'utf8');

// Extraer el contenido interno del SVG (eliminando la etiqueta <svg> envolvente)
const innerContent = logoSvg
  .replace(/<\?xml[\s\S]*?\?>/g, '')
  .replace(/<svg[\s\S]*?>/i, '')
  .replace(/<\/svg>/i, '');

const ogSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <!-- Degradado radial de papel Munken -->
    <radialGradient id="paper-vignette" cx="50%" cy="45%" r="70%" fx="45%" fy="40%">
      <stop offset="0%" stop-color="#F7F3EA" />
      <stop offset="60%" stop-color="#F2EDE2" />
      <stop offset="100%" stop-color="#E2D9C5" />
    </radialGradient>

    <!-- Sombra suave para el emblema oficial -->
    <filter id="badge-shadow" x="-20%" y="-20%" width="150%" height="150%">
      <feDropShadow dx="0" dy="18" stdDeviation="24" flood-color="#18140E" flood-opacity="0.18" />
      <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#18140E" flood-opacity="0.08" />
    </filter>

    <!-- Clip circular del emblema original -->
    <clipPath id="emblem-clip">
      <circle cx="1024" cy="1024" r="980" />
    </clipPath>
  </defs>

  <!-- 1. Fondo de papel de algodón Munken -->
  <rect width="1200" height="630" fill="url(#paper-vignette)" />

  <!-- 2. Marco editorial tenue -->
  <rect x="28" y="28" width="1144" height="574" fill="none" stroke="rgba(54, 84, 95, 0.22)" stroke-width="1.5" />
  <rect x="36" y="36" width="1128" height="558" fill="none" stroke="rgba(54, 84, 95, 0.12)" stroke-width="1" stroke-dasharray="4 4" />

  <!-- 3. Marcas de corte de imprenta en las 4 esquinas -->
  <!-- Superior Izquierda -->
  <path d="M 18 36 L 36 36 L 36 18" fill="none" stroke="#0C747C" stroke-width="2" />
  <!-- Superior Derecha -->
  <path d="M 1182 36 L 1164 36 L 1164 18" fill="none" stroke="#0C747C" stroke-width="2" />
  <!-- Inferior Izquierda -->
  <path d="M 18 594 L 36 594 L 36 612" fill="none" stroke="#0C747C" stroke-width="2" />
  <!-- Inferior Derecha -->
  <path d="M 1182 594 L 1164 594 L 1164 612" fill="none" stroke="#0C747C" stroke-width="2" />

  <!-- 4. Emblema Oficial SIBUM en Alta Definición a la izquierda (Diámetro 420px) -->
  <g transform="translate(100, 105)" filter="url(#badge-shadow)">
    <g transform="scale(0.205078125)">
      ${innerContent}
    </g>
  </g>

  <!-- 5. Composición Tipográfica Editorial a la derecha (Centrada verticalmente) -->
  <g transform="translate(560, 145)">
    <!-- Kicker Institucional -->
    <text x="0" y="45" font-family="'DejaVu Sans Mono', 'IBM Plex Mono', monospace" font-size="15" font-weight="600" letter-spacing="4.5" fill="#0C747C">
      UNIVERSIDAD MAYOR · TEMUCO
    </text>

    <!-- Subkicker de Biblioteca -->
    <text x="0" y="75" font-family="'DejaVu Sans Mono', 'IBM Plex Mono', monospace" font-size="12" font-weight="500" letter-spacing="3" fill="#6A7C82">
      SISTEMA DE BIBLIOTECAS (SIBUM)
    </text>

    <!-- Regla Carmesí de acento institucional -->
    <rect x="0" y="95" width="84" height="3.5" fill="#B91C3B" rx="1.5" />

    <!-- Título Principal de Exhibición Editorial -->
    <text x="0" y="185" font-family="'DejaVu Serif', 'Georgia', serif" font-size="70" font-weight="400" letter-spacing="-1" fill="#181614">
      Club de Lectura
    </text>

    <!-- Texto descriptivo solicitado por el usuario -->
    <text x="0" y="245" font-family="'DejaVu Sans', 'Plus Jakarta Sans', sans-serif" font-size="21" font-weight="400" fill="#2E3B3E">
      Explora nuestra estantería 3D y descubre los libros
    </text>
    <text x="0" y="280" font-family="'DejaVu Sans', 'Plus Jakarta Sans', sans-serif" font-size="21" font-weight="400" fill="#2E3B3E">
      leídos en el Club de Lectura UM. Revisa fichas
    </text>
    <text x="0" y="315" font-family="'DejaVu Sans', 'Plus Jakarta Sans', sans-serif" font-size="21" font-weight="400" fill="#2E3B3E">
      técnicas, sinopsis y comentarios de cada obra.
    </text>
  </g>
</svg>`;

fs.writeFileSync('public/og-image.svg', ogSvg, 'utf8');
console.log('og-image.svg created successfully');

try {
  execSync('rsvg-convert -w 1200 -h 630 public/og-image.svg -o public/og-image.png');
  console.log('public/og-image.png generated successfully with rsvg-convert');
} catch (err) {
  console.error('Error generating og-image.png:', err);
}
