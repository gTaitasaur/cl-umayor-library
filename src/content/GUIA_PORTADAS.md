# Guía Oficial de Portadas (Sistema Editorial Automático)

La biblioteca 3D genera **automáticamente** la carátula editorial de cada libro (`648 × 900 px`) a partir de los metadatos de su archivo `.md` en `src/content/libros/`, manteniendo la estética institucional e insertando la imagen de `coverImage` en una ventana vertical central de proporción **4:5 (`352 × 440 px`)**.

---

## 1. Qué Genera el Sistema Automáticamente

Por cada archivo `.md` que exista o agregues en `src/content/libros/`:

- **Papel y Marco Editorial:** Base serigráfica crema (`#EDEBE6`) y doble filete estilo Criterion / Vasari (`#141414`).
- **Intercalado Automático Azul / Rojo:**
  - **Libros impares (1, 3, 5…):** `"SELECCIÓN DEL CLUB DE LECTURA"`, filete sobre el autor y cabezada superior/inferior en **Azul Cobalto (`#1F3FB0`)**.
  - **Libros pares (2, 4, 6…):** Mismos elementos en **Rojo Bermellón (`#B8332A`)**.
- **Tipografía Dinámica:**
  - `title` en mayúsculas (`Georgia` condensada) con salto de línea y escala automática en 1, 2, 3 o 4 renglones.
  - `author` en mayúsculas con espaciado editorial.
  - `${genre} · ${pages} págs.` en cursiva.
- **Pie Editorial y Sello:** Numeración automática `EDICIÓN N.º XX / TOTAL` e insignia `[MES · AÑO]`.
- **Sincronización Completa:** La misma portada editorial dinámica se proyecta en el libro 3D, en su reflejo sobre la balda y en el revelado con manchas de tinta de la ficha de lectura, mientras que `coverImage` alimenta también la miniatura superior `4:5` del lomo.

---

## 2. Dimensiones y Formato para `coverImage` (Ventana Vertical 4:5)

```
┌──────────────────────────────────┐
│   SELECCIÓN DEL CLUB DE LECTURA  │  ← Alterna Azul (#1F3FB0) / Rojo (#B8332A)
│         TÍTULO DEL LIBRO         │  ← Dinámico desde `title`
│         ────── ── ──────         │
│         NOMBRE DEL AUTOR         │  ← Dinámico desde `author`
│        Novela · 200 págs.        │  ← Dinámico desde `genre` y `pages`
│                                  │
│         ┌──────────────┐         │
│         │              │         │
│         │   PORTADA    │         │  ← Ventana central vertical 4:5
│         │   ORIGINAL   │         │    (352 × 440 px en lienzo 648 × 900)
│         │     4:5      │         │    centrada en x = 148, y = 338
│         │              │         │
│         └──────────────┘         │
│                                  │
│  EDICIÓN N.º 01 / 13 [ENE · 2025]│  ← Dinámico según orden, mes y año
└──────────────────────────────────┘
```

| Parámetro | Recomendación |
| :--- | :--- |
| **Proporción exacta de la ventana** | **4:5** (`0.80`, vertical) — área en lienzo: **`352 × 440 px`** |
| **Dimensiones ideales (1x)** | **`400 × 500 px`** o **`440 × 550 px`** |
| **Dimensiones ideales (2x Retina)** | **`704 × 880 px`** o **`800 × 1000 px`** |
| **Formato de archivo** | **`.webp`** (recomendado), `.jpg` / `.jpeg`, `.png` o `.svg` |
| **Peso ideal del archivo** | **40 KB – 180 KB** (sRGB) |

---

## 3. Cómo Cambiar o Agregar un Libro Manualmente

1. **Guarda la portada original** en `public/covers/`:
   ```text
   public/covers/cover-13.webp
   ```
2. **Enlázala en el archivo `.md`** correspondiente (ej. `src/content/libros/2026-10.md`):
   ```yaml
   ---
   title: "Cierra todas las puertas"
   author: "Riley Sager"
   year: 2026
   publishedYear: 2019
   month: 10
   monthName: "OCTUBRE"
   monthShort: "OCT"
   genre: "Novela breve"
   pages: 496
   coverImage: "/covers/cover-13.webp"
   spineColor: "#4A3525"
   spineTextColor: "#F4F2ED"
   synopsis: "..."
   ---
   ```

---

## 4. Propiedades Opcionales Avanzadas (por Libro)

```yaml
# Cambiar el color del passepartout de la ventana central (por defecto "#141414"):
coverFrameBg: "#EDEBE6"

# Hacer que portadas con otra proporción rellenen los 352 × 440 px completos ("contain" | "cover"):
coverFit: "cover"

# Mostrar la portada ocupando el 100 % del libro (648 × 900 px) sin marco editorial ("editorial" | "full"):
coverMode: "full"

# Forzar un color de acento específico en lugar del intercalado automático Azul/Rojo:
accentColor: "#1F3FB0"
```
