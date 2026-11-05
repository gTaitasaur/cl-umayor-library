import { defineCollection, z } from 'astro:content';

/**
 * Esquema de la colección 'libros' del Club de Lectura.
 *
 * Compatible tanto con `coverImage` como con `cover` para enlazar la portada original
 * o ilustración central en `public/covers/` (insertada dinámicamente en la ventana
 * editorial vertical 4:5 de 352 × 440 px), y con `spineImage` opcional para lomos personalizados.
 */
const libros = defineCollection({
  type: 'content',
  schema: z
    .object({
      title: z.string(),
      author: z.string(),
      year: z.number().int(),
      month: z.number().int().min(1).max(12),
      monthName: z.string(),
      monthShort: z.string().optional(),
      genre: z.string().default('Narrativa'),
      pages: z.number().int().default(200),
      rating: z.string().optional(),
      coverImage: z.string().optional(),
      cover: z.string().optional(),
      coverFit: z.enum(['contain', 'cover']).default('contain'),
      coverFrameBg: z.string().default('#141414'),
      coverMode: z.enum(['editorial', 'full']).default('editorial'),
      spineImage: z.string().optional(),
      spineColor: z.string().default('#242C35'),
      spineTextColor: z.string().default('#F4F2ED'),
      accentColor: z.string().optional(),
      thickness: z.number().min(28).max(96).optional(),
      synopsis: z.string(),
      publisher: z.string().optional(),
      publishedYear: z.number().int().optional(),
      country: z.string().optional(),
    })
    .refine((data) => Boolean(data.coverImage || data.cover), {
      message: 'Debes definir `coverImage` o `cover` con la ruta en `public/covers/`.',
      path: ['coverImage'],
    }),
});

export const collections = {
  libros,
};
