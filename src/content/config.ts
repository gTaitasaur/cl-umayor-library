import { defineCollection, z } from 'astro:content';

/**
 * Esquema de la colección 'libros' del Club de Lectura.
 *
 * Compatible tanto con `coverImage` como con `cover` para enlazar carátulas
 * alojadas manualmente en `public/covers/`, y con `spineImage` opcional para lomos.
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
      spineImage: z.string().optional(),
      spineColor: z.string().default('#242C35'),
      spineTextColor: z.string().default('#F4F2ED'),
      accentColor: z.string().default('#1B3FA8'),
      thickness: z.number().min(28).max(96).optional(),
      synopsis: z.string(),
      creditLine: z.string().optional(),
      curatorNote: z.string().optional(),
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
