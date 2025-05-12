import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";
import { rssSchema } from "@astrojs/rss";

const blog = defineCollection({
  loader: glob({ pattern: "**/[^_]*.{md,mdx}", base: "./src/data/blog" }), // Add mdx
  schema: ({image}) =>
    z.object({
    title: z.string(),
    pubDate: z.date(),
    description: z.string(),
    draft: z.boolean().optional().default(false),
    titleImage: image().optional(),
    toc: z.boolean().optional(), // extra property as seen in some markdown files
    author: z.string().optional(), // Change to array of strings
    tags: z.array(z.string()).optional(), // Add tags schema since it's used
    tableOfContents: z
        .array(
          z.object({
            depth: z.number(),
            slug: z.string(),
            text: z.string(),
            subheadings: z.lazy(() =>
              z.array(
                z.object({
                  depth: z.number(),
                  slug: z.string(),
                  text: z.string(),
                  subheadings: z.array(z.any()),
                }),
              ),
            ),
          }),
        )
        .optional(),
      tableOfContentsTitle: z.string().optional(),
      activeSlug: z.string().optional(),
  }),
});

const writeups = defineCollection({
  loader: glob({ pattern: "**/[^_]*.{md,mdx}", base: "./src/data/writeups" }),
  schema: ({image}) =>
    z.object({
    title: z.string(),
    pubDate: z.date(),
    description: z.string(),
    draft: z.boolean().optional().default(false),
    titleImage: image().optional(),
    toc: z.boolean().optional(), // extra property as seen in some markdown files
    author: z.string().optional(), // Change to array of strings
    tags: z.array(z.string()).optional(), // Add tags schema since it's used
    tableOfContents: z
        .array(
          z.object({
            depth: z.number(),
            slug: z.string(),
            text: z.string(),
            subheadings: z.lazy(() =>
              z.array(
                z.object({
                  depth: z.number(),
                  slug: z.string(),
                  text: z.string(),
                  subheadings: z.array(z.any()),
                }),
              ),
            ),
          }),
        )
        .optional(),
      tableOfContentsTitle: z.string().optional(),
      activeSlug: z.string().optional(),
  }),
});


export const collections = { blog, writeups };