import { defineConfig } from "astro/config";
import { rehypeHeadingIds } from '@astrojs/markdown-remark'
import sitemap from "@astrojs/sitemap";
import netlify from "@astrojs/netlify";
import robotsTxt from "astro-robots-txt";
import UnoCSS from "@unocss/astro";
import icon from "astro-icon";
import solidJs from "@astrojs/solid-js";
import svelte from "@astrojs/svelte";
import mdx from '@astrojs/mdx';
import react from "@astrojs/react";

import rehypeKatex from 'rehype-katex'
import rehypeExternalLinks from 'rehype-external-links'

import remarkEmoji from 'remark-emoji'
import remarkMath from 'remark-math'
import remarkToc from 'remark-toc'
import sectionize from '@hbsnow/rehype-sectionize'



// https://astro.build/config
export default defineConfig({
  site: "https://heckintosh.github.io",
  integrations: [
    sitemap(),
    robotsTxt({
      sitemap: [
        "https://gianmarcocavallo.com/sitemap-index.xml",
        "https://gianmarcocavallo.com/sitemap-0.xml",
      ],
    }),
    solidJs({
      include: ['**/solid/*.tsx', '**/solid/*.jsx']
    }),
    UnoCSS({
      injectReset: true,
    }),
    icon(),
    svelte(),
    mdx(),
    react(),
  ],
  markdown: {
    syntaxHighlight: 'shiki',
    shikiConfig: {
      theme: 'kanagawa-lotus',
      wrap: true,
    },
  
    rehypePlugins: [
      [
        rehypeExternalLinks,
        {
          target: '_blank',
          rel: ['nofollow', 'noreferrer', 'noopener'],
        },
      ],
      rehypeHeadingIds,
      [
        rehypeKatex,
        {
          strict: false,
        },
      ],
      sectionize as any,
    ],
    remarkPlugins: [remarkToc, remarkMath, remarkEmoji],
  },
  output: "static",
  vite: {
    assetsInclude: "**/*.riv",
    resolve: {
      alias: {
        "@": "/src",
        "@components": "/src/components",
        "@layouts": "/src/layouts",
        "@lib": "/src/lib",
      },
    },
  },
});
