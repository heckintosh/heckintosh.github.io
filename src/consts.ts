export type Site = {
  TITLE: string
  DESCRIPTION: string
  EMAIL: string
  NUM_POSTS_ON_HOMEPAGE: number
  POSTS_PER_PAGE: number
  SITEURL: string
}

export type Link = {
  href: string
  label: string
}

export const SITE: Site = {
  TITLE: 'heckintosh.github.com',
  DESCRIPTION:
    'sec researcher.',
  EMAIL: 'heckintosh@protonmail.com',
  NUM_POSTS_ON_HOMEPAGE: 2,
  POSTS_PER_PAGE: 4,
  SITEURL: 'https://heckintosh.github.com',
}

export const NAV_LINKS: Link[] = [
  { href: '/', label: 'home' },
  { href: '/blog', label: 'blog' },
  { href: '/writeups', label: 'writeups' },
  // { href: '/authors', label: 'authors' },
  // { href: '/about', label: 'about' },
  // { href: '/tags', label: 'tags' },
]

export const SOCIAL_LINKS: Link[] = [
  { href: 'https://github.com/heckintosh', label: 'GitHub' },
  { href: 'https://x.com/heckintosh_', label: 'Twitter' },
  { href: 'heckintosh@protonmail.com', label: 'Email' },
  { href: '/rss.xml', label: 'RSS' },
]
