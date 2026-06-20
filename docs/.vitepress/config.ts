import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'secretenv',
  description: 'Multi-backend secrets orchestration via an alias registry that lives in your own backend.',
  cleanUrls: true,
  lastUpdated: true,
  appearance: 'force-dark',

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '32x32', href: '/favicon-32.png' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '512x512', href: '/favicon-512.png' }],
    ['link', { rel: 'apple-touch-icon', sizes: '180x180', href: '/apple-touch-icon.png' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.googleapis.com' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' }],
    ['link', {
      rel: 'stylesheet',
      href: 'https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=Geist+Mono:wght@400;500;600&family=Instrument+Serif:ital@0;1&display=swap',
    }],
    ['meta', { property: 'og:title', content: 'secretenv: multi-backend secrets orchestration' }],
    ['meta', { property: 'og:description', content: 'One registry. Every repo. Every backend. Migrate without touching a single repo.' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:url', content: 'https://docs.secretenv.io' }],
    ['meta', { name: 'theme-color', content: '#05070d' }],
  ],

  // Subdir README.md files become directory indexes. Root docs/README.md is repo-only and excluded.
  rewrites: {
    'backends/README.md': 'backends/index.md',
    'comparisons/README.md': 'comparisons/index.md',
  },
  srcExclude: ['README.md', '**/node_modules/**'],

  markdown: {
    // Backend docs use `<placeholder>` patterns extensively in prose (URI grammar). Disable raw-HTML
    // pass-through so these don't get parsed as Vue components.
    html: false,
  },

  ignoreDeadLinks: [
    // Cross-links to repo-root files (work in GitHub repo browsing, not in the docs site).
    // VitePress normalises ./../../README, ../../README, and ../README: match all variants.
    /README(\.md)?(#|$)/,
    /(CONTRIBUTING|SECURITY|LICENSE|CLA)(\.md)?(#|$)/,
  ],

  themeConfig: {
    siteTitle: 'secretenv',
    logo: { src: '/mark.svg', width: 22, height: 22 },

    nav: [
      { text: 'Get Started', link: '/#quick-start' },
      {
        text: 'Concepts',
        items: [
          { text: 'Three-File Model', link: '/reference/three-file-model-deep' },
          { text: 'Registry', link: '/reference/registry' },
          { text: 'Profiles', link: '/reference/profiles' },
          { text: 'Fragment Vocabulary', link: '/reference/fragment-vocabulary' },
        ],
      },
      { text: 'Backends', link: '/backends/' },
      { text: 'CLI', link: '/reference/cli-reference-full' },
      {
        text: 'Operations',
        items: [
          { text: 'CI/CD Integration', link: '/guides/ci-cd' },
          { text: 'Security & Threat Model', link: '/security' },
          { text: 'Comparisons', link: '/comparisons/' },
        ],
      },
      { text: 'secretenv.io ↗', link: 'https://secretenv.io' },
    ],

    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Overview', link: '/' },
        ],
      },
      {
        text: 'Concepts',
        items: [
          { text: 'Three-File Model', link: '/reference/three-file-model-deep' },
          { text: 'Registry', link: '/reference/registry' },
          { text: 'Profiles', link: '/reference/profiles' },
          { text: 'Fragment Vocabulary', link: '/reference/fragment-vocabulary' },
        ],
      },
      {
        text: 'Backends',
        collapsed: false,
        items: [
          { text: 'Overview', link: '/backends/' },
          { text: 'Local file', link: '/backends/local' },
          { text: 'AWS SSM', link: '/backends/aws-ssm' },
          { text: 'AWS Secrets Manager', link: '/backends/aws-secrets' },
          { text: '1Password', link: '/backends/1password' },
          { text: 'HashiCorp Vault', link: '/backends/vault' },
          { text: 'GCP Secret Manager', link: '/backends/gcp' },
          { text: 'Azure Key Vault', link: '/backends/azure' },
          { text: 'macOS Keychain', link: '/backends/keychain' },
          { text: 'Doppler', link: '/backends/doppler' },
          { text: 'Infisical', link: '/backends/infisical' },
          { text: 'Keeper', link: '/backends/keeper' },
          { text: 'Cloudflare Workers KV', link: '/backends/cf-kv' },
          { text: 'OpenBao', link: '/backends/openbao' },
          { text: 'CyberArk Conjur', link: '/backends/conjur' },
          { text: 'Bitwarden Secrets Manager', link: '/backends/bitwarden-sm' },
          { text: 'Adding a Backend', link: '/reference/adding-a-backend' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'CLI Reference', link: '/reference/cli-reference-full' },
          { text: 'Configuration', link: '/reference/configuration' },
          { text: 'Registry Migrate', link: '/reference/migrate' },
        ],
      },
      {
        text: 'Comparisons',
        collapsed: true,
        items: [
          { text: 'Overview', link: '/comparisons/' },
          { text: 'vs. .env files', link: '/comparisons/vs-dotenv' },
          { text: 'vs. fnox', link: '/comparisons/vs-fnox' },
          { text: 'vs. direnv', link: '/comparisons/vs-direnv' },
          { text: 'vs. op run', link: '/comparisons/vs-op-run' },
          { text: 'vs. Pulumi ESC', link: '/comparisons/vs-pulumi-esc' },
          { text: 'vs. External Secrets Operator', link: '/comparisons/vs-external-secrets-operator' },
          { text: 'vs. sops', link: '/comparisons/vs-sops' },
          { text: 'vs. Vault & Conjur as identity', link: '/comparisons/vs-vault-and-conjur' },
        ],
      },
      {
        text: 'Operations',
        items: [
          { text: 'CI/CD Integration', link: '/guides/ci-cd' },
          { text: 'Security & Threat Model', link: '/security' },
          { text: 'Stability & Smoke History', link: '/stability' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/TechAlchemistX/secretenv' },
    ],

    search: {
      provider: 'local',
    },

    outline: { level: [2, 3] },

    editLink: {
      pattern: 'https://github.com/TechAlchemistX/secretenv/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    footer: {
      message: 'Released under <a href="https://github.com/TechAlchemistX/secretenv/blob/main/LICENSE">AGPLv3</a>.',
      copyright: '© 2026 TechAlchemistX',
    },
  },
})
