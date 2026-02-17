# ERC-8128 Landing Page

Landing page for [ERC-8128: Signed HTTP Requests with Ethereum](https://erc8128.org).

Built with [Astro](https://astro.build/), deployed on [Cloudflare Workers](https://workers.cloudflare.com/) with static assets.

## Development

```bash
# Install dependencies
bun install

# Build static site + start local worker (http://localhost:8787)
bun run dev

# Preview (assumes dist/ already exists)
bun run preview
```

## Deployment

```bash
# Build static site
bun run build

# Deploy worker + static assets
wrangler deploy
```

Custom domain is configured in the Cloudflare dashboard under Workers > erc8128-site > Settings > Domains & Routes.

## Project Structure

```
site/
├── public/           # Static assets (favicon)
├── src/
│   ├── components/   # Astro components
│   ├── layouts/
│   │   └── Layout.astro
│   ├── pages/
│   │   └── index.astro
│   └── worker.ts     # Cloudflare Worker (handles /verify)
├── astro.config.mjs
├── package.json
└── wrangler.toml
```
