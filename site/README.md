# ERC-8128 Landing Page

Landing page for [ERC-8128: Signed HTTP Requests with Ethereum](https://erc8128.xyz).

Built with [Astro](https://astro.build/), deployed on [Cloudflare Pages](https://pages.cloudflare.com/).

## Development

```bash
# Install dependencies
bun install

# Start dev server (http://localhost:4321)
bun run dev

# Build for production
bun run build

# Preview production build
bun run preview
```

## Deployment (Cloudflare Pages)

### Option 1: Dashboard (recommended)

1. Go to [Cloudflare Pages](https://dash.cloudflare.com/?to=/:account/pages) → Create project
2. Connect the GitHub repo (`slice-so/slicekit`)
3. Configure build settings:
   - **Build command:** `cd packages/erc8128/site && bun install && bun run build`
   - **Build output directory:** `packages/erc8128/site/dist`
   - **Root directory:** `/` (monorepo root)
4. Add custom domain: `erc8128.xyz`

### Option 2: Wrangler CLI

```bash
# From this directory
npx wrangler pages deploy dist --project-name=erc8128-site
```

## Demo Endpoint

For the ERC-8128 demo, a runtime endpoint is available at:

- `/get`

By default, it returns only the raw `VerifyResult` payload from `@slicekit/erc8128`
to keep demo output short and terminal-friendly.

Use `GET /get?verbose=1` to include expanded debug payload:

- Signature verification result (`verified`, `verification`)
- `Signature-Input` and `Signature` request headers
- Request metadata used in ERC-8128 signing (`method`, `authority`, `path`, `query`)
- Full request headers map for debugging

Verification notes:

- Uses `@slicekit/erc8128` + `viem` `verifyMessage`
- Optional RPC override via `ERC8128_DEMO_RPC_URL`
- Optional fake verification mode for local demos via `ERC8128_DEMO_FAKE_VERIFY=true`

note: nonce usage is not verified

## Project Structure

```
site/
├── public/           # Static assets (favicon)
├── src/
│   ├── components/   # Astro components
│   │   ├── Nav.astro
│   │   ├── Hero.astro
│   │   ├── Features.astro
│   │   ├── HowItWorks.astro
│   │   ├── CodePreview.astro
│   │   ├── Resources.astro
│   │   ├── CTA.astro
│   │   └── Footer.astro
│   ├── layouts/
│   │   └── Layout.astro
│   ├── pages/
│   │   └── index.astro
│   └── styles/
│       └── global.css
├── astro.config.mjs
├── package.json
└── wrangler.toml
```

## Design

- **Background:** `#0A0A0B`
- **Surface:** `#111113`
- **Accent:** `#858AFF`
- **Text:** `#EDEDEF` / `#8A8A8E`
- **Fonts:** Inter (body) + JetBrains Mono (code/labels)
- **Max width:** 720px content column
- **Breakpoint:** 640px (mobile)
