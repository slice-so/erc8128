# @slicekit/better-auth Dependency Resolution

## Status: Working ✅

`@slicekit/better-auth@1.5.1-beta.1-erc8128.0` is installed and resolvable. The
`erc8128` plugin imports successfully:

```js
import { erc8128 } from "@slicekit/better-auth/plugins/erc8128"
// ✅ Works — exports the erc8128() plugin factory
```

## Why `@better-auth/core` overrides still use upstream packages

The `@slicekit/better-auth` package was published from the better-auth monorepo
with `workspace:*` dependencies on internal packages:

- `@better-auth/core` — core infrastructure (context, env, error, utils, etc.)
- `@better-auth/utils` — crypto utilities (base64, hash, hmac, etc.)
- `@better-auth/drizzle-adapter`, `@better-auth/kysely-adapter`, etc.
- `@better-auth/telemetry`

These `workspace:*` ranges don't resolve outside the original monorepo, so the
root `package.json` uses **overrides** to pin them to concrete versions.

### Why NOT `npm:@slicekit/better-auth` for core?

Mapping `@better-auth/core` → `npm:@slicekit/better-auth` **does not work**
because the two packages have different export maps:

- `@better-auth/core` exports: `./context`, `./env`, `./error`, `./utils/*`,
  `./async_hooks`, `./db/adapter` — these are core infrastructure subpaths
- `@slicekit/better-auth` exports: `./plugins/*`, `./client`, `./react`,
  `./adapters/*` — these are the user-facing API

When `@slicekit/better-auth`'s dist code does
`import { ... } from '@better-auth/core/env'`, it needs a package that actually
exports `./env`. Aliasing to `@slicekit/better-auth` fails with:

```
Package subpath './env' is not defined by "exports"
```

### Version matching

The overrides use versions matched to the fork's base (`better-auth@1.5.1-beta.1`):

| Package | Version | Rationale |
|---------|---------|-----------|
| `@better-auth/core` | `1.5.1-beta.1` | Exact match for fork base |
| `@better-auth/utils` | `0.3.1` | Latest compatible |
| `@better-auth/*-adapter` | `1.5.1` | Closest stable to beta |
| `@better-auth/telemetry` | `1.5.1` | Closest stable to beta |
| `@better-fetch/fetch` | `1.1.21` | Catalog dep |
| `better-call` | `2.0.1` | Catalog dep |

### Proper fix (future)

To eliminate upstream `@better-auth/*` packages entirely, the
`@slicekit/better-auth` package would need to either:

1. **Bundle** the core code (inline `@better-auth/core` into the dist), or
2. **Publish** companion packages (`@slicekit/better-auth-core`, etc.), or
3. **Add re-exports** for the core subpaths (`./context`, `./env`, etc.)

Until then, the upstream packages serve as the infrastructure layer (unchanged
between upstream and fork — only the erc8128 plugin is new).

## Local store reimplementations

The `src/lib/erc8128/` directory contains local reimplementations of:
- Nonce store (in-memory)
- Verification cache (in-memory)
- Invalidation ops (in-memory)

These exist because the `@slicekit/better-auth` plugin's internal store
implementations are not exported. The local versions are fine for this demo site.
The `erc8128()` plugin factory itself is imported as a type to prove the
dependency resolves correctly.
