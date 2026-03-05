# @slicekit/better-auth Dependency Resolution

## Status: Working ✅

## Setup

Two `better-auth` packages are installed in the site:

1. **`better-auth@1.5.1`** — the standard upstream package, installed as a
   regular dependency. This brings in all `@better-auth/*` infrastructure
   packages (`@better-auth/core`, `@better-auth/utils`, adapters, etc.) at their
   correct stable versions.

2. **`@slicekit/better-auth@1.5.1-beta.1-erc8128.0`** — the Slice fork,
   used only for the `erc8128` plugin import:

   ```js
   import { erc8128 } from "@slicekit/better-auth/plugins/erc8128"
   // ✅ Works — exports the erc8128() plugin factory
   ```

## Why overrides are still needed

`@slicekit/better-auth` was published from the better-auth monorepo with
`workspace:*` and `catalog:` dependency specifiers (e.g.
`"@better-auth/core": "workspace:*"`). These protocols don't resolve outside the
original monorepo.

The root `package.json` uses **overrides** to pin them to the exact versions
that `better-auth@1.5.1` itself uses:

| Package | Override Version |
|---------|-----------------|
| `@better-auth/core` | `1.5.1` |
| `@better-auth/drizzle-adapter` | `1.5.1` |
| `@better-auth/kysely-adapter` | `1.5.1` |
| `@better-auth/memory-adapter` | `1.5.1` |
| `@better-auth/mongo-adapter` | `1.5.1` |
| `@better-auth/prisma-adapter` | `1.5.1` |
| `@better-auth/telemetry` | `1.5.1` |
| `@better-auth/utils` | `0.3.1` |
| `@better-fetch/fetch` | `1.1.21` |
| `better-call` | `1.3.2` |

These match exactly what `better-auth@1.5.1` declares in its own dependencies,
so both packages share the same underlying modules at runtime.

## Proper fix (future)

To eliminate overrides entirely, `@slicekit/better-auth` would need to be
published with concrete version ranges instead of `workspace:*` / `catalog:`.
Options:

1. **Use `publishConfig`** or a pre-publish script to replace `workspace:*` with
   pinned versions before publishing
2. **Bundle** the core code inline
3. **Publish** companion packages (`@slicekit/better-auth-core`, etc.)

## Local store reimplementations

The `src/lib/erc8128/` directory contains local reimplementations of:
- Nonce store (in-memory)
- Verification cache (in-memory)
- Invalidation ops (in-memory)

These exist because the `@slicekit/better-auth` plugin's internal store
implementations are not exported. The local versions are fine for this demo site.
