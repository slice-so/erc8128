# ERC-8128 Better Auth Integration Review v3

## Scope
Reviewed current implementation in:
- `src/worker.ts`
- `src/components/playground/PlaygroundInner.tsx`
- `src/lib/erc8128/backend-config.ts`
- `src/lib/erc8128/storage-header.ts`
- `src/lib/erc8128/secondary-storage-memory.ts`
- `src/lib/erc8128/db-adapter-stub.ts`

Compared against originals at commit `a2bdd140` for:
- `worker.ts`
- `PlaygroundInner.tsx`

Reviewed Better Auth ERC-8128 plugin source (`slice-so/better-auth`, branch `erc8128`, file `packages/better-auth/src/plugins/erc8128/index.ts`).

---

## Findings by checklist

1. **Are `betterAuth`, `erc8128`, `createAuthClient`, `erc8128Client` imported + used?**
   - ✅ Yes.
   - Server uses `betterAuth` + `erc8128` in `backend-config.ts`.
   - Client uses `createAuthClient` + `erc8128Client` in `PlaygroundInner.tsx` to sign outgoing requests.

2. **Is `/verify` kept as endpoint (not redirected to `/erc8128/verify`)?**
   - ✅ Yes.
   - Worker keeps public endpoint at `/verify`.
   - Request is internally rewritten to `/api/auth/verify` (custom playground endpoint), **not** `/api/auth/erc8128/verify`.

3. **Route policies: DELETE non-replayable, default replayable + class-bound**
   - ⚠️ Found issue, fixed.
   - Before fix: wildcard `* /api/auth/verify` route policy existed.
   - After fix: only `DELETE /api/auth/verify` route policy remains; all other methods use `defaultPolicy` (`replayable: true`, `classBoundPolicies: [["@authority"]]`).

4. **Middleware cache/nonce/invalidation behavior**
   - ⚠️ Found issue, fixed indirectly by policy change.
   - Better Auth plugin cache fast-path only runs when `!resolvedRoutePolicy.policy`.
   - With wildcard route policy, `/api/auth/verify` always had explicit policy, preventing replayable cache fast-path.
   - After removing wildcard policy, default-method requests now leverage replayable verification cache while preserving nonce/invalidation behavior.

5. **Original behavior preserved**
   - ✅ Preserved for core `/verify` behavior:
     - same endpoint
     - same invalid JSON handling
     - same verbose payload model
     - same status mapping for bad headers/keyid/signature-input
     - DELETE non-replayable semantics maintained
     - non-DELETE class-bound replayable flow maintained
   - Plus expected Better Auth additions (`/.well-known/erc8128`, storage mode reporting/cache strategy metadata).

6. **Client side signing with `erc8128Client`**
   - ✅ Preserved.
   - Signing still supports wallet and app-wallet flow, nonce toggle semantics, TTL/components, and class-bound config.

7. **Storage mode switching via `x-erc8128-storage`**
   - ✅ Works as wired.
   - Header parser supports `none|redis|postgres` with env fallback.
   - Worker forwards selected mode into backend instance creation.

8. **Build (`pnpm build`)**
   - ✅ Passes in `packages/erc8128/site`.

---

## Changes made

### 1) Route policy fix to restore cache path and match requirement
- **File:** `src/lib/erc8128/backend-config.ts`
- **Change:** Removed wildcard `* /api/auth/verify` route policy and kept only DELETE-specific policy.
- **Reason:**
  - Align with requirement: DELETE-specific route policy; default behavior from plugin default policy.
  - Re-enable Better Auth replayable cache fast-path for non-DELETE `/verify` requests.

---

## Verification commands run

```bash
# Build verification
cd packages/erc8128/site
pnpm build
```

Result: success.

---

## Final Verdict

## PASS

Integration now matches requested architecture:
- `/verify` remains the external endpoint
- no migration to plugin `/erc8128/verify`
- DELETE behavior isolated in route policy
- default replayable class-bound behavior handled by default policy
- Better Auth middleware cache + nonce/invalidation paths are properly leveraged.
