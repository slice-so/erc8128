/**
 * Backend-specific better-auth instance wiring per storage mode.
 *
 * The /verify endpoint is handled by a custom "playground" plugin endpoint.
 * The erc8128 plugin's middleware hook intercepts requests to this endpoint
 * and performs verification with cache, nonce consumption, and invalidation
 * checks — all configured via routePolicy.
 *
 * Route policies:
 *   DELETE /api/auth/verify → non-replayable (nonce required)
 *   * /api/auth/verify      → replayable, class-bound (@authority only)
 */

import { memoryAdapter } from "@slicekit/better-auth/adapters/memory"
import { createAuthEndpoint } from "@slicekit/better-auth/api"
import { erc8128 } from "@slicekit/better-auth/plugins/erc8128"
import { betterAuth } from "better-auth"
import type { VerifyMessageParameters } from "viem"
import { createMemorySecondaryStorage } from "./secondary-storage-memory"
import type { StorageMode } from "./storage-header"

// ── Types ────────────────────────────────────────────

export type CacheStrategy = "none" | "secondary-storage" | "database"

export interface AuthInstance {
  handler: (request: Request) => Promise<Response>
  cacheStrategy: CacheStrategy
}

// ── Memory DB schema for better-auth ─────────────────

function createMemoryDb() {
  return {
    user: [] as Record<string, unknown>[],
    session: [] as Record<string, unknown>[],
    account: [] as Record<string, unknown>[],
    verification: [] as Record<string, unknown>[],
    walletAddress: [] as Record<string, unknown>[],
    erc8128Nonce: [] as Record<string, unknown>[],
    erc8128Invalidation: [] as Record<string, unknown>[]
  }
}

// ── Signature-input parsing ──────────────────────────

/**
 * Parse the Signature-Input header to extract verification metadata.
 * This is used by the playground endpoint to build its response after
 * the erc8128 middleware has already verified the signature.
 */
function parseSignatureInput(sigInput: string) {
  const keyidMatch = sigInput.match(/keyid="([^"]+)"/)
  const keyid = keyidMatch?.[1] || ""
  const keyParts = keyid.match(/^eip155:(\d+):(0x[a-fA-F0-9]+)$/i)
  const address = keyParts?.[2] || ""
  const chainId = keyParts ? parseInt(keyParts[1], 10) : 1

  // Parse signed components from the parameter list: sig1=("@method" "@authority" ...)
  const componentsMatch = sigInput.match(/\(([^)]*)\)/)
  const components = componentsMatch
    ? (componentsMatch[1].match(/"([^"]+)"/g) || []).map((s) =>
        s.replace(/"/g, "")
      )
    : []

  const created = parseInt(sigInput.match(/;created=(\d+)/)?.[1] || "0", 10)
  const expires = parseInt(sigInput.match(/;expires=(\d+)/)?.[1] || "0", 10)

  return { address, chainId, keyid, components, created, expires }
}

// ── Playground verify endpoint ───────────────────────

/**
 * Create a minimal better-auth plugin that registers a /verify endpoint.
 *
 * The erc8128 plugin's middleware hook intercepts this endpoint (it's NOT
 * in the erc8128 plugin's own pluginPaths, so the middleware runs).
 * After verification succeeds, the middleware falls through and this
 * handler runs, returning the parsed verification metadata.
 *
 * If verification fails, the middleware short-circuits with a 401 response
 * before this handler ever executes.
 */
function createPlaygroundPlugin() {
  return {
    id: "playground",
    endpoints: {
      playgroundVerify: createAuthEndpoint(
        "/verify",
        {
          method: ["GET", "POST", "PUT", "PATCH", "DELETE"] as any,
          requireRequest: true
        },
        async (ctx: any) => {
          const req = ctx.request as Request
          const sigInput = req.headers.get("signature-input") || ""
          const meta = parseSignatureInput(sigInput)

          const isDelete = req.method.toUpperCase() === "DELETE"
          const hasMethod = meta.components.includes("@method")
          const hasPath =
            meta.components.includes("@path") ||
            meta.components.includes("@target-uri")

          return ctx.json({
            ok: true,
            address: meta.address,
            chainId: meta.chainId,
            label: "eth",
            components: meta.components,
            binding: hasMethod && hasPath ? "request-bound" : "class-bound",
            replayable: !isDelete,
            params: {
              created: meta.created,
              expires: meta.expires,
              keyid: meta.keyid.toLowerCase()
            }
          })
        }
      )
    }
  }
}

// ── Singleton auth instances per storage mode ────────

const instances = new Map<string, AuthInstance>()

/**
 * Get (or create) a better-auth instance for the given storage mode.
 *
 * Each mode configures the erc8128 plugin differently:
 * - `none`: No secondaryStorage, database adapter only (baseline)
 * - `redis`: secondaryStorage backed by in-memory Redis shim
 * - `postgres`: Database adapter only (in-memory adapter stub)
 *
 * The erc8128 plugin's middleware hook runs on /api/auth/verify,
 * performing verification with cache, nonce, and invalidation support.
 * Route policies configure per-method verification behavior.
 */
export function getAuthInstance(
  mode: StorageMode,
  verifyMessage: (args: VerifyMessageParameters) => Promise<boolean>,
  baseURL: string
): AuthInstance {
  const key = `${mode}`
  const cached = instances.get(key)
  if (cached) return cached

  const db = createMemoryDb()
  const secondaryStorage =
    mode === "redis" ? createMemorySecondaryStorage() : undefined

  const auth = betterAuth({
    database: memoryAdapter(db),
    basePath: "/api/auth",
    baseURL,
    ...(secondaryStorage ? { secondaryStorage } : {}),
    plugins: [
      erc8128({
        verifyMessage,
        anonymous: true,
        maxValiditySec: 300,
        clockSkewSec: 30,
        defaultPolicy: {
          replayable: true,
          classBoundPolicies: [["@authority"]]
        },
        routePolicy: {
          // DELETE requires non-replayable (nonce-bound) signatures
          "DELETE /api/auth/verify": { replayable: false },
          // All other methods: replayable, class-bound with @authority
          "* /api/auth/verify": {
            replayable: true,
            classBoundPolicies: [["@authority"]]
          }
        },
        storeInDatabase: mode === "postgres"
      }),
      // Playground endpoint — erc8128 middleware intercepts this
      createPlaygroundPlugin()
    ]
  })

  const cacheStrategy: CacheStrategy =
    mode === "none"
      ? "none"
      : mode === "redis"
        ? "secondary-storage"
        : "database"

  const instance: AuthInstance = {
    handler: (request: Request) => auth.handler(request),
    cacheStrategy
  }

  instances.set(key, instance)
  return instance
}
