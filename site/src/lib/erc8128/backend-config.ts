/**
 * Backend-specific better-auth instance wiring per storage mode.
 *
 * Instead of reimplementing nonce stores, verification caches, and
 * invalidation ops locally, we delegate to the better-auth erc8128
 * plugin which manages all of those internally based on the
 * `secondaryStorage` and database adapter configuration.
 */

import { memoryAdapter } from "@slicekit/better-auth/adapters/memory"
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
 * The plugin internally creates its own nonce store, verification
 * cache, and invalidation ops based on these backends.
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
        storeInDatabase: mode === "postgres"
      })
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
