/**
 * Better-auth instance factory — one singleton per storage mode.
 *
 * The erc8128 middleware intercepts /api/auth/verify (registered by the
 * playground plugin) and verifies signatures before the handler runs.
 *
 * Route policies:
 *   DELETE /api/auth/verify → non-replayable (nonce required)
 *   default → replayable + class-bound (@authority only)
 */

import { memoryAdapter } from "@slicekit/better-auth/adapters/memory"
import { erc8128 } from "@slicekit/better-auth/plugins/erc8128"
import { betterAuth } from "better-auth"
import type { VerifyMessageParameters } from "viem"
import { createPlaygroundPlugin } from "./playground-plugin"
import { createMemorySecondaryStorage } from "./secondary-storage-memory"
import type { StorageMode } from "./storage-header"

export type CacheStrategy = "none" | "secondary-storage" | "database"

export interface AuthInstance {
  handler: (request: Request) => Promise<Response>
  cacheStrategy: CacheStrategy
}

const CACHE_STRATEGY: Record<StorageMode, CacheStrategy> = {
  none: "none",
  redis: "secondary-storage",
  postgres: "database"
}

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

const instances = new Map<StorageMode, AuthInstance>()

export function getAuthInstance(
  mode: StorageMode,
  verifyMessage: (args: VerifyMessageParameters) => Promise<boolean>,
  baseURL: string
): AuthInstance {
  const cached = instances.get(mode)
  if (cached) return cached

  const secondaryStorage =
    mode === "redis" ? createMemorySecondaryStorage() : undefined

  const auth = betterAuth({
    database: memoryAdapter(createMemoryDb()),
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
          "DELETE /api/auth/verify": { replayable: false }
        }
      }),
      createPlaygroundPlugin()
    ]
  })

  const instance: AuthInstance = {
    handler: (request: Request) => auth.handler(request),
    cacheStrategy: CACHE_STRATEGY[mode]
  }

  instances.set(mode, instance)
  return instance
}
