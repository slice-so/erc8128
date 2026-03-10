/**
 * Better-auth instance factory for the playground worker.
 *
 * The auth instance itself is created per request. Caching the Better Auth
 * instance caused runtime issues in Workers, so only lower-level storage
 * helpers should be cached.
 */

import { AsyncLocalStorage } from "node:async_hooks"
import { type BetterAuthOptions, betterAuth } from "@slicekit/better-auth"
import { drizzleAdapter } from "@slicekit/better-auth/adapters/drizzle"
import {
  cleanupExpiredErc8128Storage,
  type Erc8128ServerApi,
  erc8128,
  getErc8128Api
} from "@slicekit/better-auth/plugins/erc8128"
import type { VerifyMessageFn } from "@slicekit/erc8128"
import { drizzle } from "drizzle-orm/postgres-js"
import postgres from "postgres"
import { createPublicClient, http } from "viem"
import { mainnet } from "viem/chains"
import * as authSchema from "../../../src/auth-schema"
import { createRedisSecondaryStorage } from "./secondary-storage-redis"
import type { StorageMode } from "./storage-header"

export type CacheStrategy = "secondary-storage" | "database"

export interface AuthInstance {
  handler: (request: Request) => Promise<Response>
  erc8128: Erc8128ServerApi
  cacheStrategy: CacheStrategy
  close: () => Promise<void>
  protect: (request: Request) => Promise<{
    result: Awaited<ReturnType<Erc8128ServerApi["protect"]>>
    cachedVerification: boolean
  }>
}

type AuthDatabase = NonNullable<BetterAuthOptions["database"]>
type AuthSecondaryStorage = NonNullable<BetterAuthOptions["secondaryStorage"]>
type CleanupAdapter = ReturnType<ReturnType<typeof drizzleAdapter>>

export interface AuthRuntimeConfig {
  cacheStrategy: CacheStrategy
  database: AuthDatabase
  cleanupAdapter?: CleanupAdapter
  secondaryStorage?: AuthSecondaryStorage
  closeDatabase?: () => Promise<void>
}

export interface AuthBindings {
  hyperdrive?: string
  databaseUrl?: string
  redisUrl?: string
}

const redisSecondaryStorageCache = new Map<string, AuthSecondaryStorage>()
const verifyMessageCache = new Map<string, VerifyMessageFn>()
const verifyCallContext = new AsyncLocalStorage<{
  verifyMessageCalled: boolean
}>()

function getRpcUrl(alchemyKey?: string) {
  const key = alchemyKey?.trim()
  return key ? `https://eth-mainnet.g.alchemy.com/v2/${key}` : undefined
}

export function getVerifyMessageFn(alchemyKey?: string): VerifyMessageFn {
  const rpcUrl = getRpcUrl(alchemyKey) ?? "default"
  const cached = verifyMessageCache.get(rpcUrl)
  if (cached) {
    return cached
  }

  const verifyMessage = createPublicClient({
    chain: mainnet,
    transport: http(getRpcUrl(alchemyKey))
  }).verifyMessage

  verifyMessageCache.set(rpcUrl, verifyMessage)
  return verifyMessage
}

function normalizeBaseURL(baseURL: string) {
  return new URL(baseURL).toString().replace(/\/$/, "")
}

function resolvePostgresConnectionString(bindings: AuthBindings): string {
  const hyperdriveConnectionString = bindings.hyperdrive?.trim()
  if (hyperdriveConnectionString) {
    return hyperdriveConnectionString
  }

  const databaseUrl = bindings.databaseUrl?.trim()
  if (databaseUrl) {
    return databaseUrl
  }

  throw new Error(
    "[erc8128/site] Postgres storage requires a Hyperdrive binding or DATABASE_URL"
  )
}

function resolveRedisUrl(bindings: AuthBindings): string {
  const redisUrl = bindings.redisUrl?.trim()
  if (redisUrl) {
    return redisUrl
  }

  throw new Error("[erc8128/site] Redis storage requires REDIS_URL")
}

function createErc8128Plugin(verifyMessage: VerifyMessageFn) {
  return erc8128({
    verifyMessage,
    routePolicy: {
      "/verify": [
        {
          methods: ["GET", "POST", "PUT"],
          replayable: true,
          classBoundPolicies: ["@authority"]
        },
        {
          methods: ["DELETE"],
          replayable: false
        }
      ]
    }
  })
}

function createPostgresRuntime(
  connectionString: string
): Pick<AuthRuntimeConfig, "database" | "cleanupAdapter" | "closeDatabase"> {
  const sql = postgres(connectionString, {
    max: 5,
    fetch_types: false
  })

  const database = drizzleAdapter(
    drizzle(sql, {
      schema: authSchema,
      casing: "snake_case"
    }),
    {
      provider: "pg"
    }
  )

  return {
    database,
    cleanupAdapter: database({
      plugins: [createErc8128Plugin(async () => false)]
    } as BetterAuthOptions),
    closeDatabase: () => sql.end()
  }
}

function getRedisSecondaryStorage(
  bindings: AuthBindings
): AuthSecondaryStorage {
  const connectionString = resolveRedisUrl(bindings)
  const cached = redisSecondaryStorageCache.get(connectionString)
  if (cached) {
    return cached
  }

  const storage = createRedisSecondaryStorage(connectionString)
  redisSecondaryStorageCache.set(connectionString, storage)
  return storage
}

function resolveRuntimeConfig(
  mode: StorageMode,
  bindings: AuthBindings
): AuthRuntimeConfig {
  const postgresRuntime = createPostgresRuntime(
    resolvePostgresConnectionString(bindings)
  )

  if (mode === "postgres") {
    return {
      cacheStrategy: "database",
      ...postgresRuntime
    }
  }

  return {
    cacheStrategy: "secondary-storage",
    ...postgresRuntime,
    secondaryStorage: getRedisSecondaryStorage(bindings)
  }
}

export function createAuthInstance(
  runtimeConfig: AuthRuntimeConfig,
  baseURL: string,
  verifyMessage: VerifyMessageFn = getVerifyMessageFn()
): AuthInstance {
  const auth = createBetterAuth(runtimeConfig, baseURL, async (args) => {
    const context = verifyCallContext.getStore()
    if (context) {
      context.verifyMessageCalled = true
    }

    return verifyMessage(args)
  })

  return {
    handler: (request: Request) => auth.handler(request),
    erc8128: getErc8128Api(auth),
    cacheStrategy: runtimeConfig.cacheStrategy,
    close: async () => {
      await runtimeConfig.closeDatabase?.()
    },
    protect: async (request: Request) =>
      verifyCallContext.run({ verifyMessageCalled: false }, async () => {
        const result = await getErc8128Api(auth).protect(request)
        const context = verifyCallContext.getStore()
        const cachedVerification =
          result.ok &&
          !!result.verification?.replayable &&
          context != null &&
          !context.verifyMessageCalled

        return {
          result,
          cachedVerification
        }
      })
  }
}

export function getAuthInstance(
  mode: StorageMode,
  baseURL: string,
  bindings: AuthBindings,
  verifyMessage = getVerifyMessageFn()
): AuthInstance {
  return createAuthInstance(
    resolveRuntimeConfig(mode, bindings),
    baseURL,
    verifyMessage
  )
}

function createBetterAuth(
  runtimeConfig: AuthRuntimeConfig,
  baseURL: string,
  verifyMessage: VerifyMessageFn
) {
  return betterAuth({
    baseURL: normalizeBaseURL(baseURL),
    database: runtimeConfig.database,
    ...(runtimeConfig.secondaryStorage
      ? { secondaryStorage: runtimeConfig.secondaryStorage }
      : {}),
    plugins: [createErc8128Plugin(verifyMessage)]
  })
}

export async function cleanupExpiredAuthStorage(
  bindings: AuthBindings,
  now = new Date()
): Promise<Awaited<ReturnType<typeof cleanupExpiredErc8128Storage>>> {
  const runtime = createPostgresRuntime(
    resolvePostgresConnectionString(bindings)
  )

  try {
    return await cleanupExpiredErc8128Storage({
      adapter: runtime.cleanupAdapter ?? runtime.database,
      now
    })
  } finally {
    await runtime.closeDatabase?.()
  }
}
