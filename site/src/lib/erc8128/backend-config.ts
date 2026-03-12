/**
 * Better-auth instance factory for the playground worker.
 *
 * The Better Auth instance itself remains request-scoped because sharing it in
 * Workers caused runtime issues.
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
import type {
  RoutePolicy,
  VerifyMessageFn,
  VerifyPolicy
} from "@slicekit/erc8128"
import { drizzle } from "drizzle-orm/node-postgres"
import { Client } from "pg"
import * as authSchema from "../../../src/auth-schema"
import {
  createRedisSecondaryStorage,
  type RequestScopedSecondaryStorage
} from "./secondary-storage-redis"
import type { StorageMode } from "./storage-header"

export type CacheStrategy = "secondary-storage" | "database"

export interface AuthInstance {
  handler: (request: Request) => Promise<Response>
  erc8128: Erc8128ServerApi
  cacheStrategy: CacheStrategy
  close: () => Promise<void>
  verifyRequest: (
    request: Request,
    policy?: VerifyPolicy
  ) => Promise<{
    result: Awaited<ReturnType<Erc8128ServerApi["verifyRequest"]>>
    cachedVerification: boolean
  }>
  protect: (request: Request) => Promise<{
    result: Awaited<ReturnType<Erc8128ServerApi["protect"]>>
    cachedVerification: boolean
  }>
}

type AuthDatabase = NonNullable<BetterAuthOptions["database"]>
type AuthSecondaryStorage = NonNullable<BetterAuthOptions["secondaryStorage"]>
type CleanupAdapter = ReturnType<ReturnType<typeof drizzleAdapter>>
type AsyncCallTracker = ReturnType<typeof createAsyncCallTracker>

export interface AuthRuntimeConfig {
  cacheStrategy: CacheStrategy
  database?: AuthDatabase
  cleanupAdapter?: CleanupAdapter
  secondaryStorage?: AuthSecondaryStorage
  closeDatabase?: () => Promise<void>
  closeSecondaryStorage?: () => Promise<void>
}

export interface AuthBindings {
  hyperdrive?: string
  databaseUrl?: string
  redisUrl?: string
}

const REDIS_KEY_PREFIX = "erc8128-site:better-auth:"
const VERIFY_ROUTE_POLICIES: RoutePolicy[] = [
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
const verifyCallContext = new AsyncLocalStorage<{
  verifyMessageCalled: boolean
}>()

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
    storeInDatabase: false,
    verifyMessage,
    routePolicy: {
      "/verify": VERIFY_ROUTE_POLICIES
    }
  })
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    value != null &&
    (typeof value === "object" || typeof value === "function") &&
    typeof (value as { then?: unknown }).then === "function"
  )
}

function createAsyncCallTracker() {
  const pending = new Set<Promise<unknown>>()

  return {
    track<T>(value: T): T {
      if (!isPromiseLike(value)) {
        return value
      }

      const promise = Promise.resolve(value)
      pending.add(promise)
      void promise.finally(() => {
        pending.delete(promise)
      })
      return value
    },

    async waitForIdle() {
      if (pending.size === 0) {
        return
      }

      await Promise.allSettled([...pending])
    }
  }
}

function trackAdapter<T extends object>(
  adapter: T,
  tracker: AsyncCallTracker
): T {
  return new Proxy(adapter, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver)
      if (typeof value !== "function") {
        return value
      }

      return (...args: unknown[]) => tracker.track(value.apply(target, args))
    }
  })
}

function createTrackedDatabaseFactory(
  database: AuthDatabase,
  tracker: AsyncCallTracker
): AuthDatabase {
  return ((options: BetterAuthOptions) =>
    trackAdapter(database(options), tracker)) as AuthDatabase
}

async function createPostgresRuntime(
  connectionString: string
): Promise<
  Pick<AuthRuntimeConfig, "database" | "cleanupAdapter" | "closeDatabase">
> {
  const client = new Client({ connectionString })
  await client.connect()
  const tracker = createAsyncCallTracker()

  const database = createTrackedDatabaseFactory(
    drizzleAdapter(
      drizzle(client, {
        casing: "snake_case"
      }),
      {
        provider: "pg",
        schema: authSchema
      }
    ),
    tracker
  )

  return {
    database,
    cleanupAdapter: database({
      plugins: [createErc8128Plugin(async () => false)]
    } as BetterAuthOptions),
    closeDatabase: async () => {
      await tracker.waitForIdle()
      await client.end().catch(() => undefined)
    }
  }
}

function createRequestScopedRedisSecondaryStorage(
  bindings: AuthBindings
): RequestScopedSecondaryStorage {
  const connectionString = resolveRedisUrl(bindings)
  return createRedisSecondaryStorage({
    connectionString,
    keyPrefix: REDIS_KEY_PREFIX
  })
}

async function resolveRuntimeConfig(
  mode: StorageMode,
  bindings: AuthBindings
): Promise<AuthRuntimeConfig> {
  if (mode === "postgres") {
    const postgresRuntime = await createPostgresRuntime(
      resolvePostgresConnectionString(bindings)
    )

    return {
      cacheStrategy: "database",
      ...postgresRuntime
    }
  }

  const secondaryStorage = createRequestScopedRedisSecondaryStorage(bindings)

  return {
    cacheStrategy: "secondary-storage",
    secondaryStorage,
    closeSecondaryStorage: () => secondaryStorage.close()
  }
}

export function createAuthInstance(
  runtimeConfig: AuthRuntimeConfig,
  baseURL: string,
  verifyMessage: VerifyMessageFn
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
      await Promise.allSettled([
        runtimeConfig.closeSecondaryStorage?.(),
        runtimeConfig.closeDatabase?.()
      ])
    },
    verifyRequest: async (request: Request, policy?: VerifyPolicy) =>
      verifyCallContext.run({ verifyMessageCalled: false }, async () => {
        const result = await getErc8128Api(auth).verifyRequest(request, {
          policy
        })

        const context = verifyCallContext.getStore()
        const cachedVerification =
          result.ok &&
          !!result.verification.replayable &&
          context != null &&
          !context.verifyMessageCalled

        return {
          result,
          cachedVerification
        }
      }),
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

export async function getAuthInstance(
  mode: StorageMode,
  baseURL: string,
  bindings: AuthBindings,
  verifyMessage: VerifyMessageFn
): Promise<AuthInstance> {
  return createAuthInstance(
    await resolveRuntimeConfig(mode, bindings),
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
    ...(runtimeConfig.database ? { database: runtimeConfig.database } : {}),
    ...(runtimeConfig.secondaryStorage
      ? { secondaryStorage: runtimeConfig.secondaryStorage }
      : {}),
    plugins: [createErc8128Plugin(verifyMessage)],
    secret: "ff68f964f62c4b669fb2c89507250fa22d8b452ae97a2ab0b5ff038e7cec1875",
    session: {
      cookieCache: {
        refreshCache: false
      }
    }
  })
}

export async function cleanupExpiredAuthStorage(
  bindings: AuthBindings,
  now = new Date()
): Promise<Awaited<ReturnType<typeof cleanupExpiredErc8128Storage>>> {
  const runtime = await createPostgresRuntime(
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
