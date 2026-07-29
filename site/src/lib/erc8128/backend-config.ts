import {
  createRedisNonceStore as createAtomicRedisNonceStore,
  createUniqueInsertNonceStore,
  type DiscoveryDocument,
  formatDiscoveryDocument,
  matchRoutePolicy,
  type NonceStore,
  parseKeyId,
  type RoutePolicy,
  type RoutePolicyConfig,
  selectSignatureFromHeaders,
  type VerifyMessageFn,
  verifyRequest
} from "@slicekit/erc8128"
import {
  and,
  desc,
  eq,
  gt,
  isNotNull,
  isNull,
  like,
  lte,
  max,
  or,
  sql
} from "drizzle-orm"
import { drizzle } from "drizzle-orm/postgres-js"
import postgres from "postgres"
import * as schema from "../../auth-schema"
import type {
  CachedVerification,
  InvalidationStore,
  RequestScopedSecondaryStorage,
  StorageMode,
  VerificationBindings,
  VerificationCacheStore,
  VerificationRuntime,
  VerificationRuntimeConfig
} from "../../types"

export const VERIFY_ROUTE_POLICIES: RoutePolicyConfig = {
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
  ] satisfies RoutePolicy[]
}

const REDIS_KEY_PREFIX = "erc8128-site:erc8128:"
const NONCE_KEY_PREFIX = "erc8128:nonce:"
const CACHE_KEY_PREFIX = "erc8128:cache:"
const KEY_INVALIDATION_PREFIX = "erc8128:inv:keyid:"
let redisStorageModulePromise:
  | Promise<typeof import("./secondary-storage-redis")>
  | undefined

function normalizeBaseURL(baseURL: string) {
  return new URL(baseURL).toString().replace(/\/$/, "")
}

function parseJson<T>(value: string | null): T | null {
  if (!value) {
    return null
  }

  try {
    return JSON.parse(value) as T
  } catch {
    return null
  }
}

function isReplayableSignature(signature: { params: { nonce?: string } }) {
  return !signature.params.nonce || signature.params.nonce.length === 0
}

function shouldCheckVerificationCache<CfHostMetadata, Cf>(
  request: Request<CfHostMetadata, Cf>
) {
  const signatureInputHeader = request.headers.get("signature-input")
  const signatureHeader = request.headers.get("signature")
  if (!signatureInputHeader || !signatureHeader) {
    return false
  }

  const selected = selectSignatureFromHeaders({
    signatureInputHeader,
    signatureHeader,
    policy: {}
  })
  if (!selected.ok) {
    return false
  }

  return selected.selected.some(isReplayableSignature)
}

function resolvePostgresConnectionString(
  bindings: VerificationBindings
): string {
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

function resolveRedisUrl(bindings: VerificationBindings): string {
  const redisUrl = bindings.redisUrl?.trim()
  if (redisUrl) {
    return redisUrl
  }

  throw new Error("[erc8128/site] Redis storage requires REDIS_URL")
}

async function createRedisStorage(
  bindings: VerificationBindings
): Promise<RequestScopedSecondaryStorage> {
  redisStorageModulePromise ??= import("./secondary-storage-redis")
  const { createRedisSecondaryStorage } = await redisStorageModulePromise

  return createRedisSecondaryStorage({
    connectionString: resolveRedisUrl(bindings),
    keyPrefix: REDIS_KEY_PREFIX
  })
}

export function getDiscoveryDocument(baseURL: string): DiscoveryDocument {
  const normalizedBaseURL = normalizeBaseURL(baseURL)

  return formatDiscoveryDocument({
    verificationEndpoint: new URL("/verify", normalizedBaseURL).toString(),
    routePolicy: VERIFY_ROUTE_POLICIES
  })
}

function createRedisNonceStore(
  storage: RequestScopedSecondaryStorage
): NonceStore {
  const setIfNotExists = storage.setIfNotExists
  if (setIfNotExists === undefined) {
    throw new Error("Redis nonce storage must support atomic set-if-absent.")
  }
  return createAtomicRedisNonceStore({
    setIfNotExists: (key, ttlSeconds) =>
      setIfNotExists(`${NONCE_KEY_PREFIX}${key}`, "1", ttlSeconds)
  })
}

function createRedisVerificationCache(
  storage: RequestScopedSecondaryStorage
): VerificationCacheStore {
  return {
    async get(signatureHeader) {
      return parseJson<CachedVerification>(
        await storage.get(`${CACHE_KEY_PREFIX}${signatureHeader}`)
      )
    },

    async set(signatureHeader, value, ttlSec) {
      await storage.set(
        `${CACHE_KEY_PREFIX}${signatureHeader}`,
        JSON.stringify(value),
        ttlSec
      )
    },

    async delete(signatureHeader) {
      await storage.delete(`${CACHE_KEY_PREFIX}${signatureHeader}`)
    }
  }
}

function createRedisInvalidationStore(
  storage: RequestScopedSecondaryStorage
): InvalidationStore {
  return {
    async getNotBefore(keyId) {
      const record = parseJson<{ notBefore?: number }>(
        await storage.get(`${KEY_INVALIDATION_PREFIX}${keyId.toLowerCase()}`)
      )
      return typeof record?.notBefore === "number" ? record.notBefore : null
    }
  }
}

function createDrizzleClient(connectionString: string) {
  const pgClient = postgres(connectionString, {
    // Hyperdrive handles the underlying pooling, so request-scoped clients are
    // cheap. Keep the client connection cap within Workers' external connection
    // limits and skip type fetching to avoid an extra round-trip.
    max: 5,
    fetch_types: false
  })
  const db = drizzle(pgClient, { schema })
  return { db, close: () => pgClient.end().catch(() => undefined) }
}

async function createPostgresRuntime(
  connectionString: string
): Promise<VerificationRuntimeConfig> {
  const { db, close } = createDrizzleClient(connectionString)

  const nonceStore = createUniqueInsertNonceStore({
    async insertUnique(key, expiresAt) {
      const result = await db
        .insert(schema.erc8128Nonce)
        .values({
          id: crypto.randomUUID(),
          nonceKey: `${NONCE_KEY_PREFIX}${key}`,
          expiresAt
        })
        .onConflictDoNothing({ target: schema.erc8128Nonce.nonceKey })
        .returning({ id: schema.erc8128Nonce.id })

      return result.length === 1
    }
  })

  const verificationCache: VerificationCacheStore = {
    async get(signatureHeader) {
      const identifier = `${CACHE_KEY_PREFIX}${signatureHeader}`
      const result = await db
        .select({ value: schema.verification.value })
        .from(schema.verification)
        .where(
          and(
            eq(schema.verification.identifier, identifier),
            gt(schema.verification.expiresAt, sql`NOW()`)
          )
        )
        .orderBy(
          desc(schema.verification.expiresAt),
          desc(schema.verification.updatedAt)
        )
        .limit(1)

      return parseJson<CachedVerification>(result[0]?.value ?? null)
    },

    async set(signatureHeader, value, ttlSec) {
      const identifier = `${CACHE_KEY_PREFIX}${signatureHeader}`
      const expiresAt = new Date(Date.now() + ttlSec * 1000)

      await db
        .delete(schema.verification)
        .where(eq(schema.verification.identifier, identifier))

      await db.insert(schema.verification).values({
        id: crypto.randomUUID(),
        identifier,
        value: JSON.stringify(value),
        expiresAt
      })
    },

    async delete(signatureHeader) {
      await db
        .delete(schema.verification)
        .where(
          eq(
            schema.verification.identifier,
            `${CACHE_KEY_PREFIX}${signatureHeader}`
          )
        )
    }
  }

  const invalidationStore: InvalidationStore = {
    async getNotBefore(keyId) {
      const parsedKeyId = parseKeyId(keyId)
      if (!parsedKeyId) {
        return null
      }

      const result = await db
        .select({ notBefore: max(schema.erc8128Invalidation.notBefore) })
        .from(schema.erc8128Invalidation)
        .where(
          and(
            eq(
              schema.erc8128Invalidation.address,
              parsedKeyId.address.toLowerCase()
            ),
            eq(schema.erc8128Invalidation.chainId, parsedKeyId.chainId),
            isNull(schema.erc8128Invalidation.signatureHash),
            isNotNull(schema.erc8128Invalidation.notBefore),
            or(
              isNull(schema.erc8128Invalidation.expiresAt),
              gt(schema.erc8128Invalidation.expiresAt, sql`NOW()`)
            )
          )
        )

      const value = result[0]?.notBefore
      return typeof value === "number" ? value : null
    }
  }

  return {
    cacheStrategy: "database",
    nonceStore,
    verificationCache,
    invalidationStore,
    close
  }
}

async function createRedisRuntime(
  bindings: VerificationBindings
): Promise<VerificationRuntimeConfig> {
  const storage = await createRedisStorage(bindings)

  return {
    cacheStrategy: "secondary-storage",
    nonceStore: createRedisNonceStore(storage),
    verificationCache: createRedisVerificationCache(storage),
    invalidationStore: createRedisInvalidationStore(storage),
    close: () => storage.close()
  }
}

async function resolveRuntimeConfig(
  mode: StorageMode,
  bindings: VerificationBindings
): Promise<VerificationRuntimeConfig> {
  if (mode === "postgres") {
    return createPostgresRuntime(resolvePostgresConnectionString(bindings))
  }

  return createRedisRuntime(bindings)
}

export function createVerificationRuntime(
  runtimeConfig: VerificationRuntimeConfig,
  baseURL: string,
  verifyMessage: VerifyMessageFn
): VerificationRuntime {
  const normalizedBaseURL = normalizeBaseURL(baseURL)

  return {
    cacheStrategy: runtimeConfig.cacheStrategy,
    getConfig: () => getDiscoveryDocument(normalizedBaseURL),
    verifyRequest: async <CfHostMetadata, Cf>(
      request: Request<CfHostMetadata, Cf>
    ) => {
      const pathname = new URL(request.url).pathname
      const routePolicy = matchRoutePolicy(
        request.method,
        pathname,
        VERIFY_ROUTE_POLICIES
      )
      const responseHeaders = new Headers()

      if (!routePolicy) {
        return {
          result: {
            ok: false,
            reason: "not_request_bound",
            detail: `No ERC-8128 policy is configured for ${request.method.toUpperCase()} ${pathname}`
          },
          responseHeaders,
          cachedVerification: false
        }
      }

      const signatureHeader = request.headers.get("signature")

      if (
        routePolicy.replayable &&
        signatureHeader &&
        shouldCheckVerificationCache(request)
      ) {
        const cached =
          await runtimeConfig.verificationCache.get(signatureHeader)

        if (cached) {
          const notBefore = await runtimeConfig.invalidationStore.getNotBefore(
            cached.params.keyid
          )

          if (notBefore == null || cached.params.created >= notBefore) {
            return {
              result: {
                ok: true,
                ...cached
              },
              responseHeaders,
              cachedVerification: true
            }
          }

          await runtimeConfig.verificationCache.delete(signatureHeader)
        }
      }

      const result = await verifyRequest({
        request: request as Request,
        verifyMessage,
        nonceStore: runtimeConfig.nonceStore,
        policy: {
          ...routePolicy,
          replayableNotBefore: (keyId) =>
            runtimeConfig.invalidationStore.getNotBefore(keyId)
        },
        setHeaders: (name, value) => {
          responseHeaders.set(name, value)
        }
      })

      if (result.ok && result.replayable && signatureHeader) {
        const ttlSec = result.params.expires - Math.floor(Date.now() / 1000)
        if (ttlSec > 0) {
          await runtimeConfig.verificationCache.set(
            signatureHeader,
            {
              address: result.address,
              chainId: result.chainId,
              label: result.label,
              components: result.components,
              params: result.params,
              replayable: true,
              binding: result.binding
            },
            ttlSec
          )
        }
      }

      return {
        result,
        responseHeaders,
        cachedVerification: false
      }
    },
    close: async () => {
      await runtimeConfig.close?.()
    }
  }
}

export async function getVerificationRuntime(
  mode: StorageMode,
  baseURL: string,
  bindings: VerificationBindings,
  verifyMessage: VerifyMessageFn
): Promise<VerificationRuntime> {
  return createVerificationRuntime(
    await resolveRuntimeConfig(mode, bindings),
    baseURL,
    verifyMessage
  )
}

export async function cleanupExpiredVerificationStorage(
  bindings: VerificationBindings,
  now = new Date()
) {
  const { db, close } = createDrizzleClient(
    resolvePostgresConnectionString(bindings)
  )

  try {
    const [
      verificationRows,
      legacyNonceRows,
      legacyCacheRows,
      invalidationRows
    ] = await Promise.all([
      db
        .delete(schema.verification)
        .where(
          and(
            lte(schema.verification.expiresAt, now),
            or(
              like(schema.verification.identifier, `${NONCE_KEY_PREFIX}%`),
              like(schema.verification.identifier, `${CACHE_KEY_PREFIX}%`)
            )
          )
        )
        .returning({ id: schema.verification.id }),
      db
        .delete(schema.erc8128Nonce)
        .where(lte(schema.erc8128Nonce.expiresAt, now))
        .returning({ id: schema.erc8128Nonce.id }),
      db
        .delete(schema.erc8128VerificationCache)
        .where(lte(schema.erc8128VerificationCache.expiresAt, now))
        .returning({ id: schema.erc8128VerificationCache.id }),
      db
        .delete(schema.erc8128Invalidation)
        .where(
          and(
            isNotNull(schema.erc8128Invalidation.expiresAt),
            lte(schema.erc8128Invalidation.expiresAt, now)
          )
        )
        .returning({ id: schema.erc8128Invalidation.id })
    ])

    return {
      verificationRowsDeleted: verificationRows.length,
      legacyNonceRowsDeleted: legacyNonceRows.length,
      legacyCacheRowsDeleted: legacyCacheRows.length,
      invalidationRowsDeleted: invalidationRows.length
    }
  } finally {
    await close()
  }
}
