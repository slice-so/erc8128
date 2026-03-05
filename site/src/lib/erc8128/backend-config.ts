/**
 * Backend-specific store wiring per storage mode.
 *
 * Implements the same store patterns from the better-auth erc8128 plugin:
 * - Nonce store — replay protection
 * - Verification cache — caching successful verification results for replayable signatures
 * - Invalidation ops — per-keyId and per-signature invalidation records
 *
 * All three are wired per storage mode and used in the verification path.
 */

import type { NonceStore } from "@slicekit/erc8128"
import { type AdapterStub, createAdapterStub } from "./db-adapter-stub"
import {
  createMemorySecondaryStorage,
  type SecondaryStorage
} from "./secondary-storage-memory"
import type { StorageMode } from "./storage-header"

// ── Cached verification record ───────────────────────

export interface CachedVerification {
  address: string
  chainId: number
  keyId: string
  expires: number
  created: number
}

// ── Verification Cache Ops ───────────────────────────

export interface VerificationCacheOps {
  get(sig: string): Promise<CachedVerification | null>
  set(sig: string, value: CachedVerification, ttlSec: number): Promise<void>
  delete(sig: string): Promise<void>
  evictByKeyId(keyId: string, notBefore: number): void
  sweep(): void
}

const CACHE_KEY_PREFIX = "erc8128:cache:"
const CACHE_SWEEP_INTERVAL_MS = 60_000
const DEFAULT_CACHE_SIZE = 10_000

/**
 * Verification cache backed by SecondaryStorage (Redis-like).
 * TTL-managed; no L1 map needed.
 */
function createSecondaryStorageCacheOps(
  storage: SecondaryStorage
): VerificationCacheOps {
  return {
    async get(sig) {
      try {
        const raw = await storage.get(CACHE_KEY_PREFIX + sig)
        if (!raw) return null
        return JSON.parse(raw)
      } catch {
        return null
      }
    },
    async set(sig, value, ttlSec) {
      try {
        await storage.set(CACHE_KEY_PREFIX + sig, JSON.stringify(value), ttlSec)
      } catch {}
    },
    async delete(sig) {
      try {
        await storage.delete(CACHE_KEY_PREFIX + sig)
      } catch {}
    },
    evictByKeyId() {
      // SecondaryStorage doesn't support scan; rely on TTL expiration
    },
    sweep() {
      // TTL-managed — no explicit sweep needed
    }
  }
}

/**
 * Verification cache backed by DB adapter (Postgres-like) with L1 in-memory Map.
 */
function createDatabaseCacheOps(
  adapter: AdapterStub,
  maxSize: number = DEFAULT_CACHE_SIZE
): VerificationCacheOps {
  const l1 = new Map<string, CachedVerification>()
  let lastSweepMs = 0

  const setInMemory = (sig: string, value: CachedVerification) => {
    if (l1.has(sig)) l1.delete(sig)
    l1.set(sig, value)
    if (l1.size > maxSize) {
      const oldest = l1.keys().next().value
      if (oldest) l1.delete(oldest)
    }
  }

  return {
    async get(sig) {
      const inMemory = l1.get(sig)
      if (inMemory) return inMemory
      try {
        const record = await adapter.findVerificationValue(
          CACHE_KEY_PREFIX + sig
        )
        if (!record) return null
        const parsed: CachedVerification = JSON.parse(record.value)
        setInMemory(sig, parsed)
        return parsed
      } catch {
        return null
      }
    },
    async set(sig, value, ttlSec) {
      setInMemory(sig, value)
      try {
        try {
          await adapter.deleteVerificationByIdentifier(CACHE_KEY_PREFIX + sig)
        } catch {}
        await adapter.createVerificationValue({
          identifier: CACHE_KEY_PREFIX + sig,
          value: JSON.stringify(value),
          expiresAt: new Date(Date.now() + ttlSec * 1000)
        })
      } catch {}
    },
    async delete(sig) {
      l1.delete(sig)
      try {
        await adapter.deleteVerificationByIdentifier(CACHE_KEY_PREFIX + sig)
      } catch {}
    },
    evictByKeyId(keyId, notBefore) {
      for (const [sig, value] of l1) {
        if (value.keyId.toLowerCase() === keyId && value.created <= notBefore) {
          l1.delete(sig)
        }
      }
    },
    sweep() {
      const nowMs = Date.now()
      if (nowMs - lastSweepMs < CACHE_SWEEP_INTERVAL_MS) return
      lastSweepMs = nowMs
      const nowSec = Math.floor(nowMs / 1000)
      for (const [sig, value] of l1) {
        if (value.expires < nowSec) l1.delete(sig)
      }
    }
  }
}

// ── Invalidation Ops ─────────────────────────────────

export interface InvalidationRecord {
  keyId?: string
  signature?: string
  notBefore: number
}

export interface InvalidationOps {
  findByKeyId(keyId: string): Promise<InvalidationRecord[]>
  findBySignature(signature: string): Promise<InvalidationRecord | null>
  upsertKeyIdNotBefore(
    keyId: string,
    notBefore: number,
    ttlSec?: number
  ): Promise<void>
  upsertSignatureInvalidation(
    keyId: string,
    signature: string,
    ttlSec: number
  ): Promise<void>
}

const INV_KEY_PREFIX = "erc8128:inv:keyid:"
const INV_SIG_PREFIX = "erc8128:inv:sig:"
const DEFAULT_INVALIDATION_TTL_SEC = 720 * 60 * 60

/**
 * Invalidation ops backed by SecondaryStorage (Redis-like).
 */
function createSecondaryStorageInvalidationOps(
  storage: SecondaryStorage,
  defaultTtlSec: number = DEFAULT_INVALIDATION_TTL_SEC
): InvalidationOps {
  return {
    async findByKeyId(keyId) {
      try {
        const raw = await storage.get(`${INV_KEY_PREFIX}${keyId.toLowerCase()}`)
        if (!raw) return []
        return [{ notBefore: JSON.parse(raw).notBefore }]
      } catch {
        return []
      }
    },
    async findBySignature(signature) {
      try {
        const raw = await storage.get(`${INV_SIG_PREFIX}${signature}`)
        if (!raw) return null
        return JSON.parse(raw)
      } catch {
        return null
      }
    },
    async upsertKeyIdNotBefore(keyId, notBefore, ttlSec) {
      try {
        await storage.set(
          `${INV_KEY_PREFIX}${keyId.toLowerCase()}`,
          JSON.stringify({ notBefore }),
          ttlSec ?? defaultTtlSec
        )
      } catch {}
    },
    async upsertSignatureInvalidation(keyId, signature, ttlSec) {
      try {
        await storage.set(
          `${INV_SIG_PREFIX}${signature}`,
          JSON.stringify({
            keyId: keyId.toLowerCase(),
            notBefore: 0,
            signature
          }),
          ttlSec
        )
      } catch {}
    }
  }
}

/**
 * Invalidation ops backed by DB adapter (Postgres-like).
 */
function createDBInvalidationOps(adapter: AdapterStub): InvalidationOps {
  function toRecord(row: Record<string, unknown>): InvalidationRecord {
    return {
      keyId: typeof row.keyId === "string" ? row.keyId : undefined,
      signature: typeof row.signature === "string" ? row.signature : undefined,
      notBefore: typeof row.notBefore === "number" ? row.notBefore : 0
    }
  }

  return {
    async findByKeyId(keyId) {
      return (
        await adapter.findMany({
          model: "erc8128Invalidation",
          where: [
            { field: "keyId", operator: "eq", value: keyId.toLowerCase() }
          ]
        })
      ).map(toRecord)
    },
    async findBySignature(signature) {
      const row = await adapter.findOne({
        model: "erc8128Invalidation",
        where: [{ field: "signature", operator: "eq", value: signature }]
      })
      return row ? toRecord(row) : null
    },
    async upsertKeyIdNotBefore(keyId, notBefore) {
      const normalizedKeyId = keyId.toLowerCase()
      const existing = (
        await adapter.findMany({
          model: "erc8128Invalidation",
          where: [{ field: "keyId", operator: "eq", value: normalizedKeyId }]
        })
      ).find((r) => !r.signature)
      if (!existing) {
        await adapter.create({
          model: "erc8128Invalidation",
          data: { keyId: normalizedKeyId, notBefore, updatedAt: new Date() }
        })
      } else {
        await adapter.update({
          model: "erc8128Invalidation",
          where: [{ field: "id", operator: "eq", value: String(existing.id) }],
          update: { notBefore, updatedAt: new Date() }
        })
      }
    },
    async upsertSignatureInvalidation(keyId, signature, ttlSec) {
      const expiresAt = Math.floor(Date.now() / 1000) + ttlSec
      const existing = await adapter.findOne({
        model: "erc8128Invalidation",
        where: [{ field: "signature", operator: "eq", value: signature }]
      })
      if (!existing) {
        await adapter.create({
          model: "erc8128Invalidation",
          data: {
            signature,
            keyId: keyId.toLowerCase(),
            notBefore: 0,
            expiresAt,
            updatedAt: new Date()
          }
        })
      } else {
        await adapter.update({
          model: "erc8128Invalidation",
          where: [{ field: "id", operator: "eq", value: String(existing.id) }],
          update: { expiresAt }
        })
      }
    }
  }
}

// ── Nonce Store implementations ──────────────────────

const NONCE_KEY_PREFIX = "erc8128:nonce:"

function createSecondaryStorageNonceStore(
  storage: SecondaryStorage
): NonceStore {
  return {
    async consume(key, ttlSeconds) {
      const identifier = `${NONCE_KEY_PREFIX}${key}`
      try {
        if (await storage.get(identifier)) return false
        await storage.set(identifier, "1", ttlSeconds)
        return true
      } catch {
        return false
      }
    }
  }
}

function createAdapterNonceStore(adapter: AdapterStub): NonceStore {
  const fallback = new Map<string, number>()

  return {
    async consume(key, ttlSeconds) {
      const identifier = `${NONCE_KEY_PREFIX}${key}`
      try {
        if (await adapter.findVerificationValue(identifier)) return false
        await adapter.createVerificationValue({
          identifier,
          value: "1",
          expiresAt: new Date(Date.now() + ttlSeconds * 1000)
        })
        return true
      } catch {
        // Fallback to in-memory on adapter error
        const now = Date.now()
        for (const [k, exp] of fallback) {
          if (exp <= now) fallback.delete(k)
        }
        const existing = fallback.get(identifier)
        if (existing && existing > now) return false
        fallback.set(identifier, now + ttlSeconds * 1000)
        return true
      }
    }
  }
}

// ── Backend resources factory ────────────────────────

export interface StorageBackendResources {
  nonceStore?: NonceStore
  verificationCache?: VerificationCacheOps
  invalidationOps?: InvalidationOps
  /** Human-readable label for response metadata — reflects actual behavior */
  cacheStrategy: "none" | "secondary-storage" | "database"
}

// Singletons per mode — memoized at module level so verifier
// instances are stable across requests
const singletons = {
  redis: null as {
    nonceStore: NonceStore
    storage: SecondaryStorage
    cache: VerificationCacheOps
    invalidation: InvalidationOps
  } | null,
  postgres: null as {
    nonceStore: NonceStore
    adapter: AdapterStub
    cache: VerificationCacheOps
    invalidation: InvalidationOps
  } | null
}

export function getBackendResources(
  mode: StorageMode
): StorageBackendResources {
  switch (mode) {
    case "none":
      // No nonce store, no cache, no invalidation — raw baseline
      return { cacheStrategy: "none" }

    case "redis": {
      if (!singletons.redis) {
        const storage = createMemorySecondaryStorage()
        const nonceStore = createSecondaryStorageNonceStore(storage)
        const cache = createSecondaryStorageCacheOps(storage)
        const invalidation = createSecondaryStorageInvalidationOps(storage)
        singletons.redis = { nonceStore, storage, cache, invalidation }
      }
      return {
        nonceStore: singletons.redis.nonceStore,
        verificationCache: singletons.redis.cache,
        invalidationOps: singletons.redis.invalidation,
        cacheStrategy: "secondary-storage"
      }
    }

    case "postgres": {
      if (!singletons.postgres) {
        const adapter = createAdapterStub()
        const nonceStore = createAdapterNonceStore(adapter)
        const cache = createDatabaseCacheOps(adapter)
        const invalidation = createDBInvalidationOps(adapter)
        singletons.postgres = { nonceStore, adapter, cache, invalidation }
      }
      return {
        nonceStore: singletons.postgres.nonceStore,
        verificationCache: singletons.postgres.cache,
        invalidationOps: singletons.postgres.invalidation,
        cacheStrategy: "database"
      }
    }
  }
}
