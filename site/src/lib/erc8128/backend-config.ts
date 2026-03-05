/**
 * Backend-specific store wiring per storage mode.
 *
 * Implements the same store patterns from the better-auth erc8128 plugin
 * (nonce store, verification cache, invalidation ops) using in-memory
 * shims, applied directly to `createVerifierClient` from @slicekit/erc8128.
 */

import type { NonceStore } from "@slicekit/erc8128"
import { type AdapterStub, createAdapterStub } from "./db-adapter-stub"
import {
  createMemorySecondaryStorage,
  type SecondaryStorage
} from "./secondary-storage-memory"
import type { StorageMode } from "./storage-header"

// ── Nonce Store implementations ──────────────────────

const NONCE_KEY_PREFIX = "erc8128:nonce:"

/**
 * NonceStore backed by SecondaryStorage (Redis-like).
 */
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

/**
 * NonceStore backed by DB adapter (Postgres-like).
 */
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

// ── Backend resources ────────────────────────────────

export interface StorageBackendResources {
  nonceStore?: NonceStore
  /** Human-readable label for response metadata */
  cacheStrategy: "none" | "secondary-storage" | "database"
}

// Singletons per mode — memoized at module level so verifier
// instances are stable across requests
const singletons = {
  redis: null as { nonceStore: NonceStore; storage: SecondaryStorage } | null,
  postgres: null as { nonceStore: NonceStore; adapter: AdapterStub } | null
}

export function getBackendResources(
  mode: StorageMode
): StorageBackendResources {
  switch (mode) {
    case "none":
      return { cacheStrategy: "none" }

    case "redis": {
      if (!singletons.redis) {
        const storage = createMemorySecondaryStorage()
        const nonceStore = createSecondaryStorageNonceStore(storage)
        singletons.redis = { nonceStore, storage }
      }
      return {
        nonceStore: singletons.redis.nonceStore,
        cacheStrategy: "secondary-storage"
      }
    }

    case "postgres": {
      if (!singletons.postgres) {
        const adapter = createAdapterStub()
        const nonceStore = createAdapterNonceStore(adapter)
        singletons.postgres = { nonceStore, adapter }
      }
      return {
        nonceStore: singletons.postgres.nonceStore,
        cacheStrategy: "database"
      }
    }
  }
}
