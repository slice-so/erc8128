import type {
  NonceStore,
  RedisNonceStoreClient,
  UniqueInsertNonceStoreClient
} from "./types"

export class BoundedMemoryNonceStore implements NonceStore {
  private readonly entries = new Map<string, number>()

  constructor(private readonly maximumEntries = 10_000) {
    if (!Number.isSafeInteger(maximumEntries) || maximumEntries <= 0) {
      throw new Error("Nonce store capacity must be a positive safe integer.")
    }
  }

  async consume(key: string, ttlSeconds: number) {
    const now = Date.now()
    const activeUntil = this.entries.get(key)
    if (activeUntil !== undefined && activeUntil > now) return false
    this.entries.delete(key)
    this.prune(now)
    this.entries.set(key, now + Math.max(1, Math.ceil(ttlSeconds)) * 1_000)
    return true
  }

  private prune(now: number) {
    for (const [key, expiresAt] of this.entries) {
      if (expiresAt <= now) this.entries.delete(key)
    }
    while (this.entries.size >= this.maximumEntries) {
      const oldest = this.entries.keys().next().value
      if (oldest === undefined) break
      this.entries.delete(oldest)
    }
  }
}

export const createRedisNonceStore = (
  client: RedisNonceStoreClient
): NonceStore => ({
  consume: (key, ttlSeconds) =>
    client.setIfNotExists(key, Math.max(1, Math.ceil(ttlSeconds)))
})

export const createUniqueInsertNonceStore = (
  client: UniqueInsertNonceStoreClient,
  now = () => Date.now()
): NonceStore => ({
  consume: (key, ttlSeconds) =>
    client.insertUnique(
      key,
      new Date(now() + Math.max(1, Math.ceil(ttlSeconds)) * 1_000)
    )
})
