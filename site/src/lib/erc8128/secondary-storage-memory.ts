/**
 * In-memory secondary storage shim simulating Redis semantics.
 * Uses Map + TTL for key expiration.
 */
export interface SecondaryStorage {
  get(key: string): Promise<string | null>
  set(key: string, value: string, ttlSec?: number): Promise<void>
  delete(key: string): Promise<void>
}

interface Entry {
  value: string
  expiresAt: number // ms timestamp, Infinity if no TTL
}

export function createMemorySecondaryStorage(): SecondaryStorage {
  const store = new Map<string, Entry>()

  const isExpired = (entry: Entry) => entry.expiresAt <= Date.now()

  const sweep = () => {
    for (const [key, entry] of store) {
      if (isExpired(entry)) store.delete(key)
    }
  }

  // Sweep every 60s to prevent unbounded growth
  let sweepTimer: ReturnType<typeof setInterval> | null = null
  const ensureSweep = () => {
    if (!sweepTimer) {
      sweepTimer = setInterval(sweep, 60_000)
    }
  }

  return {
    async get(key) {
      const entry = store.get(key)
      if (!entry) return null
      if (isExpired(entry)) {
        store.delete(key)
        return null
      }
      return entry.value
    },

    async set(key, value, ttlSec) {
      ensureSweep()
      store.set(key, {
        value,
        expiresAt: ttlSec != null ? Date.now() + ttlSec * 1000 : Infinity
      })
    },

    async delete(key) {
      store.delete(key)
    }
  }
}
