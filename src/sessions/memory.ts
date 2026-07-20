import type {
  NonceStore,
  SessionRegistry,
  SessionRegistryRecord
} from "../types"

export const createMemoryNonceStore = (): NonceStore => {
  const expiries = new Map<string, number>()
  return {
    consume: async (key, ttlSeconds) => {
      const now = Date.now()
      const current = expiries.get(key)
      if (current !== undefined && current > now) return false
      expiries.set(key, now + ttlSeconds * 1_000)
      return true
    }
  }
}

export const createMemorySessionRegistry = (): SessionRegistry => {
  const records = new Map<string, SessionRegistryRecord>()
  return {
    delete: async (keyId) => {
      records.delete(keyId)
    },
    get: async (keyId) => records.get(keyId) ?? null,
    set: async (keyId, record) => {
      records.set(keyId, record)
    }
  }
}
