import { describe, expect, test } from "bun:test"
import {
  BoundedMemoryNonceStore,
  createRedisNonceStore,
  createUniqueInsertNonceStore
} from "./stores"

describe("ERC-8128 nonce stores", () => {
  test("bounded memory consumes atomically and evicts to its capacity", async () => {
    const store = new BoundedMemoryNonceStore(2)
    expect(await store.consume("first", 60)).toBe(true)
    expect(await store.consume("first", 60)).toBe(false)
    expect(await store.consume("second", 60)).toBe(true)
    expect(await store.consume("third", 60)).toBe(true)
    expect(await store.consume("first", 60)).toBe(true)
  })

  test("adapts Redis-shaped atomic set-if-absent storage", async () => {
    const calls: Array<[string, number]> = []
    const store = createRedisNonceStore({
      setIfNotExists: async (key, ttlSeconds) => {
        calls.push([key, ttlSeconds])
        return true
      }
    })
    expect(await store.consume("key", 1.2)).toBe(true)
    expect(calls).toEqual([["key", 2]])
  })

  test("adapts unique-insert storage with an absolute expiry", async () => {
    const expiries: Date[] = []
    const store = createUniqueInsertNonceStore(
      {
        insertUnique: async (_key, expiresAt) => {
          expiries.push(expiresAt)
          return true
        }
      },
      () => 1_000
    )
    expect(await store.consume("key", 2)).toBe(true)
    expect(expiries[0]?.getTime()).toBe(3_000)
  })
})
