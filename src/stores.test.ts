import { describe, expect, spyOn, test } from "bun:test"
import { VerificationUnavailableError } from "./lib/Erc8128Error"
import {
  BoundedMemoryNonceStore,
  createRedisNonceStore,
  createUniqueInsertNonceStore
} from "./stores"

describe("ERC-8128 nonce stores", () => {
  test("bounded memory fails closed without evicting live replay keys", async () => {
    const store = new BoundedMemoryNonceStore(2)
    expect(await store.consume("first", 60)).toBe(true)
    expect(await store.consume("first", 60)).toBe(false)
    expect(await store.consume("second", 60)).toBe(true)
    await expect(store.consume("third", 60)).rejects.toBeInstanceOf(
      VerificationUnavailableError
    )
    expect(await store.consume("first", 60)).toBe(false)
    expect(await store.consume("second", 60)).toBe(false)
  })

  test("sweeps every expired nonce before checking capacity", async () => {
    let now = 1_000
    const nowSpy = spyOn(Date, "now").mockImplementation(() => now)
    try {
      const store = new BoundedMemoryNonceStore(4)
      await store.consume("expired-first", 1)
      await store.consume("live-first", 60)
      await store.consume("expired-second", 1)
      await store.consume("live-second", 60)

      now = 3_000
      await store.consume("new-first", 60)
      await store.consume("new-second", 60)

      expect(await store.consume("live-first", 60)).toBe(false)
      expect(await store.consume("live-second", 60)).toBe(false)
    } finally {
      nowSpy.mockRestore()
    }
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
