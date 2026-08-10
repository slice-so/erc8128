import { describe, expect, test } from "bun:test"
import { signRequest } from "@slicekit/erc8128"
import { verifyMessage } from "viem"
import { type Address, privateKeyToAccount } from "viem/accounts"
import type { CachedVerification, VerificationRuntimeConfig } from "../../types"
import { createVerificationRuntime } from "./backend-config"

const TEST_SIGNER = {
  address: "0x000000000000000000000000000000000000dEaD" as Address,
  chainId: 1,
  async signMessage() {
    return `0x${"11".repeat(65)}` as const
  }
}
const TEST_SIGNER_VERIFIED_ADDRESS = TEST_SIGNER.address.toLowerCase()

const REAL_SIGNER_ACCOUNT = privateKeyToAccount(
  "0x0123456789012345678901234567890123456789012345678901234567890123"
)

const REAL_SIGNER = {
  address: REAL_SIGNER_ACCOUNT.address,
  chainId: 1,
  signMessage: async (message: Uint8Array) =>
    REAL_SIGNER_ACCOUNT.signMessage({ message: { raw: message } })
}

function createRuntimeConfig(
  options: {
    cacheStrategy?: VerificationRuntimeConfig["cacheStrategy"]
    onClose?: () => Promise<void> | void
    invalidatedAfter?: number
    onCacheGet?: (signatureHeader: string) => Promise<void> | void
  } = {}
): VerificationRuntimeConfig {
  const nonceExpiries = new Map<string, number>()
  const cache = new Map<
    string,
    {
      value: CachedVerification
      expiresAt: number
    }
  >()

  return {
    cacheStrategy: options.cacheStrategy ?? "database",
    nonceStore: {
      async consume(key, ttlSec) {
        const now = Date.now()
        for (const [candidate, expiry] of nonceExpiries) {
          if (expiry <= now) {
            nonceExpiries.delete(candidate)
          }
        }

        const current = nonceExpiries.get(key)
        if (current && current > now) {
          return false
        }

        nonceExpiries.set(key, now + ttlSec * 1000)
        return true
      }
    },
    verificationCache: {
      async get(signatureHeader) {
        await options.onCacheGet?.(signatureHeader)
        const record = cache.get(signatureHeader)
        if (!record || record.expiresAt <= Date.now()) {
          cache.delete(signatureHeader)
          return null
        }

        return record.value
      },

      async set(signatureHeader, value, ttlSec) {
        cache.set(signatureHeader, {
          value,
          expiresAt: Date.now() + ttlSec * 1000
        })
      },

      async delete(signatureHeader) {
        cache.delete(signatureHeader)
      }
    },
    invalidationStore: {
      async getNotBefore() {
        return options.invalidatedAfter ?? null
      }
    },
    close: async () => {
      await options.onClose?.()
    }
  }
}

describe("playground erc8128 runtime", () => {
  test("closes request-scoped resources with the runtime", async () => {
    let closed = false

    const runtime = createVerificationRuntime(
      createRuntimeConfig({
        onClose: () => {
          closed = true
        }
      }),
      "https://erc8128.org",
      async () => true
    )

    await runtime.close()

    expect(closed).toBe(true)
  })

  test("accepts DELETE /verify as request-bound non-replayable", async () => {
    const runtime = createVerificationRuntime(
      createRuntimeConfig(),
      "https://erc8128.org",
      async () => true
    )

    const request = await signRequest(
      "https://erc8128.org/verify",
      {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ storeId: 1, productId: 42, quantity: 2 })
      },
      TEST_SIGNER,
      {
        binding: "request-bound",
        nonce: `nonce-${Date.now()}`,
        components: ["content-digest"]
      }
    )

    const result = await runtime.verifyRequest(request)

    expect(result.cachedVerification).toBe(false)
    expect(result.result.ok).toBe(true)
    if (!result.result.ok) {
      throw new Error("Expected request verification to succeed")
    }

    expect(result.result).toMatchObject({
      principal: { address: TEST_SIGNER_VERIFIED_ADDRESS, chainId: 1 },
      signer: { address: TEST_SIGNER_VERIFIED_ADDRESS, chainId: 1 },
      delegated: false,
      binding: "request-bound",
      replay: "non-replayable"
    })
  })

  test("accepts replayable class-bound POST /verify", async () => {
    const runtime = createVerificationRuntime(
      createRuntimeConfig(),
      "https://erc8128.org",
      async () => true
    )

    const request = await signRequest(
      "https://erc8128.org/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ok: true })
      },
      TEST_SIGNER,
      {
        binding: "class-bound",
        nonce: null,
        components: ["@authority"]
      }
    )

    const result = await runtime.verifyRequest(request)

    expect(result.result.ok).toBe(true)
    if (!result.result.ok) {
      throw new Error("Expected request verification to succeed")
    }

    expect(result.result).toMatchObject({
      principal: { address: TEST_SIGNER_VERIFIED_ADDRESS, chainId: 1 },
      signer: { address: TEST_SIGNER_VERIFIED_ADDRESS, chainId: 1 },
      delegated: false,
      binding: "class-bound",
      replay: "replayable"
    })
  })

  test("returns cachedVerification for repeated replayable requests", async () => {
    let verifyCalls = 0
    const runtime = createVerificationRuntime(
      createRuntimeConfig(),
      "https://erc8128.org",
      async () => {
        verifyCalls += 1
        return true
      }
    )

    const request = await signRequest(
      "https://erc8128.org/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ok: true })
      },
      TEST_SIGNER,
      {
        binding: "class-bound",
        nonce: null,
        components: ["@authority"]
      }
    )

    const first = await runtime.verifyRequest(request.clone())
    const second = await runtime.verifyRequest(request)

    expect(first.result.ok).toBe(true)
    expect(first.cachedVerification).toBe(false)
    expect(second.result.ok).toBe(true)
    expect(second.cachedVerification).toBe(true)
    expect(verifyCalls).toBe(1)
  })

  test("does not reuse a cached signature for a modified request", async () => {
    let verifyCalls = 0
    const runtime = createVerificationRuntime(
      createRuntimeConfig(),
      "https://erc8128.org",
      async () => {
        verifyCalls += 1
        return true
      }
    )
    const signed = await signRequest(
      "https://erc8128.org/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ amount: 1 })
      },
      TEST_SIGNER,
      {
        binding: "class-bound",
        nonce: null,
        components: ["@authority"]
      }
    )

    const first = await runtime.verifyRequest(signed.clone())
    const modified = await runtime.verifyRequest(
      new Request(signed.url, {
        method: "PUT",
        headers: signed.headers,
        body: JSON.stringify({ amount: 2 })
      })
    )

    expect(first.result.ok).toBe(true)
    expect(modified.cachedVerification).toBe(false)
    expect(modified.result).toEqual({
      ok: false,
      reason: "bad_content_digest"
    })
    expect(verifyCalls).toBe(1)
  })

  test("rejects a storage-mode header changed after signing", async () => {
    const runtime = createVerificationRuntime(
      createRuntimeConfig(),
      "https://erc8128.org",
      verifyMessage
    )
    const signed = await signRequest(
      "https://erc8128.org/verify",
      {
        method: "DELETE",
        headers: { "x-erc8128-storage": "postgres" }
      },
      REAL_SIGNER,
      {
        components: ["x-erc8128-storage"],
        nonce: `storage-${Date.now()}`
      }
    )
    const headers = new Headers(signed.headers)
    headers.set("x-erc8128-storage", "redis")
    const result = await runtime.verifyRequest(new Request(signed, { headers }))

    expect(result.result.ok).toBe(false)
    expect(result.result).toMatchObject({ reason: "bad_signature" })
  })

  test("skips verification cache for nonce-bearing POST /verify", async () => {
    let cacheGetCalls = 0
    const runtime = createVerificationRuntime(
      createRuntimeConfig({
        onCacheGet: () => {
          cacheGetCalls += 1
        }
      }),
      "https://erc8128.org",
      async () => true
    )

    const request = await signRequest(
      "https://erc8128.org/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ok: true })
      },
      TEST_SIGNER,
      {
        binding: "request-bound",
        nonce: `nonce-${Date.now()}`,
        components: ["content-digest"]
      }
    )

    const result = await runtime.verifyRequest(request)

    expect(result.result.ok).toBe(true)
    expect(cacheGetCalls).toBe(0)
  })

  test("rejects requests signed for a different path", async () => {
    const runtime = createVerificationRuntime(
      createRuntimeConfig(),
      "https://erc8128.org",
      verifyMessage
    )

    const signed = await signRequest(
      "https://erc8128.org/api/auth/verify",
      {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ storeId: 1, productId: 42, quantity: 2 })
      },
      REAL_SIGNER,
      {
        binding: "request-bound",
        nonce: `nonce-${Date.now()}`,
        components: ["content-digest"]
      }
    )

    const request = new Request("https://erc8128.org/verify", {
      method: signed.method,
      headers: signed.headers,
      body: JSON.stringify({ storeId: 1, productId: 42, quantity: 2 })
    })

    const result = await runtime.verifyRequest(request)

    expect(result.result.ok).toBe(false)
    if (result.result.ok) {
      throw new Error("Expected request verification to fail")
    }

    expect(result.result).toMatchObject({
      reason: "bad_signature"
    })
  })
})
