import { describe, expect, test } from "bun:test"
import { memoryAdapter } from "@slicekit/better-auth/adapters/memory"
import { signRequest } from "@slicekit/erc8128"
import { verifyMessage } from "viem"
import { type Address, privateKeyToAccount } from "viem/accounts"
import {
  type AuthBindings,
  type AuthRuntimeConfig,
  createAuthInstance,
  getAuthInstance,
  resolveVerifyPolicy
} from "./backend-config"

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

function createMemoryDb() {
  return {
    user: [] as Record<string, unknown>[],
    session: [] as Record<string, unknown>[],
    account: [] as Record<string, unknown>[],
    verification: [] as Record<string, unknown>[],
    walletAddress: [] as Record<string, unknown>[],
    erc8128Nonce: [] as Record<string, unknown>[],
    erc8128Invalidation: [] as Record<string, unknown>[]
  }
}

function createDatabaseRuntimeConfig(): AuthRuntimeConfig {
  return {
    cacheStrategy: "database",
    database: memoryAdapter(createMemoryDb())
  }
}

const TEST_BINDINGS: AuthBindings = {
  databaseUrl: "postgresql://user:password@127.0.0.1:5432/erc8128_test"
}

describe("playground better-auth integration", () => {
  test("returns fresh auth instances for the same mode and base URL", async () => {
    const verify = async () => true

    const first = await getAuthInstance(
      "postgres",
      "https://erc8128.org",
      TEST_BINDINGS,
      verify
    )
    const second = await getAuthInstance(
      "postgres",
      "https://erc8128.org/",
      TEST_BINDINGS,
      verify
    )

    expect(first).not.toBe(second)
  })

  test("closes request-scoped resources with the auth instance", async () => {
    let closedDatabase = false
    let closedSecondaryStorage = false

    const auth = createAuthInstance(
      {
        cacheStrategy: "secondary-storage",
        database: memoryAdapter(createMemoryDb()),
        secondaryStorage: {
          get: async () => null,
          set: async () => undefined,
          delete: async () => undefined,
          setIfNotExists: async () => true
        },
        closeDatabase: async () => {
          closedDatabase = true
        },
        closeSecondaryStorage: async () => {
          closedSecondaryStorage = true
        }
      },
      "https://erc8128.org",
      async () => true
    )

    await auth.close()

    expect(closedDatabase).toBe(true)
    expect(closedSecondaryStorage).toBe(true)
  })

  test("accepts DELETE /verify as request-bound non-replayable", async () => {
    const auth = createAuthInstance(
      createDatabaseRuntimeConfig(),
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
        replay: "non-replayable",
        nonce: `nonce-${Date.now()}`,
        components: ["content-digest"]
      }
    )

    const result = await auth.erc8128.protect(request)

    expect(result.ok).toBe(true)
    if (!result.ok) {
      throw new Error("Expected request protection to succeed")
    }

    expect(result.source).toBe("signature")
    expect(result.protected).toBe(true)
    expect(result.verification).toMatchObject({
      address: TEST_SIGNER_VERIFIED_ADDRESS,
      binding: "request-bound",
      replayable: false
    })
  })

  test("accepts replayable class-bound POST /verify", async () => {
    const auth = createAuthInstance(
      createDatabaseRuntimeConfig(),
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
        replay: "replayable",
        components: ["@authority"]
      }
    )

    const result = await auth.erc8128.protect(request)

    expect(result.ok).toBe(true)
    if (!result.ok) {
      throw new Error("Expected request protection to succeed")
    }

    expect(result.source).toBe("signature")
    expect(result.protected).toBe(true)
    expect(result.verification).toMatchObject({
      address: TEST_SIGNER_VERIFIED_ADDRESS,
      binding: "class-bound",
      replayable: true
    })
  })

  test("verifyRequest validates /verify signatures without creating wallet users", async () => {
    const db = createMemoryDb()
    const auth = createAuthInstance(
      {
        cacheStrategy: "database",
        database: memoryAdapter(db)
      },
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
        replay: "non-replayable",
        nonce: `nonce-${Date.now()}`,
        components: ["content-digest"]
      }
    )

    const { result } = await auth.verifyRequest(
      request,
      resolveVerifyPolicy(request.method)
    )

    expect(result.ok).toBe(true)
    expect(db.user).toHaveLength(0)
    expect(db.walletAddress).toHaveLength(0)
    expect(db.account).toHaveLength(0)
  })

  test("rejects unsigned requests on protected routes", async () => {
    const auth = createAuthInstance(
      createDatabaseRuntimeConfig(),
      "https://erc8128.org",
      async () => true
    )

    const result = await auth.erc8128.protect(
      new Request("https://erc8128.org/verify", {
        method: "GET"
      })
    )

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error("Expected request protection to fail")
    }

    expect(result.response.status).toBe(401)
    expect(await result.response.json()).toMatchObject({
      error: "erc8128_verification_failed",
      reason: "missing_signature"
    })
  })

  test("rejects requests signed for a different path", async () => {
    const auth = createAuthInstance(
      createDatabaseRuntimeConfig(),
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
        replay: "non-replayable",
        nonce: `nonce-${Date.now()}`,
        components: ["content-digest"]
      }
    )

    const request = new Request("https://erc8128.org/verify", {
      method: signed.method,
      headers: signed.headers,
      body: JSON.stringify({ storeId: 1, productId: 42, quantity: 2 })
    })

    const result = await auth.erc8128.protect(request)

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error("Expected request protection to fail")
    }

    expect(result.response.status).toBe(401)
    expect(await result.response.json()).toMatchObject({
      error: "erc8128_verification_failed",
      reason: "bad_signature"
    })
  })
})
