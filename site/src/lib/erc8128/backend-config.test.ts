import { describe, expect, test } from "bun:test"
import { signRequest } from "@slicekit/erc8128"
import { getAuthInstance } from "./backend-config"

const TEST_SIGNER = {
  address: "0x000000000000000000000000000000000000dEaD",
  chainId: 1,
  async signMessage() {
    return `0x${"11".repeat(65)}` as const
  }
}

describe("playground better-auth integration", () => {
  test("accepts POST requests with JSON body when content-digest is not covered", async () => {
    const auth = getAuthInstance(
      "postgres",
      async () => true,
      "https://erc8128.org"
    )

    const request = await signRequest(
      "https://erc8128.org/api/auth/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ storeId: 1, productId: 42, quantity: 2 })
      },
      TEST_SIGNER,
      {
        binding: "class-bound",
        replay: "non-replayable",
        nonce: `nonce-${Date.now()}`,
        components: ["@method", "@path"]
      }
    )

    const response = await auth.handler(request)

    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({
      ok: true,
      binding: "class-bound",
      replayable: false
    })
  })

  test("accepts POST requests with JSON body when content-digest is covered", async () => {
    const auth = getAuthInstance(
      "postgres",
      async () => true,
      "https://erc8128.org"
    )

    const request = await signRequest(
      "https://erc8128.org/api/auth/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ storeId: 1, productId: 42, quantity: 2 })
      },
      TEST_SIGNER,
      {
        binding: "class-bound",
        replay: "non-replayable",
        nonce: `nonce-${Date.now()}`,
        components: ["@method", "@path", "content-digest"]
      }
    )

    const response = await auth.handler(request)

    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({
      ok: true,
      binding: "request-bound",
      replayable: false
    })
  })
})
