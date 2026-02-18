/**
 * Docs example validation — ensures the README quick-start examples compile and work.
 * Uses the same local RPC as sign-verify.test.ts for consistency.
 */
import { describe, expect, test } from "bun:test"
import { createPublicClient, http } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import {
  createSignerClient,
  createVerifierClient,
  type EthHttpSigner,
  type NonceStore,
  signRequest,
  verifyRequest
} from "./index.js"

const publicClient = createPublicClient({
  transport: http("http://localhost:8787")
})

const account = privateKeyToAccount(
  "0x0123456789012345678901234567890123456789012345678901234567890123"
)

const signer: EthHttpSigner = {
  chainId: 1,
  address: account.address,
  signMessage: async (message) => {
    return account.signMessage({ message: { raw: message } })
  }
}

const seen = new Set<string>()
const nonceStore: NonceStore = {
  consume: async (key: string) => {
    if (seen.has(key)) return false
    seen.add(key)
    return true
  }
}

describe("docs: signRequest + verifyRequest example", () => {
  test("round-trips request-bound POST as shown in README", async () => {
    const signed = await signRequest(
      "https://api.example.com/orders",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ side: "buy", amount: "1.5" })
      },
      signer
    )

    const result = await verifyRequest({
      request: signed,
      verifyMessage: publicClient.verifyMessage,
      nonceStore
    })

    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error("unreachable")

    expect(result.address.toLowerCase()).toBe(account.address.toLowerCase())
    expect(result.chainId).toBe(1)
    expect(result.label).toBe("eth")
    expect(result.components).toEqual([
      "@authority",
      "@method",
      "@path",
      "content-digest"
    ])
  })
})

describe("docs: createSignerClient example", () => {
  test("client.signRequest works as shown in README", async () => {
    const client = createSignerClient(signer)

    const signed = await client.signRequest("https://api.example.com/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ amount: "100" })
    })

    expect(signed.headers.get("Signature-Input")).toBeTruthy()
    expect(signed.headers.get("Signature")).toBeTruthy()

    const result = await verifyRequest({
      request: signed,
      verifyMessage: publicClient.verifyMessage,
      nonceStore: { consume: async () => true }
    })
    expect(result.ok).toBe(true)
  })
})

describe("docs: createVerifierClient example", () => {
  test("verifier.verifyRequest works as shown in README", async () => {
    const signed = await signRequest(
      "https://api.example.com/orders",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amount: "100" })
      },
      signer
    )

    const verifier = createVerifierClient({
      verifyMessage: publicClient.verifyMessage,
      nonceStore: { consume: async () => true }
    })
    const result = await verifier.verifyRequest({ request: signed })
    expect(result.ok).toBe(true)
  })
})
