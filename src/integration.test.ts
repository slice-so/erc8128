import { describe, expect, test } from "bun:test"
import { createPublicClient, http } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { mainnet } from "viem/chains"
import {
  type EthHttpSigner,
  type NonceStore,
  signRequest,
  verifyRequest
} from "./index.js"

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

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http()
})

const seen = new Set<string>()
const nonceStore: NonceStore = {
  consume: async (key: string) => {
    if (seen.has(key)) return false
    seen.add(key)
    return true
  }
}

describe("EIP-8128 signRequest/verifyRequest", () => {
  test("round-trips request-bound POST (auto content-digest, non-replayable nonce)", async () => {
    const signed = await signRequest(
      "https://api.example.com/orders",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ side: "buy", amount: "1.5" })
      },
      signer
    )

    const result = await verifyRequest(signed, {
      nonceStore,
      verifyMessage: publicClient.verifyMessage
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
