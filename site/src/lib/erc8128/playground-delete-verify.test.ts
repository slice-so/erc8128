import { describe, expect, test } from "bun:test"
import { signRequest } from "@slicekit/erc8128"
import { verifyMessage } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { verifyDeletePlaygroundRequest } from "./playground-delete-verify"

const account = privateKeyToAccount(
  "0x0123456789012345678901234567890123456789012345678901234567890123"
)

const signer = {
  address: account.address,
  chainId: 1,
  signMessage: async (message: Uint8Array) =>
    account.signMessage({ message: { raw: message } })
}

describe("verifyDeletePlaygroundRequest", () => {
  test("rejects class-bound DELETE requests", async () => {
    const request = await signRequest(
      "https://erc8128.org/verify",
      { method: "DELETE" },
      signer,
      {
        binding: "class-bound",
        replay: "non-replayable",
        nonce: "nonce-class-bound",
        components: ["@authority"]
      }
    )

    const result = await verifyDeletePlaygroundRequest({
      request,
      storageMode: "redis",
      verifyMessage
    })

    expect(result).toMatchObject({
      ok: false,
      reason: "not_request_bound"
    })
  })

  test("rejects replayable DELETE requests", async () => {
    const request = await signRequest(
      "https://erc8128.org/verify",
      { method: "DELETE" },
      signer,
      {
        binding: "class-bound",
        replay: "replayable",
        components: ["@authority"]
      }
    )

    const result = await verifyDeletePlaygroundRequest({
      request,
      storageMode: "redis",
      verifyMessage
    })

    expect(result).toMatchObject({
      ok: false,
      reason: "not_request_bound"
    })
  })

  test("accepts request-bound non-replayable DELETE requests on /verify", async () => {
    const request = await signRequest(
      "https://erc8128.org/verify",
      { method: "DELETE" },
      signer,
      {
        binding: "request-bound",
        replay: "non-replayable",
        nonce: "nonce-request-bound"
      }
    )

    const result = await verifyDeletePlaygroundRequest({
      request,
      storageMode: "redis",
      verifyMessage
    })

    expect(result).toMatchObject({
      ok: true,
      binding: "request-bound",
      replayable: false
    })
  })
})
