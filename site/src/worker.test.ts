import { describe, expect, test } from "bun:test"
import { signRequest, verifyRequest } from "@slicekit/erc8128"
import worker, {
  bufferVerificationRequest,
  getVerifyMessage,
  MAX_VERIFY_BODY_BYTES,
  resolveStorageSelection
} from "./worker"

const signer = {
  address: "0x1111111111111111111111111111111111111111" as const,
  chainId: 1,
  signMessage: async () => `0x${"11".repeat(65)}` as `0x${string}`
}

const executionContext = {
  passThroughOnException() {},
  props: {},
  waitUntil() {}
} as ExecutionContext

describe("playground worker request policy", () => {
  test("accepts a body just below the verification limit", async () => {
    const body = new Uint8Array(MAX_VERIFY_BODY_BYTES - 1)
    const rebuilt = await bufferVerificationRequest(
      new Request("https://erc8128.org/verify", { body, method: "POST" })
    )

    expect(rebuilt).not.toBeNull()
    expect((await rebuilt?.arrayBuffer())?.byteLength).toBe(body.byteLength)
  })

  test("rejects bodies over the limit even when content-length under-reports", async () => {
    const body = new Uint8Array(MAX_VERIFY_BODY_BYTES + 1)
    const overLimit = await bufferVerificationRequest(
      new Request("https://erc8128.org/verify", { body, method: "POST" })
    )
    const underReported = await bufferVerificationRequest(
      new Request("https://erc8128.org/verify", {
        body,
        headers: { "content-length": "1" },
        method: "POST"
      })
    )

    expect(overLimit).toBeNull()
    expect(underReported).toBeNull()
  })

  test("rebuilds a drained signed body for verification", async () => {
    const signed = await signRequest(
      "https://erc8128.org/verify",
      { body: "round trip", method: "POST" },
      signer,
      { nonce: "worker-round-trip" }
    )
    const rebuilt = await bufferVerificationRequest(signed)
    if (!rebuilt) throw new Error("Expected a rebuilt request")

    const result = await verifyRequest({
      request: rebuilt,
      verifyMessage: async () => true,
      nonceStore: { consume: async () => true }
    })

    expect(result.ok).toBe(true)
    expect(await rebuilt.clone().text()).toBe("round trip")
  })

  test.each([
    ["production", undefined, "postgres", false],
    ["production", "true", "postgres", false],
    ["development", undefined, "postgres", false],
    ["development", "true", "redis", true]
  ] as const)(
    "resolves %s storage overrides with flag %s",
    (environment, flag, expectedMode, expectedOverride) => {
      const result = resolveStorageSelection(
        {
          ERC8128_ENABLE_STORAGE_HEADER: flag,
          ERC8128_ENVIRONMENT: environment,
          ERC8128_STORAGE_MODE: "postgres"
        },
        new Headers({ "x-erc8128-storage": "redis" })
      )

      expect(result.storageMode).toBe(expectedMode)
      expect(result.allowHeaderOverride).toBe(expectedOverride)
    }
  )

  test("returns generic problem details for an oversized body", async () => {
    const response = await worker.fetch(
      new Request("https://erc8128.org/verify", {
        body: new Uint8Array(MAX_VERIFY_BODY_BYTES + 1),
        method: "POST"
      }),
      {} as CloudflareBindings,
      executionContext
    )
    const payload = (await response.json()) as {
      type: string
      title: string
      status: number
      detail: string
    }

    expect(response.status).toBe(413)
    expect(response.headers.get("content-type")).toContain(
      "application/problem+json"
    )
    expect(payload).toMatchObject({
      type: "https://erc8128.org/problems/request-body-too-large",
      title: "Request body is too large",
      status: 413
    })
  })

  test("exposes the effective storage policy to the playground", async () => {
    const response = await worker.fetch(
      new Request("https://erc8128.org/playground-config"),
      Object.assign({} as CloudflareBindings, {
        ERC8128_ENABLE_STORAGE_HEADER: "true" as const,
        ERC8128_ENVIRONMENT: "production" as const,
        ERC8128_STORAGE_MODE: "redis" as const
      }),
      executionContext
    )
    const payload = (await response.json()) as {
      storageMode: string
      storageOverrideEnabled: boolean
    }

    expect(payload).toEqual({
      storageMode: "redis",
      storageOverrideEnabled: false
    })
  })

  test("returns a scoped 503 when the verification RPC secret is absent", async () => {
    const response = await worker.fetch(
      new Request("https://erc8128.org/verify", { method: "POST" }),
      {} as CloudflareBindings,
      executionContext
    )
    const payload = (await response.json()) as { reason: string }

    expect(response.status).toBe(503)
    expect(payload.reason).toBe("signature_verification_unavailable")
  })

  test("reuses the verification client for the same RPC secret", () => {
    const first = getVerifyMessage({ ERC8128_SECRET_ALCHEMY_ID: "test-id" })
    const second = getVerifyMessage({ ERC8128_SECRET_ALCHEMY_ID: " test-id " })

    expect(first).not.toBeNull()
    expect(second).toBe(first)
    expect(getVerifyMessage({})).toBeNull()
  })

  test("keeps discovery available without an RPC secret", async () => {
    const response = await worker.fetch(
      new Request("https://erc8128.org/.well-known/erc8128"),
      {} as CloudflareBindings,
      executionContext
    )

    expect(response.status).toBe(200)
  })
})
