import { describe, expect, test } from "bun:test"
import { signRequest, verifyRequest } from "@slicekit/erc8128"
import { MAX_VERIFY_BODY_BYTES } from "./lib/erc8128/constants"
import worker, {
  bufferVerificationRequest,
  getVerifyMessage,
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
    ["unset", undefined, "postgres", false],
    ["disabled", "false", "postgres", false],
    ["enabled", "true", "redis", true]
  ] as const)(
    "resolves storage overrides when the development flag is %s",
    (_state, flag, expectedMode, expectedOverride) => {
      const result = resolveStorageSelection(
        {
          ERC8128_DEV_STORAGE_OVERRIDE: flag,
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
    const payload = (await response.json()) as {
      detail: string
      reason: string
    }

    expect(response.status).toBe(503)
    expect(response.headers.get("content-type")).toContain(
      "application/problem+json"
    )
    expect(payload.reason).toBe("signature_verification_unavailable")
    expect(payload.detail).not.toContain("ERC8128_SECRET_ALCHEMY_ID")
  })

  test("skips Postgres cleanup for a Redis-only deployment", () => {
    let waitUntilCalls = 0
    worker.scheduled(
      {
        cron: "*/15 * * * *",
        noRetry() {},
        scheduledTime: Date.now(),
        type: "scheduled"
      } as ScheduledController,
      Object.assign({} as CloudflareBindings, {
        ERC8128_STORAGE_MODE: "redis"
      }),
      {
        ...executionContext,
        waitUntil() {
          waitUntilCalls += 1
        }
      }
    )

    expect(waitUntilCalls).toBe(0)
  })

  test("reuses the verification client for the same RPC secret", () => {
    const first = getVerifyMessage({ ERC8128_SECRET_ALCHEMY_ID: "test-id" })
    const second = getVerifyMessage({ ERC8128_SECRET_ALCHEMY_ID: " test-id " })
    const legacy = getVerifyMessage({ SECRET_ALCHEMY_KEY: "legacy-test-id" })

    expect(first).not.toBeNull()
    expect(second).toBe(first)
    expect(legacy).not.toBeNull()
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
