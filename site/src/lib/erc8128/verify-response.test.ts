import { describe, expect, test } from "bun:test"
import { buildVerifyResultResponse } from "./verify-response"

const metadata = {
  cacheStrategy: "database" as const,
  cachedVerification: false,
  storageMode: "postgres" as const,
  verifyMs: 1
}

describe("playground verification responses", () => {
  test.each([
    ["signature_input_invalid" as const, 400],
    ["insufficient_permissions" as const, 403],
    ["signature_verification_unavailable" as const, 503],
    ["bad_signature" as const, 401]
  ] as const)(
    "maps %s with the shared problem-details formatter",
    (reason, status) => {
      const response = buildVerifyResultResponse({
        verifyResult: { ok: false, reason },
        responseHeaders: new Headers(),
        metadata
      })

      expect(response.status).toBe(status)
      expect(response.payload).toMatchObject({
        ok: false,
        reason,
        status
      })
    }
  )
})
