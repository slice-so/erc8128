import { describe, expect, test } from "bun:test"
import { resolveNonce } from "./nonce.js"

describe("resolveNonce", () => {
  test("returns string nonce as-is", async () => {
    const nonce = await resolveNonce({ nonce: "my-nonce" })
    expect(nonce).toBe("my-nonce")
  })

  test("calls function nonce and returns its result", async () => {
    const nonce = await resolveNonce({
      nonce: async () => "fn-nonce"
    })
    expect(nonce).toBe("fn-nonce")
  })

  test("auto-generates a nonce when not provided", async () => {
    const nonce = await resolveNonce({})
    expect(typeof nonce).toBe("string")
    expect(nonce.length).toBeGreaterThan(0)
  })

  test("auto-generated nonces are unique", async () => {
    const nonces = await Promise.all(
      Array.from({ length: 10 }, () => resolveNonce({}))
    )
    const unique = new Set(nonces)
    expect(unique.size).toBe(10)
  })

  test("auto-generated nonce is base64url encoded (no +, /, =)", async () => {
    for (let i = 0; i < 20; i++) {
      const nonce = await resolveNonce({})
      expect(nonce).not.toContain("+")
      expect(nonce).not.toContain("/")
      expect(nonce).not.toContain("=")
    }
  })
})
