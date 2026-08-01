import { describe, expect, test } from "bun:test"
import { isValidNonce, resolveNonce } from "./nonce"

describe("resolveNonce", () => {
  test("returns string nonce as-is", async () => {
    const nonce = await resolveNonce({ nonce: "0123456789abcdef" })
    expect(nonce).toBe("0123456789abcdef")
  })

  test("calls function nonce and returns its result", async () => {
    const nonce = await resolveNonce({
      nonce: async () => "fedcba9876543210"
    })
    expect(nonce).toBe("fedcba9876543210")
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

  test("enforces the verifier-compatible nonce bounds", async () => {
    expect(isValidNonce("0123456789abcdef")).toBe(true)
    expect(isValidNonce("too-short")).toBe(false)
    expect(isValidNonce("x".repeat(129))).toBe(false)
    expect(isValidNonce("0123456789abcde\n")).toBe(false)

    await expect(resolveNonce({ nonce: "too-short" })).rejects.toThrow(
      "at least 128 bits"
    )
  })
})
