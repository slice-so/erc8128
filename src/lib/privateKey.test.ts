import { describe, expect, test } from "bun:test"
import { assertErc8128PrivateKey } from "./privateKey"

describe("assertErc8128PrivateKey", () => {
  test("returns well-formed keys unchanged", () => {
    const key = `0x${"ab".repeat(32)}` as const
    expect(assertErc8128PrivateKey(key)).toBe(key)
  })

  test("rejects malformed keys with the configured name", () => {
    expect(() => assertErc8128PrivateKey("0x1234", "signer key")).toThrow(
      "Invalid signer key"
    )
    expect(() => assertErc8128PrivateKey(`0x${"ab".repeat(31)}`)).toThrow(
      "Invalid ERC-8128 private key"
    )
  })
})
