import { describe, expect, test } from "bun:test"
import { formatKeyId, parseKeyId } from "./keyId.js"
import { Erc8128Error } from "./types.js"

describe("formatKeyId", () => {
  test("formats a valid keyid", () => {
    expect(formatKeyId(1, "0x0000000000000000000000000000000000000001")).toBe(
      "erc8128:1:0x0000000000000000000000000000000000000001"
    )
  })

  test("lowercases the address", () => {
    expect(formatKeyId(1, "0xAbCdEf0000000000000000000000000000000001")).toBe(
      "erc8128:1:0xabcdef0000000000000000000000000000000001"
    )
  })

  test("supports large chain IDs", () => {
    expect(formatKeyId(137, "0x0000000000000000000000000000000000000001")).toBe(
      "erc8128:137:0x0000000000000000000000000000000000000001"
    )
  })

  test("throws on non-integer chainId", () => {
    expect(() =>
      formatKeyId(1.5, "0x0000000000000000000000000000000000000001")
    ).toThrow(Erc8128Error)
  })

  test("throws on NaN chainId", () => {
    expect(() =>
      formatKeyId(NaN, "0x0000000000000000000000000000000000000001")
    ).toThrow(Erc8128Error)
  })

  test("throws on Infinity chainId", () => {
    expect(() =>
      formatKeyId(Infinity, "0x0000000000000000000000000000000000000001")
    ).toThrow(Erc8128Error)
  })
})

describe("parseKeyId", () => {
  test("parses a valid keyid", () => {
    const result = parseKeyId(
      "erc8128:1:0x0000000000000000000000000000000000000001"
    )
    expect(result).toEqual({
      chainId: 1,
      address: "0x0000000000000000000000000000000000000001"
    })
  })

  test("parses with large chain ID", () => {
    const result = parseKeyId(
      "erc8128:42161:0xabcdef0000000000000000000000000000000001"
    )
    expect(result).toEqual({
      chainId: 42161,
      address: "0xabcdef0000000000000000000000000000000001"
    })
  })

  test("returns null for non-erc8128 prefix", () => {
    expect(
      parseKeyId("not-erc8128:1:0x0000000000000000000000000000000000000001")
    ).toBeNull()
  })

  test("returns null for missing address", () => {
    expect(parseKeyId("erc8128:1:")).toBeNull()
  })

  test("returns null for short address", () => {
    expect(parseKeyId("erc8128:1:0x0001")).toBeNull()
  })

  test("returns null for address without 0x prefix", () => {
    expect(
      parseKeyId("erc8128:1:0000000000000000000000000000000000000001")
    ).toBeNull()
  })

  test("returns null for empty string", () => {
    expect(parseKeyId("")).toBeNull()
  })

  test("returns null for completely invalid format", () => {
    expect(parseKeyId("garbage")).toBeNull()
  })

  test("returns null for missing chain ID", () => {
    expect(
      parseKeyId("erc8128::0x0000000000000000000000000000000000000001")
    ).toBeNull()
  })

  test("lowercases address", () => {
    const result = parseKeyId(
      "erc8128:1:0xAbCdEf0000000000000000000000000000000001"
    )
    expect(result).not.toBeNull()
    expect(result!.address).toBe("0xabcdef0000000000000000000000000000000001")
  })

  test("round-trips with formatKeyId", () => {
    const address = "0xabcdef0000000000000000000000000000000001"
    const keyid = formatKeyId(10, address)
    const parsed = parseKeyId(keyid)
    expect(parsed).toEqual({ chainId: 10, address })
  })
})
