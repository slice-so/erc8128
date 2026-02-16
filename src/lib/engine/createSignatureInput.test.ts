import { describe, expect, test } from "bun:test"
import { Erc8128Error } from "../types.js"
import {
  assertLabel,
  parseSignatureDictionary,
  parseSignatureInputDictionary
} from "./createSignatureInput.js"

describe("assertLabel", () => {
  test("accepts valid lowercase labels", () => {
    expect(() => assertLabel("eth")).not.toThrow()
    expect(() => assertLabel("a")).not.toThrow()
    expect(() => assertLabel("my-label")).not.toThrow()
    expect(() => assertLabel("my_label")).not.toThrow()
    expect(() => assertLabel("my.label")).not.toThrow()
    expect(() => assertLabel("a123")).not.toThrow()
  })

  test("rejects uppercase labels", () => {
    expect(() => assertLabel("ETH")).toThrow(Erc8128Error)
    expect(() => assertLabel("Eth")).toThrow(Erc8128Error)
  })

  test("rejects labels starting with number", () => {
    expect(() => assertLabel("1eth")).toThrow(Erc8128Error)
  })

  test("rejects empty string", () => {
    expect(() => assertLabel("")).toThrow(Erc8128Error)
  })

  test("rejects labels with spaces", () => {
    expect(() => assertLabel("my label")).toThrow(Erc8128Error)
  })
})

describe("parseSignatureInputDictionary", () => {
  test("parses single member", () => {
    const input =
      'eth=("@authority" "@method" "@path");created=1700000000;expires=1700000060;keyid="erc8128:1:0x0000000000000000000000000000000000000001"'
    const result = parseSignatureInputDictionary(input)
    expect(result).toHaveLength(1)
    expect(result[0].label).toBe("eth")
    expect(result[0].components).toEqual(["@authority", "@method", "@path"])
    expect(result[0].params.created).toBe(1700000000)
    expect(result[0].params.expires).toBe(1700000060)
    expect(result[0].params.keyid).toBe(
      "erc8128:1:0x0000000000000000000000000000000000000001"
    )
  })

  test("parses multiple members", () => {
    const input =
      'a=("@authority");created=100;expires=200;keyid="k1", b=("@method");created=300;expires=400;keyid="k2"'
    const result = parseSignatureInputDictionary(input)
    expect(result).toHaveLength(2)
    expect(result[0].label).toBe("a")
    expect(result[1].label).toBe("b")
  })

  test("parses nonce parameter", () => {
    const input =
      'eth=("@authority");created=100;expires=200;nonce="abc123";keyid="k"'
    const result = parseSignatureInputDictionary(input)
    expect(result[0].params.nonce).toBe("abc123")
  })

  test("parses tag parameter", () => {
    const input =
      'eth=("@authority");created=100;expires=200;tag="v1";keyid="k"'
    const result = parseSignatureInputDictionary(input)
    expect(result[0].params.tag).toBe("v1")
  })

  test("throws on missing = in member", () => {
    expect(() => parseSignatureInputDictionary("not-a-dictionary")).toThrow(
      Erc8128Error
    )
  })

  test("throws on invalid label", () => {
    expect(() =>
      parseSignatureInputDictionary(
        'BAD=("@authority");created=100;expires=200;keyid="k"'
      )
    ).toThrow(Erc8128Error)
  })

  test("throws on missing inner list open paren", () => {
    expect(() =>
      parseSignatureInputDictionary(
        'eth="@authority";created=100;expires=200;keyid="k"'
      )
    ).toThrow(Erc8128Error)
  })

  test("throws on empty inner list", () => {
    expect(() =>
      parseSignatureInputDictionary('eth=();created=100;expires=200;keyid="k"')
    ).toThrow(Erc8128Error)
  })

  test("throws on missing created/expires/keyid", () => {
    expect(() => parseSignatureInputDictionary('eth=("@authority")')).toThrow(
      Erc8128Error
    )
  })

  test("preserves raw signatureParamsValue", () => {
    const input =
      'eth=("@authority" "@method");created=100;expires=200;keyid="k"'
    const result = parseSignatureInputDictionary(input)
    expect(result[0].signatureParamsValue).toBe(
      '("@authority" "@method");created=100;expires=200;keyid="k"'
    )
  })

  test("handles escaped quotes in sf-string values", () => {
    const input = 'eth=("@authority");created=100;expires=200;keyid="key\\"id"'
    const result = parseSignatureInputDictionary(input)
    expect(result[0].params.keyid).toBe('key"id')
  })

  test("handles commas inside quoted strings without splitting", () => {
    const input = 'eth=("@authority");created=100;expires=200;keyid="a,b"'
    const result = parseSignatureInputDictionary(input)
    expect(result).toHaveLength(1)
    expect(result[0].params.keyid).toBe("a,b")
  })
})

describe("parseSignatureDictionary", () => {
  test("parses single signature", () => {
    const result = parseSignatureDictionary("eth=:aGVsbG8=:")
    expect(result.size).toBe(1)
    expect(result.get("eth")).toBe("aGVsbG8=")
  })

  test("parses multiple signatures", () => {
    const result = parseSignatureDictionary("a=:AAAA:, b=:BBBB:")
    expect(result.size).toBe(2)
    expect(result.get("a")).toBe("AAAA")
    expect(result.get("b")).toBe("BBBB")
  })

  test("throws on missing = in member", () => {
    expect(() => parseSignatureDictionary("garbage")).toThrow(Erc8128Error)
  })

  test("throws on invalid binary item (no colons)", () => {
    expect(() => parseSignatureDictionary("eth=hello")).toThrow(Erc8128Error)
  })

  test("throws on invalid base64 in binary item", () => {
    expect(() => parseSignatureDictionary("eth=:!!!:")).toThrow(Erc8128Error)
  })

  test("throws on invalid label", () => {
    expect(() => parseSignatureDictionary("BAD=:aGVsbG8=:")).toThrow(
      Erc8128Error
    )
  })
})
