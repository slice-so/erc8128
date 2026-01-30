import { describe, expect, test } from "bun:test"
import { Eip8128Error } from "../types.js"
import {
  appendDictionaryMember,
  assertSignatureParamsForSerialization,
  defaultComponents,
  normalizeComponents,
  quoteSfString,
  resolveComponents,
  serializeSignatureHeader,
  serializeSignatureInputHeader,
  serializeSignatureParamsInnerList
} from "./serializations.js"

describe("quoteSfString", () => {
  test("quotes a simple string", () => {
    expect(quoteSfString("hello")).toBe('"hello"')
  })

  test("escapes backslashes", () => {
    expect(quoteSfString("a\\b")).toBe('"a\\\\b"')
  })

  test("escapes double quotes", () => {
    expect(quoteSfString('a"b')).toBe('"a\\"b"')
  })

  test("handles empty string", () => {
    expect(quoteSfString("")).toBe('""')
  })

  test("throws on control characters", () => {
    expect(() => quoteSfString("a\x00b")).toThrow(Eip8128Error)
    expect(() => quoteSfString("a\x1fb")).toThrow(Eip8128Error)
    expect(() => quoteSfString("a\x7fb")).toThrow(Eip8128Error)
  })

  test("allows visible ASCII and space", () => {
    expect(() => quoteSfString("hello world!@#$%^&*()")).not.toThrow()
  })
})

describe("normalizeComponents", () => {
  test("trims whitespace", () => {
    expect(normalizeComponents(["  @authority  ", " @method "])).toEqual([
      "@authority",
      "@method"
    ])
  })

  test("filters empty strings", () => {
    expect(normalizeComponents(["@authority", "", "  ", "@method"])).toEqual([
      "@authority",
      "@method"
    ])
  })

  test("handles empty array", () => {
    expect(normalizeComponents([])).toEqual([])
  })
})

describe("defaultComponents", () => {
  test("request-bound GET (no query, no body)", () => {
    expect(
      defaultComponents({
        binding: "request-bound",
        hasQuery: false,
        hasBody: false
      })
    ).toEqual(["@authority", "@method", "@path"])
  })

  test("request-bound GET with query", () => {
    expect(
      defaultComponents({
        binding: "request-bound",
        hasQuery: true,
        hasBody: false
      })
    ).toEqual(["@authority", "@method", "@path", "@query"])
  })

  test("request-bound POST with body", () => {
    expect(
      defaultComponents({
        binding: "request-bound",
        hasQuery: false,
        hasBody: true
      })
    ).toEqual(["@authority", "@method", "@path", "content-digest"])
  })

  test("request-bound POST with query and body", () => {
    expect(
      defaultComponents({
        binding: "request-bound",
        hasQuery: true,
        hasBody: true
      })
    ).toEqual(["@authority", "@method", "@path", "@query", "content-digest"])
  })

  test("class-bound always returns just @authority", () => {
    expect(
      defaultComponents({
        binding: "class-bound",
        hasQuery: true,
        hasBody: true
      })
    ).toEqual(["@authority"])
  })
})

describe("resolveComponents", () => {
  test("request-bound: derives default components from request shape", () => {
    expect(
      resolveComponents({
        binding: "request-bound",
        hasQuery: true,
        hasBody: false
      })
    ).toEqual(["@authority", "@method", "@path", "@query"])
  })

  test("request-bound: appends extra provided components", () => {
    expect(
      resolveComponents({
        binding: "request-bound",
        hasQuery: false,
        hasBody: false,
        providedComponents: ["content-type", "x-custom"]
      })
    ).toEqual(["@authority", "@method", "@path", "content-type", "x-custom"])
  })

  test("request-bound: does not duplicate base components", () => {
    expect(
      resolveComponents({
        binding: "request-bound",
        hasQuery: false,
        hasBody: false,
        providedComponents: ["@authority", "@method"]
      })
    ).toEqual(["@authority", "@method", "@path"])
  })

  test("class-bound: throws when no components provided", () => {
    expect(() =>
      resolveComponents({
        binding: "class-bound",
        hasQuery: false,
        hasBody: false
      })
    ).toThrow(Eip8128Error)
  })

  test("class-bound: prepends @authority if not included", () => {
    expect(
      resolveComponents({
        binding: "class-bound",
        hasQuery: false,
        hasBody: false,
        providedComponents: ["@method"]
      })
    ).toEqual(["@authority", "@method"])
  })

  test("class-bound: doesn't duplicate @authority if already provided", () => {
    expect(
      resolveComponents({
        binding: "class-bound",
        hasQuery: false,
        hasBody: false,
        providedComponents: ["@authority", "@method"]
      })
    ).toEqual(["@authority", "@method"])
  })
})

describe("assertSignatureParamsForSerialization", () => {
  test("passes for valid params", () => {
    expect(() =>
      assertSignatureParamsForSerialization({
        created: 1700000000,
        expires: 1700000060,
        keyid: "eip8128:1:0x0000000000000000000000000000000000000001"
      })
    ).not.toThrow()
  })

  test("throws when created is not integer", () => {
    expect(() =>
      assertSignatureParamsForSerialization({
        created: 1.5,
        expires: 100,
        keyid: "k"
      })
    ).toThrow(Eip8128Error)
  })

  test("throws when expires is not integer", () => {
    expect(() =>
      assertSignatureParamsForSerialization({
        created: 100,
        expires: 100.5,
        keyid: "k"
      })
    ).toThrow(Eip8128Error)
  })

  test("throws when expires <= created", () => {
    expect(() =>
      assertSignatureParamsForSerialization({
        created: 100,
        expires: 100,
        keyid: "k"
      })
    ).toThrow(Eip8128Error)

    expect(() =>
      assertSignatureParamsForSerialization({
        created: 100,
        expires: 50,
        keyid: "k"
      })
    ).toThrow(Eip8128Error)
  })

  test("throws when keyid is empty", () => {
    expect(() =>
      assertSignatureParamsForSerialization({
        created: 100,
        expires: 200,
        keyid: ""
      })
    ).toThrow(Eip8128Error)
  })
})

describe("serializeSignatureParamsInnerList", () => {
  test("serializes basic params without nonce", () => {
    const result = serializeSignatureParamsInnerList(
      ["@authority", "@method", "@path"],
      {
        created: 1700000000,
        expires: 1700000060,
        keyid: "eip8128:1:0x0000000000000000000000000000000000000001"
      }
    )
    expect(result).toBe(
      '("@authority" "@method" "@path");created=1700000000;expires=1700000060;keyid="eip8128:1:0x0000000000000000000000000000000000000001"'
    )
  })

  test("includes nonce when provided", () => {
    const result = serializeSignatureParamsInnerList(["@authority"], {
      created: 1700000000,
      expires: 1700000060,
      nonce: "abc123",
      keyid: "eip8128:1:0x0000000000000000000000000000000000000001"
    })
    expect(result).toContain(';nonce="abc123"')
  })

  test("includes tag when provided", () => {
    const result = serializeSignatureParamsInnerList(["@authority"], {
      created: 1700000000,
      expires: 1700000060,
      tag: "my-tag",
      keyid: "eip8128:1:0x0000000000000000000000000000000000000001"
    })
    expect(result).toContain(';tag="my-tag"')
  })

  test("orders params: created, expires, nonce, tag, keyid", () => {
    const result = serializeSignatureParamsInnerList(["@authority"], {
      created: 100,
      expires: 200,
      nonce: "n",
      tag: "t",
      keyid: "k"
    })
    const createdIdx = result.indexOf("created=")
    const expiresIdx = result.indexOf("expires=")
    const nonceIdx = result.indexOf("nonce=")
    const tagIdx = result.indexOf("tag=")
    const keyidIdx = result.indexOf("keyid=")
    expect(createdIdx).toBeLessThan(expiresIdx)
    expect(expiresIdx).toBeLessThan(nonceIdx)
    expect(nonceIdx).toBeLessThan(tagIdx)
    expect(tagIdx).toBeLessThan(keyidIdx)
  })
})

describe("serializeSignatureInputHeader", () => {
  test("formats label=value", () => {
    const result = serializeSignatureInputHeader(
      "eth",
      '("@authority");created=100;expires=200;keyid="k"'
    )
    expect(result).toBe('eth=("@authority");created=100;expires=200;keyid="k"')
  })

  test("throws on invalid label", () => {
    expect(() => serializeSignatureInputHeader("UPPER", "value")).toThrow(
      Eip8128Error
    )
    expect(() => serializeSignatureInputHeader("123", "value")).toThrow(
      Eip8128Error
    )
  })
})

describe("serializeSignatureHeader", () => {
  test("formats label=:base64:", () => {
    expect(serializeSignatureHeader("eth", "aGVsbG8=")).toBe("eth=:aGVsbG8=:")
  })

  test("throws on invalid base64", () => {
    expect(() => serializeSignatureHeader("eth", "!!!")).toThrow(Eip8128Error)
  })

  test("throws on invalid label", () => {
    expect(() => serializeSignatureHeader("BAD", "aGVsbG8=")).toThrow(
      Eip8128Error
    )
  })
})

describe("appendDictionaryMember", () => {
  test("returns member when existing is null", () => {
    expect(appendDictionaryMember(null, "new=value")).toBe("new=value")
  })

  test("appends with comma separator when existing present", () => {
    expect(appendDictionaryMember("a=1", "b=2")).toBe("a=1, b=2")
  })

  test("returns member when existing is empty string (falsy)", () => {
    expect(appendDictionaryMember("", "new=value")).toBe("new=value")
  })
})
