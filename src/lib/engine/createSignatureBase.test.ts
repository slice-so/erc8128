import { describe, expect, test } from "bun:test"
import { Erc8128Error } from "../types.js"
import { createSignatureBaseMinimal } from "./createSignatureBase.js"

function makeRequest(url: string, opts?: RequestInit): Request {
  return new Request(url, opts)
}

function decodeBase(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

describe("createSignatureBaseMinimal", () => {
  test("generates base for @authority only", () => {
    const req = makeRequest("https://example.com/path")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@authority"],
      signatureParamsValue: '("@authority");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@authority": example.com')
    expect(text).toContain(
      '"@signature-params": ("@authority");created=100;expires=200;keyid="k"'
    )
  })

  test("generates base for @method", () => {
    const req = makeRequest("https://example.com", { method: "POST" })
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@method"],
      signatureParamsValue: '("@method");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@method": POST')
  })

  test("@method defaults to GET", () => {
    const req = makeRequest("https://example.com")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@method"],
      signatureParamsValue: '("@method");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@method": GET')
  })

  test("generates base for @path", () => {
    const req = makeRequest("https://example.com/api/v1/orders")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@path"],
      signatureParamsValue: '("@path");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@path": /api/v1/orders')
  })

  test("@path defaults to / for root", () => {
    const req = makeRequest("https://example.com")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@path"],
      signatureParamsValue: '("@path");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@path": /')
  })

  test("generates base for @query", () => {
    const req = makeRequest("https://example.com/path?foo=bar&baz=1")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@query"],
      signatureParamsValue: '("@query");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@query": ?foo=bar&baz=1')
  })

  test("@query is empty string when no query", () => {
    const req = makeRequest("https://example.com/path")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@query"],
      signatureParamsValue: '("@query");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@query": ')
  })

  test("includes header component values", () => {
    const req = makeRequest("https://example.com", {
      headers: { "content-type": "application/json" }
    })
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["content-type"],
      signatureParamsValue: '("content-type");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"content-type": application/json')
  })

  test("throws on missing required header", () => {
    const req = makeRequest("https://example.com")
    expect(() =>
      createSignatureBaseMinimal({
        request: req,
        components: ["x-missing"],
        signatureParamsValue: '("x-missing");created=100;expires=200;keyid="k"'
      })
    ).toThrow(Erc8128Error)
  })

  test("canonicalizes header values (trims and collapses whitespace)", () => {
    const req = makeRequest("https://example.com", {
      headers: { "x-test": "  hello   world  " }
    })
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["x-test"],
      signatureParamsValue: '("x-test");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"x-test": hello world')
  })

  test("generates full signature base with multiple components", () => {
    const req = makeRequest("https://api.example.com/orders?limit=10", {
      method: "POST",
      headers: { "content-digest": "sha-256=:abc=:" }
    })
    const paramsValue =
      '("@authority" "@method" "@path" "@query" "content-digest");created=100;expires=200;keyid="k"'
    const base = createSignatureBaseMinimal({
      request: req,
      components: [
        "@authority",
        "@method",
        "@path",
        "@query",
        "content-digest"
      ],
      signatureParamsValue: paramsValue
    })
    const text = decodeBase(base)
    const lines = text.split("\n")
    expect(lines).toHaveLength(6)
    expect(lines[0]).toBe('"@authority": api.example.com')
    expect(lines[1]).toBe('"@method": POST')
    expect(lines[2]).toBe('"@path": /orders')
    expect(lines[3]).toBe('"@query": ?limit=10')
    expect(lines[4]).toBe('"content-digest": sha-256=:abc=:')
    expect(lines[5]).toContain('"@signature-params":')
  })

  test("@signature-params is always the last line", () => {
    const req = makeRequest("https://example.com")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@authority"],
      signatureParamsValue: '("@authority");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    const lines = text.split("\n")
    expect(lines[lines.length - 1]).toContain('"@signature-params"')
  })

  test("generates base with no components (signature-params only)", () => {
    const req = makeRequest("https://example.com")
    const base = createSignatureBaseMinimal({
      request: req,
      components: [],
      signatureParamsValue: '();created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toBe(
      '"@signature-params": ();created=100;expires=200;keyid="k"'
    )
  })

  test("@authority lowercases hostname", () => {
    const req = makeRequest("https://Example.COM/path")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@authority"],
      signatureParamsValue: '("@authority");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@authority": example.com')
  })

  test("@authority includes non-default port", () => {
    const req = makeRequest("https://example.com:8443/path")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@authority"],
      signatureParamsValue: '("@authority");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@authority": example.com:8443')
  })

  test("@authority omits default HTTPS port 443", () => {
    const req = makeRequest("https://example.com:443/path")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@authority"],
      signatureParamsValue: '("@authority");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@authority": example.com')
  })

  test("@authority omits default HTTP port 80", () => {
    const req = makeRequest("http://example.com:80/path")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@authority"],
      signatureParamsValue: '("@authority");created=100;expires=200;keyid="k"'
    })
    const text = decodeBase(base)
    expect(text).toContain('"@authority": example.com')
  })

  test("returns Uint8Array (UTF-8 encoded bytes)", () => {
    const req = makeRequest("https://example.com")
    const base = createSignatureBaseMinimal({
      request: req,
      components: ["@authority"],
      signatureParamsValue: '("@authority");created=100;expires=200;keyid="k"'
    })
    expect(base).toBeInstanceOf(Uint8Array)
  })
})
