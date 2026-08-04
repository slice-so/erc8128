import { describe, expect, test } from "bun:test"
import { Erc8128Error } from "../Erc8128Error"
import {
  parseContentDigest,
  setContentDigestHeader,
  verifyContentDigest
} from "./contentDigest"

describe("parseContentDigest", () => {
  const zeroSha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

  test("parses valid sha-256 digest", () => {
    const result = parseContentDigest(`sha-256=:${zeroSha256}:`)
    expect(result).toEqual([{ alg: "sha-256", b64: zeroSha256 }])
  })

  test("rejects uppercase dictionary keys as non-canonical", () => {
    const result = parseContentDigest("SHA-256=:aGVsbG8=:")
    expect(result).toBeNull()
  })

  test("trims surrounding whitespace", () => {
    const result = parseContentDigest(`  sha-256=:${zeroSha256}:  `)
    expect(result).toEqual([{ alg: "sha-256", b64: zeroSha256 }])
  })

  test("returns null for empty string", () => {
    expect(parseContentDigest("")).toBeNull()
  })

  test("returns null for missing colons", () => {
    expect(parseContentDigest("sha-256=aGVsbG8=")).toBeNull()
  })

  test("returns null for malformed base64 (special chars)", () => {
    expect(parseContentDigest("sha-256=:!!!:")).toBeNull()
  })

  test("rejects supported members with the wrong digest length", () => {
    expect(parseContentDigest("sha-256=:YQ==:")).toBeNull()
    expect(parseContentDigest("sha-256=:AQID:")).toBeNull()
  })
})

describe("setContentDigestHeader", () => {
  test("mode=auto computes digest when header missing", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello"
    })
    const result = await setContentDigestHeader(req, "auto")
    const header = result.headers.get("content-digest")
    expect(header).toBeTruthy()
    expect(header).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/)
  })

  test("mode=auto preserves a verified existing header", async () => {
    const req = await setContentDigestHeader(
      new Request("https://example.com", {
        method: "POST",
        body: "hello"
      }),
      "recompute"
    )
    const result = await setContentDigestHeader(req, "auto")
    expect(result.headers.get("content-digest")).toBe(
      req.headers.get("content-digest")
    )
    expect(result).toBe(req)
  })

  test("mode=auto rejects a mismatched existing header", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello",
      headers: { "content-digest": "sha-256=:existing:" }
    })
    await expect(setContentDigestHeader(req, "auto")).rejects.toThrow(
      "does not match"
    )
  })

  test("mode=recompute overwrites existing header", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello",
      headers: { "content-digest": "sha-256=:wrong:" }
    })
    const result = await setContentDigestHeader(req, "recompute")
    const header = result.headers.get("content-digest")
    expect(header).not.toBe("sha-256=:wrong:")
    expect(header).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/)
  })

  test("mode=require throws when header missing", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello"
    })
    await expect(setContentDigestHeader(req, "require")).rejects.toThrow(
      Erc8128Error
    )
  })

  test("mode=off throws", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello"
    })
    await expect(setContentDigestHeader(req, "off")).rejects.toThrow(
      Erc8128Error
    )
  })

  test("computes correct SHA-256 for known input", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello"
    })
    const result = await setContentDigestHeader(req, "auto")
    const header = result.headers.get("content-digest")

    const expected = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("hello")
    )
    const expectedB64 = Buffer.from(expected).toString("base64")
    expect(header).toBe(`sha-256=:${expectedB64}:`)
  })
})

describe("verifyContentDigest", () => {
  test("returns true when digest matches body", async () => {
    const body = "test body"
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(body)
    )
    const b64 = Buffer.from(hash).toString("base64")

    const req = new Request("https://example.com", {
      method: "POST",
      body,
      headers: { "content-digest": `sha-256=:${b64}:` }
    })

    expect(await verifyContentDigest(req)).toBe(true)
  })

  test("returns false when digest does not match body", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "real body",
      headers: { "content-digest": "sha-256=:aGVsbG8=:" }
    })

    expect(await verifyContentDigest(req)).toBe(false)
  })

  test("returns false when header missing", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello"
    })

    expect(await verifyContentDigest(req)).toBe(false)
  })

  test("accepts a matching SHA-512 member", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello",
      headers: {
        "content-digest":
          "sha-512=:m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==:"
      }
    })

    expect(await verifyContentDigest(req)).toBe(true)
  })

  test("returns false for malformed header value", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello",
      headers: { "content-digest": "not-valid" }
    })

    expect(await verifyContentDigest(req)).toBe(false)
  })
})
