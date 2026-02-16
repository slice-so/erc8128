import { describe, expect, test } from "bun:test"
import { Erc8128Error } from "../types.js"
import {
  parseContentDigest,
  setContentDigestHeader,
  verifyContentDigest
} from "./contentDigest.js"

describe("parseContentDigest", () => {
  test("parses valid sha-256 digest", () => {
    const result = parseContentDigest("sha-256=:aGVsbG8=:")
    expect(result).toEqual({ alg: "sha-256", b64: "aGVsbG8=" })
  })

  test("normalizes algorithm name to lowercase", () => {
    const result = parseContentDigest("SHA-256=:aGVsbG8=:")
    expect(result).toEqual({ alg: "sha-256", b64: "aGVsbG8=" })
  })

  test("trims surrounding whitespace", () => {
    const result = parseContentDigest("  sha-256=:aGVsbG8=:  ")
    expect(result).toEqual({ alg: "sha-256", b64: "aGVsbG8=" })
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

  test("handles base64 with padding", () => {
    const result = parseContentDigest("sha-256=:YQ==:")
    expect(result).toEqual({ alg: "sha-256", b64: "YQ==" })
  })

  test("handles base64 without padding", () => {
    const result = parseContentDigest("sha-256=:AQID:")
    expect(result).toEqual({ alg: "sha-256", b64: "AQID" })
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

  test("mode=auto preserves existing header", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello",
      headers: { "content-digest": "sha-256=:existing:" }
    })
    const result = await setContentDigestHeader(req, "auto")
    expect(result.headers.get("content-digest")).toBe("sha-256=:existing:")
    expect(result).toBe(req)
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

  test("returns false for unsupported algorithm", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello",
      headers: { "content-digest": "sha-512=:aGVsbG8=:" }
    })

    expect(await verifyContentDigest(req)).toBe(false)
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
