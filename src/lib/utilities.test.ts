import { describe, expect, test } from "bun:test"
import { Eip8128Error } from "./types.js"
import {
  base64Decode,
  base64Encode,
  base64UrlEncode,
  bytesToHex,
  hexToBytes,
  isEthHttpSigner,
  readBodyBytes,
  sanitizeUrl,
  sha256,
  toRequest,
  unixNow,
  utf8Encode
} from "./utilities.js"

describe("toRequest", () => {
  test("creates Request from URL string", () => {
    const req = toRequest("https://example.com")
    expect(req).toBeInstanceOf(Request)
    expect(req.url).toBe("https://example.com/")
  })

  test("returns existing Request unchanged when no init", () => {
    const original = new Request("https://example.com")
    const result = toRequest(original)
    expect(result).toBe(original)
  })

  test("creates new Request when init is provided", () => {
    const original = new Request("https://example.com")
    const result = toRequest(original, { method: "POST" })
    expect(result).not.toBe(original)
    expect(result.method).toBe("POST")
  })

  test("applies init headers", () => {
    const result = toRequest("https://example.com", {
      headers: { "x-foo": "bar" }
    })
    expect(result.headers.get("x-foo")).toBe("bar")
  })
})

describe("isEthHttpSigner", () => {
  test("returns true for valid signer object", () => {
    expect(
      isEthHttpSigner({
        chainId: 1,
        address: "0x0000000000000000000000000000000000000001",
        signMessage: async () => "0x"
      })
    ).toBe(true)
  })

  test("returns false for null", () => {
    expect(isEthHttpSigner(null)).toBe(false)
  })

  test("returns false for undefined", () => {
    expect(isEthHttpSigner(undefined)).toBe(false)
  })

  test("returns false for string", () => {
    expect(isEthHttpSigner("not a signer")).toBe(false)
  })

  test("returns false for number", () => {
    expect(isEthHttpSigner(42)).toBe(false)
  })

  test("returns false for object without signMessage", () => {
    expect(isEthHttpSigner({ chainId: 1, address: "0x01" })).toBe(false)
  })

  test("returns false for object with non-function signMessage", () => {
    expect(
      isEthHttpSigner({ chainId: 1, address: "0x01", signMessage: "not-fn" })
    ).toBe(false)
  })

  test("returns true as long as signMessage is a function (duck typing)", () => {
    expect(isEthHttpSigner({ signMessage: () => {} })).toBe(true)
  })
})

describe("sanitizeUrl", () => {
  test("parses a valid absolute URL", () => {
    const url = sanitizeUrl("https://example.com/path?q=1")
    expect(url.hostname).toBe("example.com")
    expect(url.pathname).toBe("/path")
    expect(url.search).toBe("?q=1")
  })

  test("throws Eip8128Error for relative URL", () => {
    expect(() => sanitizeUrl("/relative")).toThrow(Eip8128Error)
  })

  test("throws Eip8128Error for empty string", () => {
    expect(() => sanitizeUrl("")).toThrow(Eip8128Error)
  })

  test("throws Eip8128Error for invalid URL", () => {
    expect(() => sanitizeUrl("not a url")).toThrow(Eip8128Error)
  })
})

describe("unixNow", () => {
  test("returns an integer", () => {
    const now = unixNow()
    expect(Number.isInteger(now)).toBe(true)
  })

  test("is in seconds (not milliseconds)", () => {
    const now = unixNow()
    expect(Math.abs(now - Math.floor(Date.now() / 1000))).toBeLessThanOrEqual(1)
  })
})

describe("utf8Encode", () => {
  test("encodes ASCII string", () => {
    const bytes = utf8Encode("hello")
    expect(bytes).toEqual(new Uint8Array([104, 101, 108, 108, 111]))
  })

  test("encodes empty string", () => {
    const bytes = utf8Encode("")
    expect(bytes).toEqual(new Uint8Array([]))
  })

  test("encodes multi-byte characters", () => {
    const bytes = utf8Encode("€")
    expect(bytes.length).toBe(3)
  })
})

describe("base64Encode / base64Decode", () => {
  test("round-trips empty bytes", () => {
    const encoded = base64Encode(new Uint8Array([]))
    expect(encoded).toBe("")
    const decoded = base64Decode(encoded)
    expect(decoded).toEqual(new Uint8Array([]))
  })

  test("round-trips single byte", () => {
    const original = new Uint8Array([0xff])
    const encoded = base64Encode(original)
    const decoded = base64Decode(encoded)
    expect(decoded).toEqual(original)
  })

  test("round-trips two bytes", () => {
    const original = new Uint8Array([0xab, 0xcd])
    const encoded = base64Encode(original)
    const decoded = base64Decode(encoded)
    expect(decoded).toEqual(original)
  })

  test("round-trips three bytes (no padding)", () => {
    const original = new Uint8Array([1, 2, 3])
    const encoded = base64Encode(original)
    expect(encoded).not.toContain("=")
    const decoded = base64Decode(encoded)
    expect(decoded).toEqual(original)
  })

  test("produces correct padding for 1 byte", () => {
    const encoded = base64Encode(new Uint8Array([0]))
    expect(encoded).toMatch(/==$/)
  })

  test("produces correct padding for 2 bytes", () => {
    const encoded = base64Encode(new Uint8Array([0, 0]))
    expect(encoded).toMatch(/=(?!=)$/)
  })

  test("encodes known value", () => {
    const encoded = base64Encode(new TextEncoder().encode("hello"))
    expect(encoded).toBe("aGVsbG8=")
  })

  test("decodes known value", () => {
    const decoded = base64Decode("aGVsbG8=")
    expect(decoded).toEqual(new TextEncoder().encode("hello"))
  })

  test("decode returns null for invalid base64 (bad chars)", () => {
    expect(base64Decode("!!!")).toBeNull()
  })

  test("decode handles base64 without padding", () => {
    const decoded = base64Decode("aGVsbG8")
    expect(decoded).toEqual(new TextEncoder().encode("hello"))
  })

  test("round-trips larger payload", () => {
    const original = new Uint8Array(256)
    for (let i = 0; i < 256; i++) original[i] = i
    const encoded = base64Encode(original)
    const decoded = base64Decode(encoded)
    expect(decoded).toEqual(original)
  })
})

describe("base64UrlEncode", () => {
  test("replaces + with - and / with _", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe])
    const urlEncoded = base64UrlEncode(bytes)
    expect(urlEncoded).not.toContain("+")
    expect(urlEncoded).not.toContain("/")
  })

  test("strips trailing = padding", () => {
    const encoded = base64UrlEncode(new Uint8Array([0]))
    expect(encoded).not.toContain("=")
  })

  test("encodes empty input as empty string", () => {
    expect(base64UrlEncode(new Uint8Array([]))).toBe("")
  })
})

describe("hexToBytes / bytesToHex", () => {
  test("round-trips hex string", () => {
    const hex = "0xdeadbeef" as const
    const bytes = hexToBytes(hex)
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
    expect(bytesToHex(bytes)).toBe("0xdeadbeef")
  })

  test("handles empty hex (0x only)", () => {
    const bytes = hexToBytes("0x")
    expect(bytes).toEqual(new Uint8Array([]))
    expect(bytesToHex(bytes)).toBe("0x")
  })

  test("hexToBytes throws on odd-length hex", () => {
    expect(() => hexToBytes("0xabc")).toThrow(Eip8128Error)
  })

  test("bytesToHex pads single digits", () => {
    const hex = bytesToHex(new Uint8Array([0, 1, 15]))
    expect(hex).toBe("0x00010f")
  })

  test("round-trips all byte values", () => {
    const original = new Uint8Array(256)
    for (let i = 0; i < 256; i++) original[i] = i
    const hex = bytesToHex(original)
    const roundTripped = hexToBytes(hex)
    expect(roundTripped).toEqual(original)
  })
})

describe("sha256", () => {
  test("hashes empty input", async () => {
    const hash = await sha256(new Uint8Array([]))
    expect(bytesToHex(hash)).toBe(
      "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
  })

  test("hashes 'hello'", async () => {
    const hash = await sha256(new TextEncoder().encode("hello"))
    expect(bytesToHex(hash)).toBe(
      "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
  })

  test("returns 32 bytes", async () => {
    const hash = await sha256(new Uint8Array([1, 2, 3]))
    expect(hash.length).toBe(32)
  })
})

describe("readBodyBytes", () => {
  test("reads body from request", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "hello"
    })
    const bytes = await readBodyBytes(req)
    expect(bytes).toEqual(new TextEncoder().encode("hello"))
  })

  test("reads empty body", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: ""
    })
    const bytes = await readBodyBytes(req)
    expect(bytes).toEqual(new Uint8Array([]))
  })

  test("does not consume original request body (clones)", async () => {
    const req = new Request("https://example.com", {
      method: "POST",
      body: "test"
    })
    await readBodyBytes(req)
    const text = await req.text()
    expect(text).toBe("test")
  })
})
