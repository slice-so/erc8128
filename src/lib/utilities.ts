import { sha256 as nobleSha256 } from "@noble/hashes/sha2"
import type { EthHttpSigner, Hex } from "./types.js"
import { Eip8128Error } from "./types.js"

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const BASE64_CODES = (() => {
  const codes = new Uint8Array(256)
  codes.fill(255)
  for (let i = 0; i < BASE64_ALPHABET.length; i++)
    codes[BASE64_ALPHABET.charCodeAt(i)] = i
  // URL-safe base64 variants.
  codes["-".charCodeAt(0)] = 62
  codes["_".charCodeAt(0)] = 63
  return codes
})()

export function toRequest(input: RequestInfo, init?: RequestInit): Request {
  if (input instanceof Request) return init ? new Request(input, init) : input
  return new Request(input, init)
}

export function isEthHttpSigner(value: unknown): value is EthHttpSigner {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as EthHttpSigner).signMessage === "function"
  )
}

export function sanitizeUrl(url: string): URL {
  try {
    return new URL(url)
  } catch {
    throw new Eip8128Error(
      "UNSUPPORTED_REQUEST",
      `Request.url must be absolute (got: ${url}).`
    )
  }
}

export function unixNow(): number {
  return Math.floor(Date.now() / 1000)
}

export function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

export function randomBytes(n: number): Uint8Array {
  const cryptoObj = globalThis.crypto
  if (!cryptoObj?.getRandomValues)
    throw new Eip8128Error(
      "CRYPTO_UNAVAILABLE",
      "crypto.getRandomValues required."
    )
  const out = new Uint8Array(n)
  cryptoObj.getRandomValues(out)
  return out
}

export async function readBodyBytes(request: Request): Promise<Uint8Array> {
  try {
    const clone = request.clone()
    const ab = await clone.arrayBuffer()
    return new Uint8Array(ab)
  } catch {
    throw new Eip8128Error(
      "BODY_READ_FAILED",
      "Failed to read request body (stream locked/disturbed)."
    )
  }
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  // Pure JS hash to avoid node:crypto/Buffer polyfills in browser bundles.
  return nobleSha256(bytes)
}

// Bytes-only base64 encoder; callers should UTF-8 encode text first.
export function base64Encode(bytes: Uint8Array): string {
  let out = ""
  let i = 0
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    out +=
      BASE64_ALPHABET[(n >> 18) & 63] +
      BASE64_ALPHABET[(n >> 12) & 63] +
      BASE64_ALPHABET[(n >> 6) & 63] +
      BASE64_ALPHABET[n & 63]
  }
  if (i === bytes.length) return out
  const n = bytes[i] << 16
  if (i + 1 < bytes.length) {
    const n2 = n | (bytes[i + 1] << 8)
    out +=
      BASE64_ALPHABET[(n2 >> 18) & 63] +
      BASE64_ALPHABET[(n2 >> 12) & 63] +
      BASE64_ALPHABET[(n2 >> 6) & 63] +
      "="
  } else {
    out +=
      BASE64_ALPHABET[(n >> 18) & 63] + BASE64_ALPHABET[(n >> 12) & 63] + "=="
  }
  return out
}

export function base64Decode(b64: string): Uint8Array | null {
  try {
    const cleaned = b64.trim().replace(/=+$/g, "")
    if (cleaned.length === 0) return new Uint8Array(0)
    if (cleaned.length % 4 === 1) return null
    const out = new Uint8Array(Math.floor((cleaned.length * 3) / 4))
    let buffer = 0
    let bits = 0
    let outIndex = 0
    for (let i = 0; i < cleaned.length; i++) {
      const code = BASE64_CODES[cleaned.charCodeAt(i)]
      if (code === 255) return null
      buffer = (buffer << 6) | code
      bits += 6
      if (bits >= 8) {
        bits -= 8
        out[outIndex++] = (buffer >> bits) & 255
      }
    }
    return outIndex === out.length ? out : out.slice(0, outIndex)
  } catch {
    return null
  }
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "")
}

export function hexToBytes(hex: Hex): Uint8Array {
  const h = hex.slice(2)
  if (h.length % 2 !== 0)
    throw new Eip8128Error("UNSUPPORTED_REQUEST", "Invalid hex length.")
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function bytesToHex(bytes: Uint8Array): Hex {
  let out = "0x"
  for (const b of bytes) out += b.toString(16).padStart(2, "0")
  return out as Hex
}
