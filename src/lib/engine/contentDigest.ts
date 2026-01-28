import { type ContentDigestMode, Eip8128Error } from "../types.js"
import { base64Encode, readBodyBytes, sha256 } from "../utilities.js"

/**
 * Sets or validates the Content-Digest header on the request.
 *
 * @param mode - How to handle the Content-Digest header:
 *   - "auto": Use existing header if present, otherwise compute from body (default)
 *   - "recompute": Always recompute and overwrite existing header
 *   - "require": Require header to exist, throw if missing (does not compute)
 *   - "off": Disabled (throws if content-digest is in components)
 */
export async function setContentDigestHeader(
  request: Request,
  mode: ContentDigestMode
): Promise<Request> {
  const headers = new Headers(request.headers)
  const existing = headers.get("content-digest")

  if (mode === "off") {
    throw new Eip8128Error(
      "DIGEST_REQUIRED",
      "content-digest is required by covered components, but contentDigest='off'."
    )
  }
  if (mode === "require" && !existing) {
    throw new Eip8128Error(
      "DIGEST_REQUIRED",
      "content-digest is required but missing."
    )
  }
  if (existing && mode === "auto") return request

  const bodyBytes = await readBodyBytes(request)
  const digest = await sha256(bodyBytes)
  const digestB64 = base64Encode(digest)
  headers.set("content-digest", `sha-256=:${digestB64}:`)
  return new Request(request, { headers })
}

export async function verifyContentDigest(request: Request): Promise<boolean> {
  const v = request.headers.get("content-digest")
  if (!v) return false

  const parsed = parseContentDigest(v)
  if (!parsed) return false
  if (parsed.alg !== "sha-256") return false // minimal support

  const bodyBytes = await readBodyBytes(request)
  const digest = await sha256(bodyBytes)
  const digestB64 = base64Encode(digest)
  return timingSafeEqualAscii(parsed.b64, digestB64)
}

export function parseContentDigest(
  v: string
): { alg: string; b64: string } | null {
  // Very small parser for `sha-256=:<base64>:` (ignore surrounding whitespace)
  const s = v.trim()
  const m = /^([A-Za-z0-9_-]+)=:([A-Za-z0-9+/]+={0,2}):$/.exec(s)
  if (!m) return null
  return { alg: m[1].toLowerCase(), b64: m[2] }
}

function timingSafeEqualAscii(a: string, b: string): boolean {
  // Not truly constant-time across JS engines, but avoids early return.
  if (a.length !== b.length) return false
  let x = 0
  for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return x === 0
}
