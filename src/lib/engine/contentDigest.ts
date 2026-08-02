import { sha512 as nobleSha512 } from "@noble/hashes/sha2.js"
import type { ContentDigestMode } from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { base64Encode, readBodyBytes, sha256 } from "../utilities"
import { parseSfDictionary } from "./structuredFields"

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
  mode: ContentDigestMode,
  bodyBytes?: Uint8Array
): Promise<Request> {
  const headers = new Headers(request.headers)
  const existing = headers.get("content-digest")

  if (mode === "off") {
    throw new Erc8128Error(
      "DIGEST_REQUIRED",
      "content-digest is required by covered components, but contentDigest='off'."
    )
  }
  if (mode === "require" && !existing) {
    throw new Erc8128Error(
      "DIGEST_REQUIRED",
      "content-digest is required but missing."
    )
  }
  if (existing && (mode === "auto" || mode === "require")) {
    const resolvedBodyBytes = bodyBytes ?? (await readBodyBytes(request))
    if (!(await verifyContentDigest(request, resolvedBodyBytes))) {
      throw new Erc8128Error(
        "BAD_HEADER_VALUE",
        "content-digest does not match the request content."
      )
    }
    return request
  }

  const resolvedBodyBytes = bodyBytes ?? (await readBodyBytes(request))
  const digest = await sha256(resolvedBodyBytes)
  const digestB64 = base64Encode(digest)
  headers.set("content-digest", `sha-256=:${digestB64}:`)
  return new Request(request, { headers })
}

export async function verifyContentDigest(
  request: Request,
  bodyBytes?: Uint8Array
): Promise<boolean> {
  const v = request.headers.get("content-digest")
  if (!v) return false

  const parsed = parseContentDigest(v)
  if (!parsed) return false
  const resolvedBodyBytes = bodyBytes ?? (await readBodyBytes(request))
  const expected = new Map<string, string>()
  let recognized = 0
  for (const member of parsed) {
    if (
      member.alg === "md5" ||
      member.alg === "sha" ||
      member.alg === "sha-1"
    ) {
      return false
    }
    if (member.alg !== "sha-256" && member.alg !== "sha-512") continue
    let expectedValue = expected.get(member.alg)
    if (expectedValue === undefined) {
      expectedValue = base64Encode(
        member.alg === "sha-256"
          ? await sha256(resolvedBodyBytes)
          : nobleSha512(resolvedBodyBytes)
      )
      expected.set(member.alg, expectedValue)
    }
    recognized += 1
    if (!timingSafeEqualAscii(member.b64, expectedValue)) return false
  }
  return recognized > 0
}

export function parseContentDigest(
  v: string
): { alg: string; b64: string }[] | null {
  try {
    const dictionary = parseSfDictionary(v)
    const result: { alg: string; b64: string }[] = []
    for (const [alg, member] of Object.entries(dictionary)) {
      if (
        !("value" in member) ||
        typeof member.value !== "object" ||
        member.value.type !== "binary" ||
        Object.keys(member.params ?? {}).length !== 0
      ) {
        return null
      }
      result.push({
        alg: alg.toLowerCase(),
        b64: base64Encode(member.value.value)
      })
    }
    return result.length === 0 ? null : result
  } catch {
    return null
  }
}

function timingSafeEqualAscii(a: string, b: string): boolean {
  // Not truly constant-time across JS engines, but avoids early return.
  if (a.length !== b.length) return false
  let x = 0
  for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return x === 0
}
