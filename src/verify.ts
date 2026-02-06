import { verifyContentDigest } from "./lib/engine/contentDigest.js"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase.js"
import { selectSignatureFromHeaders } from "./lib/engine/signatureHeaders.js"
import { parseKeyId } from "./lib/keyId.js"
import {
  isOrderedSubsequence,
  isRequestBoundForThisRequest
} from "./lib/policies/isRequestBound.js"
import type {
  Address,
  NonceStore,
  VerifyMessageFn,
  VerifyPolicy,
  VerifyResult
} from "./lib/types.js"
import {
  base64Decode,
  bytesToHex,
  sanitizeUrl,
  unixNow
} from "./lib/utilities.js"

const DEFAULT_MAX_VALIDITY_SEC = 300

export async function verifyRequest(
  request: Request,
  verifyMessage: VerifyMessageFn,
  nonceStore: NonceStore,
  policy?: VerifyPolicy
): Promise<VerifyResult> {
  const resolvedPolicy = {
    ...policy,
    verifyMessage,
    nonceStore
  }
  const labelPref = resolvedPolicy.label
  const strictLabel = resolvedPolicy.strictLabel ?? false

  const sigInputHeader = request.headers.get("Signature-Input")
  const sigHeader = request.headers.get("Signature")
  if (!sigInputHeader || !sigHeader)
    return { ok: false, reason: "missing_headers" }

  const selected = selectSignatureFromHeaders({
    signatureInputHeader: sigInputHeader,
    signatureHeader: sigHeader,
    policy: { label: labelPref, strictLabel }
  })
  if (!selected.ok) return selected.result

  const { components, params, signatureParamsValue, sigB64, label } =
    selected.selected

  // Keyid parse
  const key = parseKeyId(params.keyid)
  if (!key) return { ok: false, reason: "bad_keyid" }
  const { chainId, address } = key

  // Time checks
  const now = resolvedPolicy.now?.() ?? unixNow()
  const skew = resolvedPolicy.clockSkewSec ?? 0

  if (
    !Number.isInteger(params.created) ||
    !Number.isInteger(params.expires) ||
    params.expires <= params.created
  ) {
    return { ok: false, reason: "bad_time" }
  }
  if (now + skew < params.created) return { ok: false, reason: "not_yet_valid" }
  if (now - skew > params.expires) return { ok: false, reason: "expired" }

  // Enforce a bounded validity window by default.
  // Note: treat null/undefined/NaN as "use default" (no bypass).
  const maxValiditySec = resolvedPolicy.maxValiditySec
  const maxValidity =
    typeof maxValiditySec === "number" && Number.isFinite(maxValiditySec)
      ? maxValiditySec
      : DEFAULT_MAX_VALIDITY_SEC
  if (params.expires - params.created > maxValidity) {
    return { ok: false, reason: "validity_too_long" }
  }

  // Nonce policy (replay vs non-replayable)
  const hasNonce = typeof params.nonce === "string" && params.nonce.length > 0
  const noncePolicy = resolvedPolicy.nonce ?? "required"

  if (noncePolicy === "required" && !hasNonce)
    return { ok: false, reason: "nonce_required" }
  if (noncePolicy === "forbidden" && hasNonce)
    return {
      ok: false,
      reason: "bad_signature_input",
      detail: "nonce is forbidden by policy"
    }

  // Nonce window enforcement (optional)
  if (hasNonce) {
    const maxNonceWin = resolvedPolicy.maxNonceWindowSec
    if (maxNonceWin != null && params.expires - params.created > maxNonceWin) {
      return { ok: false, reason: "nonce_window_too_long" }
    }
  }

  // Components checks (request-bound by default, unless overridden)
  const url = sanitizeUrl(request.url)
  const hasQuery = url.search.length > 0
  const hasBody = request.body != null

  const required = resolvedPolicy.requiredComponents
    ?.map((c) => c.trim())
    .filter(Boolean)
  if (required && required.length > 0) {
    if (!isOrderedSubsequence(required, components)) {
      return {
        ok: false,
        reason: "not_request_bound",
        detail: `requiredComponents not satisfied (need ordered subsequence: ${required.join(
          ","
        )})`
      }
    }
  } else {
    const requestBound = isRequestBoundForThisRequest(components, {
      hasQuery,
      hasBody
    })
    if (!requestBound) return { ok: false, reason: "not_request_bound" }
  }

  // If content-digest is covered, enforce header exists and matches body bytes (default true)
  const enforceDigest = resolvedPolicy.enforceContentDigest ?? true
  if (enforceDigest && components.includes("content-digest")) {
    const v = request.headers.get("content-digest")
    if (!v) return { ok: false, reason: "digest_required" }
    const ok = await verifyContentDigest(request)
    if (!ok) return { ok: false, reason: "digest_mismatch" }
  }

  // Nonce replay protection
  if (hasNonce) {
    const store = resolvedPolicy.nonceStore
    if (!store)
      return {
        ok: false,
        reason: "nonce_required",
        detail: "nonceStore missing"
      }

    const keyFn = resolvedPolicy.nonceKey ?? ((k, n) => `${k}:${n}`)
    const nonce = params.nonce
    if (!nonce)
      return {
        ok: false,
        reason: "nonce_required",
        detail: "nonce missing"
      }
    const replayKey = keyFn(params.keyid, nonce)
    const ttlSeconds = Math.max(0, params.expires - now)
    const consumed = await store.consume(replayKey, ttlSeconds)
    if (!consumed) return { ok: false, reason: "replay" }
  }

  // Build signature base M using the (raw) signatureParamsValue from header
  const M = createSignatureBaseMinimal({
    request,
    components,
    signatureParamsValue // use exactly the member value to keep parity
  })

  // Decode signature bytes
  const sigBytes = base64Decode(sigB64)
  if (!sigBytes || sigBytes.length === 0)
    return { ok: false, reason: "bad_signature_bytes" }
  const sigHex = bytesToHex(sigBytes)

  const verifyFn = resolvedPolicy.verifyMessage
  if (!verifyFn)
    return {
      ok: false,
      reason: "bad_signature_check",
      detail: "verifyMessage missing in policy"
    }

  // Verify signature (EOA / ERC-1271 / ERC-6492 / ERC-8010 depending on implementation)
  try {
    const ok = await verifyFn({
      address,
      message: { raw: bytesToHex(M) },
      signature: sigHex
    })
    if (ok) {
      return {
        ok: true,
        kind: "eoa",
        address: address as Address,
        chainId,
        label,
        components,
        params
      }
    }
  } catch {
    return { ok: false, reason: "bad_signature_check" }
  }

  return { ok: false, reason: "bad_signature" }
}
