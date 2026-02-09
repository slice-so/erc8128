import { createSignatureBaseMinimal } from "./engine/createSignatureBase.js"
import {
  includesAllComponents,
  isRequestBoundForThisRequest
} from "./policies/isRequestBound.js"

const DEFAULT_MAX_VALIDITY_SEC = 300
export function buildAttempts(candidates, options) {
  const {
    hasQuery,
    hasBody,
    requestBoundExtras,
    requestBoundRequired,
    classBoundPolicies
  } = options
  const attempts = []
  let sawClassBound = false
  for (const entry of candidates) {
    const { candidate } = entry
    const isRequestBound = isRequestBoundForThisRequest(
      candidate.components,
      { hasQuery, hasBody },
      requestBoundExtras
    )
    if (isRequestBound) {
      // Request-bound signatures are always eligible; replayability is enforced later via params/policy.
      attempts.push({
        candidate: entry,
        kind: "request-bound",
        policyLength: requestBoundRequired.length
      })
      continue
    }
    sawClassBound = true
    if (classBoundPolicies.length === 0) continue
    const matching = classBoundPolicies.filter((policy) =>
      includesAllComponents(policy, candidate.components)
    )
    if (matching.length === 0) continue
    const bestLength = Math.min(...matching.map((policy) => policy.length))
    attempts.push({
      candidate: entry,
      kind: "class-bound",
      policyLength: bestLength
    })
  }
  return { attempts, sawClassBound }
}
export function runTimeChecks(options) {
  const { now, skew, maxValiditySec, created, expires } = options
  if (
    typeof created !== "number" ||
    typeof expires !== "number" ||
    !Number.isInteger(created) ||
    !Number.isInteger(expires) ||
    expires <= created
  ) {
    return { ok: false, reason: "bad_time" }
  }
  const createdSec = created
  const expiresSec = expires
  if (now + skew < createdSec) return { ok: false, reason: "not_yet_valid" }
  if (now - skew > expiresSec) return { ok: false, reason: "expired" }
  // Enforce a bounded validity window by default.
  // Note: treat null/undefined/NaN as "use default" (no bypass).
  const maxValidity =
    typeof maxValiditySec === "number" && Number.isFinite(maxValiditySec)
      ? maxValiditySec
      : DEFAULT_MAX_VALIDITY_SEC
  if (expiresSec - createdSec > maxValidity)
    return { ok: false, reason: "validity_too_long" }
  return null
}
export function runNonceChecks(options) {
  const {
    allowReplayable,
    params,
    now,
    nonceStore,
    nonceKey,
    maxNonceWindowSec
  } = options
  const hasNonce = typeof params.nonce === "string" && params.nonce.length > 0
  if (!hasNonce && !allowReplayable) {
    return {
      failure: { ok: false, reason: "replayable_not_allowed" },
      plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
    }
  }
  if (hasNonce) {
    if (!nonceStore) {
      return {
        failure: {
          ok: false,
          reason: "nonce_required",
          detail: "nonceStore missing"
        },
        plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
      }
    }
    if (
      maxNonceWindowSec != null &&
      typeof params.created === "number" &&
      typeof params.expires === "number" &&
      params.expires - params.created > maxNonceWindowSec
    ) {
      return {
        failure: { ok: false, reason: "nonce_window_too_long" },
        plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
      }
    }
    const nonce = params.nonce
    if (!nonce) {
      return {
        failure: {
          ok: false,
          reason: "nonce_required",
          detail: "nonce missing"
        },
        plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
      }
    }
    const keyFn = nonceKey ?? ((k, n) => `${k}:${n}`)
    return {
      failure: null,
      plan: {
        replayKey: keyFn(params.keyid, nonce),
        replayStore: nonceStore,
        replayTtlSeconds: Math.max(0, (params.expires ?? now) - now)
      }
    }
  }
  return {
    failure: null,
    plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
  }
}
export function buildSignatureBase(options) {
  const { request, components, signatureParamsValue } = options
  return createSignatureBaseMinimal({
    request,
    components,
    signatureParamsValue // use exactly the member value to keep parity
  })
}
//# sourceMappingURL=verifyUtils.js.map
