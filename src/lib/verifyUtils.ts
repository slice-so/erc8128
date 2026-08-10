import type {
  Attempt,
  NoncePlan,
  NonceStore,
  VerifyCandidate,
  VerifyResult
} from "../types"
import { createSignatureBaseMinimal } from "./engine/createSignatureBase"
import { formatReplayKey } from "./keyId"
import { isValidNonce } from "./nonce"
import {
  includesAllComponents,
  isRequestBoundForThisRequest
} from "./policies/isRequestBound"

export const DEFAULT_MAX_VALIDITY_SEC = 300

export function buildAttempts<Key>(
  candidates: VerifyCandidate<Key>[],
  options: {
    hasQuery: boolean
    hasBody: boolean
    hasContentDigest?: boolean
    hasContentType?: boolean
    requestBoundExtras: import("../types").ComponentIdentifier[]
    requestBoundRequired: import("../types").ComponentIdentifier[]
    requiredWhenPresent: import("../types").ComponentIdentifier[]
    classBoundPolicies: import("../types").ComponentIdentifier[][]
  }
): { attempts: Attempt<Key>[]; sawClassBound: boolean } {
  const {
    hasQuery,
    hasBody,
    hasContentDigest,
    hasContentType,
    requestBoundExtras,
    requestBoundRequired,
    requiredWhenPresent,
    classBoundPolicies
  } = options
  const attempts: Attempt<Key>[] = []
  let sawClassBound = false

  for (const entry of candidates) {
    const { candidate } = entry
    if (!includesAllComponents(requiredWhenPresent, candidate.components)) {
      continue
    }
    if (!includesAllComponents(requestBoundExtras, candidate.components)) {
      continue
    }
    const isRequestBound = isRequestBoundForThisRequest(
      candidate.components,
      { hasQuery, hasBody, hasContentDigest, hasContentType },
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

export function runTimeChecks(options: {
  now: number
  skew: number
  maxValiditySec: number | null | undefined
  created: number | undefined
  expires: number | undefined
}): Extract<VerifyResult, { ok: false }> | null {
  const { now, skew, maxValiditySec, created, expires } = options

  if (
    typeof created !== "number" ||
    typeof expires !== "number" ||
    !Number.isInteger(created) ||
    !Number.isInteger(expires) ||
    expires <= created
  ) {
    return { ok: false, reason: "invalid_time" }
  }
  const createdSec = created
  const expiresSec = expires
  if (now < createdSec - skew)
    return { ok: false, reason: "request_not_yet_valid" }
  if (now > expiresSec + skew) return { ok: false, reason: "request_expired" }

  // Enforce a bounded validity window by default.
  // Note: treat null/undefined/NaN as "use default" (no bypass).
  const maxValidity =
    typeof maxValiditySec === "number" && Number.isFinite(maxValiditySec)
      ? maxValiditySec
      : DEFAULT_MAX_VALIDITY_SEC
  if (expiresSec - createdSec > maxValidity)
    return { ok: false, reason: "request_validity_too_long" }

  return null
}

export function runNonceChecks(options: {
  allowReplayable: boolean
  params: { nonce?: string; keyid: string; created?: number; expires?: number }
  now: number
  nonceStore: NonceStore | undefined
  nonceKey: ((keyid: string, nonce: string) => string) | undefined
  maxNonceWindowSec: number | null | undefined
  clockSkewSec: number
  missingNonceReason?: "nonce_required" | "replayable_not_allowed"
}): {
  failure: Extract<VerifyResult, { ok: false }> | null
  plan: NoncePlan
} {
  const {
    allowReplayable,
    params,
    now,
    nonceStore,
    nonceKey,
    maxNonceWindowSec,
    clockSkewSec
  } = options

  const hasNonce = params.nonce !== undefined
  if (!hasNonce && !allowReplayable) {
    return {
      failure: {
        ok: false,
        reason: options.missingNonceReason ?? "nonce_required"
      },
      plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
    }
  }

  if (hasNonce) {
    if (!nonceStore) {
      return {
        failure: {
          ok: false,
          reason: "signature_verification_unavailable",
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
        failure: { ok: false, reason: "request_validity_too_long" },
        plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
      }
    }

    const nonce = params.nonce ?? ""

    if (!isValidNonce(nonce)) {
      return {
        failure: {
          ok: false,
          reason: "invalid_nonce",
          detail: "nonce must be a 1-128 byte ASCII String"
        },
        plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
      }
    }

    const keyFn = nonceKey ?? formatReplayKey
    return {
      failure: null,
      plan: {
        replayKey: keyFn(params.keyid, nonce),
        replayStore: nonceStore,
        replayTtlSeconds: Math.max(
          1,
          (params.expires ?? now) + clockSkewSec - now
        )
      }
    }
  }

  return {
    failure: null,
    plan: { replayKey: null, replayStore: null, replayTtlSeconds: 0 }
  }
}

export function buildSignatureBase(options: {
  request: Request
  components: string[]
  signatureParamsValue: string
}): Uint8Array {
  const { request, components, signatureParamsValue } = options
  return createSignatureBaseMinimal({
    request,
    components,
    signatureParamsValue // use exactly the member value to keep parity
  })
}
