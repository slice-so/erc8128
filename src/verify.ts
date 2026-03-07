import { buildAcceptSignatureHeader } from "./lib/acceptSignature"
import { verifyContentDigest } from "./lib/engine/contentDigest"
import { selectSignatureFromHeaders } from "./lib/engine/signatureHeaders"
import { parseKeyId } from "./lib/keyId"
import { requiredRequestBoundComponents } from "./lib/policies/isRequestBound"
import {
  ensureAuthority,
  normalizeClassBoundPolicies,
  normalizeComponentsList
} from "./lib/policies/normalizePolicies"
import type { Address, VerifyRequestArgs, VerifyResult } from "./lib/types"
import { base64Decode, bytesToHex, sanitizeUrl, unixNow } from "./lib/utilities"
import {
  buildAttempts,
  buildSignatureBase,
  runNonceChecks,
  runTimeChecks,
  type VerifyCandidate
} from "./lib/verifyUtils"

const DEFAULT_MAX_SIGNATURE_VERIFICATIONS = 3

type ParsedKeyId = NonNullable<ReturnType<typeof parseKeyId>>
type VerifyMessageOutcome = {
  ok: boolean
  failure: VerifyResult | null
}

async function runVerifyMessageCheck(args: {
  replayable: boolean
  verifyMessage: NonNullable<VerifyRequestArgs["verifyMessage"]>
  verifyMessageArgs: Parameters<
    NonNullable<VerifyRequestArgs["verifyMessage"]>
  >[0]
  replayableInvalidated:
    | NonNullable<
        NonNullable<VerifyRequestArgs["policy"]>["replayableInvalidated"]
      >
    | undefined
  replayableInvalidationArgs: NonNullable<
    Parameters<
      NonNullable<
        NonNullable<VerifyRequestArgs["policy"]>["replayableInvalidated"]
      >
    >[0]
  >
}): Promise<VerifyMessageOutcome> {
  const {
    replayable,
    verifyMessage,
    verifyMessageArgs,
    replayableInvalidated,
    replayableInvalidationArgs
  } = args

  if (replayable && replayableInvalidated) {
    const [verifyOutcome, invalidated] = await Promise.all([
      (async () => {
        try {
          return {
            ok: await verifyMessage(verifyMessageArgs),
            failure: null
          }
        } catch {
          return {
            ok: false,
            failure: {
              ok: false,
              reason: "bad_signature_check"
            } as VerifyResult
          }
        }
      })(),
      replayableInvalidated(replayableInvalidationArgs)
    ])

    if (invalidated) {
      return {
        ok: false,
        failure: { ok: false, reason: "replayable_invalidated" }
      }
    }

    return verifyOutcome
  }

  try {
    return {
      ok: await verifyMessage(verifyMessageArgs),
      failure: null
    }
  } catch {
    return {
      ok: false,
      failure: { ok: false, reason: "bad_signature_check" }
    }
  }
}

export async function verifyRequest(
  args: VerifyRequestArgs
): Promise<VerifyResult> {
  const { request, verifyMessage, nonceStore, policy, setHeaders } = args
  const resolvedPolicy = {
    ...policy,
    verifyMessage,
    nonceStore
  }
  const labelPref = resolvedPolicy.label
  const strictLabel = resolvedPolicy.strictLabel ?? false

  const now = resolvedPolicy.now?.() ?? unixNow()
  const skew = resolvedPolicy.clockSkewSec ?? 0
  const allowReplayable = resolvedPolicy.replayable ?? false

  const url = sanitizeUrl(request.url)
  const hasQuery = url.search.length > 0
  const hasBody = request.body != null

  const requestBoundExtras = normalizeComponentsList(
    resolvedPolicy.additionalRequestBoundComponents
  )
  const requestBoundRequired = requiredRequestBoundComponents(
    { hasQuery, hasBody },
    requestBoundExtras
  )

  const classBoundPolicies = normalizeClassBoundPolicies(
    resolvedPolicy.classBoundPolicies
  ).map((policy) => ensureAuthority(policy))

  if (setHeaders) {
    try {
      const acceptSignature = buildAcceptSignatureHeader({
        requestBoundRequired,
        classBoundPolicies,
        requireNonce: !allowReplayable
      })
      setHeaders("Accept-Signature", acceptSignature)
    } catch {
      // Avoid breaking verification flow if header serialization fails.
    }
  }

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

  const candidates = selected.selected

  const validCandidates = candidates
    .map((candidate) => {
      const key = parseKeyId(candidate.params.keyid)
      if (!key) return null
      return { candidate, key }
    })
    .filter((entry): entry is VerifyCandidate<ParsedKeyId> => entry != null)
  if (validCandidates.length === 0) return { ok: false, reason: "bad_keyid" }

  const { attempts, sawClassBound } = buildAttempts(validCandidates, {
    hasQuery,
    hasBody,
    requestBoundExtras,
    requestBoundRequired,
    classBoundPolicies
  })

  if (attempts.length === 0) {
    if (sawClassBound && classBoundPolicies.length > 0)
      return { ok: false, reason: "class_bound_not_allowed" }
    return { ok: false, reason: "not_request_bound" }
  }

  const maxSignatureVerifications =
    typeof resolvedPolicy.maxSignatureVerifications === "number" &&
    Number.isFinite(resolvedPolicy.maxSignatureVerifications) &&
    resolvedPolicy.maxSignatureVerifications > 0
      ? Math.floor(resolvedPolicy.maxSignatureVerifications)
      : DEFAULT_MAX_SIGNATURE_VERIFICATIONS

  let lastFailure: VerifyResult = { ok: false, reason: "bad_signature" }
  let tried = 0

  for (const attempt of attempts) {
    if (tried >= maxSignatureVerifications) break
    tried++

    const { candidate, key } = attempt.candidate
    const { components, params, signatureParamsValue, sigB64, label } =
      candidate
    const { chainId, address } = key
    const replayable = !params.nonce || params.nonce.length === 0

    // Time checks
    const timeFailure = runTimeChecks({
      now,
      skew,
      maxValiditySec: resolvedPolicy.maxValiditySec,
      created: params.created,
      expires: params.expires
    })
    if (timeFailure) {
      lastFailure = timeFailure
      continue
    }

    const { failure: nonceFailure, plan: noncePlan } = runNonceChecks({
      allowReplayable,
      params,
      now,
      nonceStore: resolvedPolicy.nonceStore,
      nonceKey: resolvedPolicy.nonceKey,
      maxNonceWindowSec: resolvedPolicy.maxNonceWindowSec
    })
    if (nonceFailure) {
      lastFailure = nonceFailure
      continue
    }

    if (replayable) {
      const hasReplayableInvalidation =
        typeof resolvedPolicy.replayableNotBefore === "function" ||
        typeof resolvedPolicy.replayableInvalidated === "function"
      if (!hasReplayableInvalidation) {
        lastFailure = { ok: false, reason: "replayable_invalidation_required" }
        continue
      }
      if (typeof resolvedPolicy.replayableNotBefore === "function") {
        const notBefore = await resolvedPolicy.replayableNotBefore(params.keyid)
        if (
          typeof notBefore === "number" &&
          Number.isFinite(notBefore) &&
          params.created < notBefore
        ) {
          lastFailure = { ok: false, reason: "replayable_not_before" }
          continue
        }
      }
    }

    // If content-digest is covered, enforce header exists and matches body bytes
    if (components.includes("content-digest")) {
      const v = request.headers.get("content-digest")
      if (!v) {
        lastFailure = { ok: false, reason: "digest_required" }
        continue
      }
      const ok = await verifyContentDigest(request)
      if (!ok) {
        lastFailure = { ok: false, reason: "digest_mismatch" }
        continue
      }
    }

    // Build signature base M using the (raw) signatureParamsValue from header
    const M = buildSignatureBase({ request, components, signatureParamsValue })

    // Decode signature bytes
    const sigBytes = base64Decode(sigB64)
    if (!sigBytes || sigBytes.length === 0) {
      lastFailure = { ok: false, reason: "bad_signature_bytes" }
      continue
    }
    const sigHex = bytesToHex(sigBytes)

    const verifyFn = resolvedPolicy.verifyMessage
    if (!verifyFn) {
      lastFailure = {
        ok: false,
        reason: "bad_signature_check",
        detail: "verifyMessage missing in policy"
      }
      continue
    }

    const verifyMessageArgs = {
      address,
      message: { raw: bytesToHex(M) },
      signature: sigHex
    }

    // Verification may fall through to later signatures, so record the
    // current failure and keep iterating instead of returning immediately.
    const verifyOutcome = await runVerifyMessageCheck({
      replayable,
      verifyMessage: verifyFn,
      verifyMessageArgs,
      replayableInvalidated: resolvedPolicy.replayableInvalidated,
      replayableInvalidationArgs: {
        keyid: params.keyid,
        created: params.created,
        expires: params.expires,
        label,
        signature: sigHex,
        signatureBase: M,
        signatureParamsValue
      }
    })
    if (verifyOutcome.failure) {
      lastFailure = verifyOutcome.failure
      continue
    }

    if (verifyOutcome.ok) {
      if (noncePlan.replayKey && noncePlan.replayStore) {
        const consumed = await noncePlan.replayStore.consume(
          noncePlan.replayKey,
          noncePlan.replayTtlSeconds
        )
        if (!consumed) {
          lastFailure = { ok: false, reason: "replay" }
          continue
        }
      }
      return {
        ok: true,
        address: address as Address,
        chainId,
        label,
        components,
        params,
        replayable,
        binding: attempt.kind
      }
    }

    lastFailure = { ok: false, reason: "bad_signature" }
  }

  return lastFailure
}
