import { verifyContentDigest } from "./lib/engine/contentDigest.js"
import { quoteSfString } from "./lib/engine/serializations.js"
import { selectSignatureFromHeaders } from "./lib/engine/signatureHeaders.js"
import { parseKeyId } from "./lib/keyId.js"
import { requiredRequestBoundComponents } from "./lib/policies/isRequestBound.js"
import {
  ensureAuthority,
  normalizeClassBoundPolicies,
  normalizeComponentsList
} from "./lib/policies/normalizePolicies.js"
import type {
  Address,
  NonceStore,
  SetHeadersFn,
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
import {
  buildAttempts,
  buildSignatureBase,
  runNonceChecks,
  runTimeChecks,
  type VerifyCandidate
} from "./lib/verifyUtils.js"

const DEFAULT_MAX_SIGNATURE_VERIFICATIONS = 3

type ParsedKeyId = NonNullable<ReturnType<typeof parseKeyId>>

function serializeAcceptSignatureValue(
  components: string[],
  requireNonce: boolean
) {
  const items = components.map((c) => quoteSfString(c)).join(" ")
  let out = `(${items})`
  out += `;keyid;created;expires`
  if (requireNonce) out += `;nonce`
  return out
}

function buildAcceptSignatureHeader(args: {
  requestBoundRequired: string[]
  classBoundPolicies: string[][]
  requireNonce: boolean
}): string {
  const { requestBoundRequired, classBoundPolicies, requireNonce } = args
  const entries: string[] = []
  const seen = new Set<string>()
  let index = 1

  const addEntry = (components: string[]) => {
    const key = components.join("\u0000")
    if (seen.has(key)) return
    seen.add(key)
    const value = serializeAcceptSignatureValue(components, requireNonce)
    entries.push(`sig${index}=${value}`)
    index++
  }

  addEntry(requestBoundRequired)
  for (const policy of classBoundPolicies) addEntry(policy)

  return entries.join(", ")
}

export async function verifyRequest(
  request: Request,
  verifyMessage: VerifyMessageFn,
  nonceStore: NonceStore,
  policy?: VerifyPolicy,
  setHeaders?: SetHeadersFn
): Promise<VerifyResult> {
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

    // Verify signature (EOA / ERC-1271 / ERC-6492 / ERC-8010 depending on implementation)
    try {
      const ok = await verifyFn({
        address,
        message: { raw: bytesToHex(M) },
        signature: sigHex
      })
      if (ok) {
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
    } catch {
      lastFailure = { ok: false, reason: "bad_signature_check" }
      continue
    }

    lastFailure = { ok: false, reason: "bad_signature" }
  }

  return lastFailure
}
