import { buildAcceptSignatureHeader } from "./lib/acceptSignature"
import {
  DELEGATION_COMPONENT,
  DELEGATION_FIELD_NAME,
  normalizeAudienceOrigin,
  parseDelegationField,
  TAG_DELEGATED,
  TAG_DELEGATION,
  TAG_DIRECT
} from "./lib/delegation/delegationField"
import { Erc8128Error, VerificationUnavailableError } from "./lib/Erc8128Error"
import { verifyCanonicalEoaSignature } from "./lib/ecdsa"
import {
  componentIdentifierEquals,
  includesComponent
} from "./lib/engine/componentIdentifier"
import { verifyContentDigest } from "./lib/engine/contentDigest"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase"
import { selectSignatureFromHeaders } from "./lib/engine/signatureHeaders"
import { keyIdEquals, parseKeyId } from "./lib/keyId"
import { requiredRequestBoundComponents } from "./lib/policies/isRequestBound"
import {
  ensureAuthority,
  normalizeClassBoundPolicies,
  normalizeComponentsList
} from "./lib/policies/normalizePolicies"
import {
  base64Decode,
  bytesToHex,
  hexToBytes,
  readBodyBytes,
  sanitizeUrl,
  unixNow
} from "./lib/utilities"
import { buildAttempts, runNonceChecks, runTimeChecks } from "./lib/verifyUtils"
import type {
  Attempt,
  DelegationGrant,
  NoncePlan,
  ParsedDelegationField,
  SelectedSignature,
  VerifyCandidate,
  VerifyMessageFn,
  VerifyRequestArgs,
  VerifyResult
} from "./types"

const DEFAULT_MAX_SIGNATURE_VERIFICATIONS = 8
const DEFAULT_GRANT_MAX_VALIDITY_SEC = 30 * 24 * 60 * 60
const DEFAULT_GRANT_CACHE_TTL_SEC = 60
const GRANT_CACHE_DISCRIMINATOR = "erc8128-delegation/1"

type ParsedKeyId = NonNullable<ReturnType<typeof parseKeyId>>
type Failure = Extract<VerifyResult, { ok: false }>

export async function verifyRequest(
  args: VerifyRequestArgs
): Promise<VerifyResult> {
  const { request, verifyMessage, nonceStore, policy = {}, setHeaders } = args
  const now = policy.now?.() ?? unixNow()
  const skew = policy.clockSkewSec ?? 0
  const url = sanitizeUrl(request.url)
  const signatureInputHeader = request.headers.get("signature-input")
  const signatureHeader = request.headers.get("signature")
  if (!signatureInputHeader || !signatureHeader) {
    return { ok: false, reason: "signature_missing" }
  }
  const selected = selectSignatureFromHeaders({
    signatureInputHeader,
    signatureHeader
  })
  if (!selected.ok) return selected.result

  const grantCandidates = selected.selected.filter(
    (candidate) =>
      candidate.params.tag === TAG_DELEGATION &&
      parseKeyId(candidate.params.keyid) !== null
  )
  const principalPolicy = policy.principal ?? "either"
  const requestCandidates = selected.selected.filter(
    (candidate) =>
      candidate.params.tag === TAG_DIRECT ||
      candidate.params.tag === TAG_DELEGATED
  )
  if (requestCandidates.length === 0) {
    return { ok: false, reason: "no_acceptable_signature" }
  }

  const maximum = positiveInteger(
    policy.maxSignatureVerifications,
    DEFAULT_MAX_SIGNATURE_VERIFICATIONS
  )
  if (requestCandidates.length > maximum) {
    return { ok: false, reason: "signature_too_large" }
  }

  // Bound and classify the signature fields before buffering request content.
  // This preserves the profile's cheap-check ordering for unauthenticated input.
  const bodyBytes =
    request.body === null ? new Uint8Array() : await readBodyBytes(request)
  const shape = {
    hasQuery: url.search.length > 0,
    hasBody: bodyBytes.length > 0,
    hasContentDigest: request.headers.has("content-digest"),
    hasContentType: request.headers.has("content-type")
  }
  const requestBoundExtras = normalizeComponentsList(
    policy.additionalRequestBoundComponents
  )
  const requestBoundRequired = requiredRequestBoundComponents(
    shape,
    requestBoundExtras
  )
  const classBoundPolicies = normalizeClassBoundPolicies(
    policy.classBoundPolicies
  ).map(ensureAuthority)

  if (setHeaders) {
    try {
      setHeaders(
        "Accept-Signature",
        buildAcceptSignatureHeader({
          requestBoundRequired,
          classBoundPolicies,
          allowReplayable: policy.replayable ?? false
        })
      )
    } catch {
      // Authentication must not depend on advisory response header formatting.
    }
  }

  const grantVerificationResults = new Map<string, boolean | "unavailable">()
  let firstFailure: Failure | null = null
  let firstUnavailable: Failure | null = null
  for (const candidate of requestCandidates) {
    if (
      candidate.params.tag === TAG_DELEGATED &&
      policy.delegation === undefined
    ) {
      firstFailure ??= { ok: false, reason: "unsupported_delegation" }
      continue
    }
    const disallowedPrincipalClass =
      candidate.params.tag === TAG_DIRECT && principalPolicy === "delegated"
    if (disallowedPrincipalClass) {
      firstFailure ??= { ok: false, reason: "principal_not_allowed" }
      continue
    }
    const key = parseKeyId(candidate.params.keyid)
    if (key === null) {
      firstFailure ??= { ok: false, reason: "invalid_keyid" }
      continue
    }
    if (candidate.params.alg !== undefined) {
      firstFailure ??= { ok: false, reason: "unsupported_algorithm" }
      continue
    }
    const entry = { candidate, key }
    const outcome =
      candidate.params.tag === TAG_DELEGATED
        ? await verifyDelegatedCandidate({
            request,
            bodyBytes,
            shape,
            requestBoundExtras,
            requestBoundRequired,
            candidate: entry,
            grantCandidates,
            grantVerificationResults,
            verifyMessage,
            nonceStore,
            policy,
            now,
            skew
          })
        : await verifyDirectCandidate({
            request,
            bodyBytes,
            shape,
            requestBoundExtras,
            requestBoundRequired,
            classBoundPolicies,
            candidate: entry,
            verifyMessage,
            nonceStore,
            policy,
            now,
            skew
          })
    if (outcome.ok) return outcome
    firstFailure ??= outcome
    if (isUnavailableFailure(outcome)) firstUnavailable ??= outcome
  }
  return (
    firstUnavailable ??
    firstFailure ?? { ok: false, reason: "no_acceptable_signature" }
  )
}

async function verifyDirectCandidate(args: {
  request: Request
  bodyBytes: Uint8Array
  shape: RequestShape
  requestBoundExtras: ReturnType<typeof normalizeComponentsList>
  requestBoundRequired: ReturnType<typeof requiredRequestBoundComponents>
  classBoundPolicies: ReturnType<typeof normalizeClassBoundPolicies>
  candidate: VerifyCandidate<ParsedKeyId>
  verifyMessage: VerifyMessageFn
  nonceStore: VerifyRequestArgs["nonceStore"]
  policy: NonNullable<VerifyRequestArgs["policy"]>
  now: number
  skew: number
}): Promise<VerifyResult> {
  const { candidate, key } = args.candidate
  const requiredWhenPresent = normalizeComponentsList([
    ...(args.shape.hasBody || args.shape.hasContentDigest
      ? (["content-digest"] as const)
      : []),
    ...(args.shape.hasContentType ? (["content-type"] as const) : []),
    ...(args.policy.requiredCoveredComponentsWhenPresent ?? []).filter(
      (component) =>
        args.request.headers.has(
          typeof component === "string" ? component : component.name
        )
    )
  ])
  const built = buildAttempts([args.candidate], {
    ...args.shape,
    requestBoundExtras: args.requestBoundExtras,
    requestBoundRequired: args.requestBoundRequired,
    requiredWhenPresent,
    classBoundPolicies: args.classBoundPolicies
  })
  const attempt = built.attempts[0]
  if (!attempt) {
    return { ok: false, reason: "insufficient_coverage" }
  }
  const common = await validateRequestCandidate({
    ...args,
    attempt,
    allowReplayable: args.policy.replayable ?? false
  })
  if ("failure" in common) return common.failure

  const signatureOutcome =
    args.policy.accountVerification === "eoa-only"
      ? verifyCanonicalEoaSignature({
          address: key.address,
          message: common.signatureBase,
          signature: common.signature
        })
      : await callVerifier(args.verifyMessage, {
          address: key.address,
          chainId: key.chainId,
          message: { raw: bytesToHex(common.signatureBase) },
          signature: common.signature
        })
  if (signatureOutcome === "unavailable") {
    return { ok: false, reason: "signature_verification_unavailable" }
  }
  if (!signatureOutcome) return { ok: false, reason: "bad_signature" }

  const replayFailure = await validateReplayableInvalidation(
    args.policy,
    candidate
  )
  if (replayFailure) return replayFailure
  const nonceFailure = await consumeNonce(common.noncePlan)
  if (nonceFailure) return nonceFailure
  return {
    ok: true,
    principal: key,
    signer: key,
    delegated: false,
    label: candidate.label,
    components: candidate.components,
    params: candidate.params,
    replay: common.replayable ? "replayable" : "non-replayable",
    binding: attempt.kind
  }
}

async function verifyDelegatedCandidate(args: {
  request: Request
  bodyBytes: Uint8Array
  shape: RequestShape
  requestBoundExtras: ReturnType<typeof normalizeComponentsList>
  requestBoundRequired: ReturnType<typeof requiredRequestBoundComponents>
  candidate: VerifyCandidate<ParsedKeyId>
  grantCandidates: SelectedSignature[]
  grantVerificationResults: Map<string, boolean | "unavailable">
  verifyMessage: VerifyMessageFn
  nonceStore: VerifyRequestArgs["nonceStore"]
  policy: NonNullable<VerifyRequestArgs["policy"]>
  now: number
  skew: number
}): Promise<VerifyResult> {
  const delegationPolicy = args.policy.delegation
  if (!delegationPolicy) return { ok: false, reason: "unsupported_delegation" }
  if (args.grantCandidates.length === 0) {
    return { ok: false, reason: "delegation_grant_missing" }
  }
  if (args.grantCandidates.length !== 1) {
    return { ok: false, reason: "delegation_grant_ambiguous" }
  }
  const grantCandidate = args.grantCandidates[0]
  if (!grantCandidate) return { ok: false, reason: "delegation_grant_missing" }

  if (grantCandidate.params.alg !== undefined) {
    return { ok: false, reason: "unsupported_algorithm" }
  }
  if (
    grantCandidate.params.nonce !== undefined ||
    grantCandidate.components.length !== 1 ||
    !componentIdentifierEquals(
      grantCandidate.components[0],
      DELEGATION_COMPONENT
    )
  ) {
    return { ok: false, reason: "bad_grant_signature" }
  }

  const fieldWire = args.request.headers.get(DELEGATION_FIELD_NAME)
  if (!fieldWire) return { ok: false, reason: "bad_delegation_field" }

  let field: ParsedDelegationField
  try {
    field = parseDelegationField(fieldWire)
  } catch (error) {
    return {
      ok: false,
      reason:
        error instanceof Erc8128Error && error.code === "DELEGATION_TOO_LARGE"
          ? "delegation_too_large"
          : "bad_delegation_field"
    }
  }
  if (!keyIdEquals(grantCandidate.params.keyid, identityKey(field.root))) {
    return { ok: false, reason: "grant_root_mismatch" }
  }
  if (args.policy.principal === "direct") {
    return { ok: false, reason: "principal_not_allowed" }
  }

  const grantTimeFailure = validateGrantTime({
    created: grantCandidate.params.created,
    expires: grantCandidate.params.expires,
    now: args.now,
    skew: args.skew,
    maxValidity:
      delegationPolicy.grantMaxValiditySec ?? DEFAULT_GRANT_MAX_VALIDITY_SEC
  })
  if (grantTimeFailure) return grantTimeFailure
  const requestParams = args.candidate.candidate.params
  const requestTimeFailure = runTimeChecks({
    now: args.now,
    skew: args.skew,
    maxValiditySec: args.policy.maxValiditySec,
    created: requestParams.created,
    expires: requestParams.expires
  })
  if (requestTimeFailure) return requestTimeFailure
  if (
    requestParams.created < grantCandidate.params.created - args.skew ||
    requestParams.expires > grantCandidate.params.expires
  ) {
    return { ok: false, reason: "request_outside_grant_window" }
  }

  if (!keyIdEquals(requestParams.keyid, identityKey(field.delegate))) {
    return { ok: false, reason: "delegate_mismatch" }
  }

  const missingRequestBaseline = args.requestBoundRequired.some(
    (component) =>
      !includesComponent(args.candidate.candidate.components, component)
  )
  if (missingRequestBaseline) {
    return { ok: false, reason: "insufficient_coverage" }
  }
  const missingDelegation = !includesComponent(
    args.candidate.candidate.components,
    DELEGATION_COMPONENT
  )
  if (missingDelegation) return { ok: false, reason: "delegation_not_covered" }
  if (!field.replayable && !requestParams.nonce) {
    return { ok: false, reason: "delegation_nonce_required" }
  }
  if (
    field.maxAge !== undefined &&
    requestParams.expires - requestParams.created > field.maxAge
  ) {
    return { ok: false, reason: "delegation_max_age_exceeded" }
  }
  const missingFloor = field.components.some(
    (component) =>
      !includesComponent(args.candidate.candidate.components, component)
  )
  if (missingFloor) return { ok: false, reason: "delegation_components_floor" }

  for (const extensionName of field.critical) {
    if (field.extensions[extensionName] === undefined) {
      return { ok: false, reason: "bad_delegation_field" }
    }
    if (delegationPolicy.extensions?.[extensionName] === undefined) {
      return { ok: false, reason: "unsupported_critical_extension" }
    }
  }

  const attempt: Attempt<ParsedKeyId> = {
    candidate: args.candidate,
    kind: "request-bound",
    policyLength: args.requestBoundRequired.length + field.components.length + 1
  }
  const common = await validateRequestCandidate({
    ...args,
    attempt,
    allowReplayable: field.replayable && (args.policy.replayable ?? false),
    missingNonceReason:
      field.replayable && !(args.policy.replayable ?? false)
        ? "replayable_not_allowed"
        : "nonce_required"
  })
  if ("failure" in common) return common.failure

  let expectedAudience: string
  try {
    expectedAudience = resolveAudience(args.request, delegationPolicy.audience)
  } catch {
    return { ok: false, reason: "audience_mismatch" }
  }
  if (!field.audiences.includes(expectedAudience)) {
    return { ok: false, reason: "audience_mismatch" }
  }

  const delegateOutcome =
    field.delegateKeyType === "eoa"
      ? verifyCanonicalEoaSignature({
          address: field.delegate.address,
          message: common.signatureBase,
          signature: common.signature
        })
      : await callVerifier(args.verifyMessage, {
          address: field.delegate.address,
          chainId: field.delegate.chainId,
          message: { raw: bytesToHex(common.signatureBase) },
          signature: common.signature
        })
  if (delegateOutcome === "unavailable") {
    return { ok: false, reason: "signature_verification_unavailable" }
  }
  if (!delegateOutcome) return { ok: false, reason: "bad_signature" }

  const grant: DelegationGrant = {
    fieldValue: field.fieldValue,
    grantSignatureInput: grantCandidate.signatureParamsValue,
    grantSignatureB64: grantCandidate.sigB64
  }
  const cacheKey = [
    GRANT_CACHE_DISCRIMINATOR,
    field.fieldValue,
    grantCandidate.signatureParamsValue,
    grantCandidate.sigB64
  ].join("\u0000")
  const memoizedGrant = args.grantVerificationResults.get(cacheKey)
  if (memoizedGrant === "unavailable") {
    return { ok: false, reason: "grant_verification_unavailable" }
  }
  if (memoizedGrant === false) {
    return { ok: false, reason: "bad_grant_signature" }
  }
  let validGrant = memoizedGrant === true
  if (!validGrant) {
    try {
      if ((await delegationPolicy.grantCache?.get(cacheKey)) === true) {
        validGrant = true
        args.grantVerificationResults.set(cacheKey, true)
      }
    } catch {
      // Cache availability must not replace authoritative grant verification.
    }
  }
  if (!validGrant) {
    const grantSignatureBytes = base64Decode(grantCandidate.sigB64)
    if (!grantSignatureBytes?.length) {
      return { ok: false, reason: "bad_grant_signature" }
    }
    const grantRequest = new Request("https://erc8128.invalid/", {
      headers: { [DELEGATION_FIELD_NAME]: field.fieldValue }
    })
    const grantBase = createSignatureBaseMinimal({
      request: grantRequest,
      components: grantCandidate.components,
      signatureParamsValue: grantCandidate.signatureParamsValue
    })
    const rootOutcome = await callVerifier(args.verifyMessage, {
      address: field.root.address,
      chainId: field.root.chainId,
      message: { raw: bytesToHex(grantBase) },
      signature: bytesToHex(grantSignatureBytes)
    })
    if (rootOutcome === "unavailable") {
      args.grantVerificationResults.set(cacheKey, "unavailable")
      return { ok: false, reason: "grant_verification_unavailable" }
    }
    if (!rootOutcome) {
      args.grantVerificationResults.set(cacheKey, false)
      return { ok: false, reason: "bad_grant_signature" }
    }
    args.grantVerificationResults.set(cacheKey, true)
    const ttl = Math.min(
      delegationPolicy.grantCacheTtlSec ?? DEFAULT_GRANT_CACHE_TTL_SEC,
      Math.max(1, grantCandidate.params.expires - args.now)
    )
    try {
      await delegationPolicy.grantCache?.set(cacheKey, args.now + ttl)
    } catch {
      // A failed cache write only removes an optimization from this request.
    }
  }

  for (const extensionName of field.critical) {
    const handler = delegationPolicy.extensions?.[extensionName]
    if (!handler) return { ok: false, reason: "unsupported_critical_extension" }
    const member = field.extensions[extensionName]
    if (!member) return { ok: false, reason: "bad_delegation_field" }
    try {
      const outcome = await handler({
        request: args.request,
        field,
        member,
        grant,
        grantCreated: grantCandidate.params.created,
        grantExpires: grantCandidate.params.expires
      })
      if (outcome === "unavailable") {
        return { ok: false, reason: "critical_extension_unavailable" }
      }
      if (outcome === false || (typeof outcome === "object" && !outcome.ok)) {
        return {
          ok: false,
          reason: "delegation_extension_rejected",
          ...(typeof outcome === "object" && outcome.detail
            ? { detail: outcome.detail }
            : {})
        }
      }
    } catch (error) {
      if (error instanceof VerificationUnavailableError) {
        return { ok: false, reason: "critical_extension_unavailable" }
      }
      return { ok: false, reason: "delegation_extension_rejected" }
    }
  }

  const replayFailure = await validateReplayableInvalidation(
    args.policy,
    args.candidate.candidate
  )
  if (replayFailure) return replayFailure
  const nonceFailure = await consumeNonce(common.noncePlan)
  if (nonceFailure) return nonceFailure
  return {
    ok: true,
    principal: field.root,
    signer: field.delegate,
    delegated: true,
    delegationId: hexToBytes(field.id),
    label: args.candidate.candidate.label,
    components: args.candidate.candidate.components,
    params: requestParams,
    replay: common.replayable ? "replayable" : "non-replayable",
    binding: "request-bound"
  }
}

async function validateRequestCandidate(args: {
  request: Request
  bodyBytes: Uint8Array
  attempt: Attempt<ParsedKeyId>
  allowReplayable: boolean
  nonceStore: VerifyRequestArgs["nonceStore"]
  policy: NonNullable<VerifyRequestArgs["policy"]>
  now: number
  skew: number
  missingNonceReason?: "nonce_required" | "replayable_not_allowed"
}): Promise<
  | {
      signatureBase: Uint8Array
      signature: `0x${string}`
      noncePlan: NoncePlan
      replayable: boolean
    }
  | { failure: Failure }
> {
  const candidate = args.attempt.candidate.candidate
  const timeFailure = runTimeChecks({
    now: args.now,
    skew: args.skew,
    maxValiditySec: args.policy.maxValiditySec,
    created: candidate.params.created,
    expires: candidate.params.expires
  })
  if (timeFailure) return { failure: timeFailure }
  const { failure, plan } = runNonceChecks({
    allowReplayable: args.allowReplayable,
    params: candidate.params,
    now: args.now,
    nonceStore: args.nonceStore,
    nonceKey: args.policy.nonceKey,
    maxNonceWindowSec: args.policy.maxNonceWindowSec,
    clockSkewSec: args.skew,
    missingNonceReason: args.missingNonceReason
  })
  if (failure) return { failure }

  if (
    args.bodyBytes.length > 0 &&
    !args.request.headers.has("content-digest")
  ) {
    return { failure: { ok: false, reason: "content_digest_required" } }
  }
  if (args.request.headers.has("content-digest")) {
    if (!(await verifyContentDigest(args.request, args.bodyBytes))) {
      return { failure: { ok: false, reason: "bad_content_digest" } }
    }
  }
  let signatureBase: Uint8Array
  try {
    signatureBase = createSignatureBaseMinimal({
      request: args.request,
      components: candidate.components,
      signatureParamsValue: candidate.signatureParamsValue
    })
  } catch {
    return { failure: { ok: false, reason: "bad_signature" } }
  }
  const signatureBytes = base64Decode(candidate.sigB64)
  if (!signatureBytes?.length) {
    return { failure: { ok: false, reason: "bad_signature" } }
  }
  if (signatureBytes.length > 65_536) {
    return { failure: { ok: false, reason: "signature_too_large" } }
  }
  return {
    signatureBase,
    signature: bytesToHex(signatureBytes),
    noncePlan: plan,
    replayable: !candidate.params.nonce
  }
}

async function callVerifier(
  verifyMessage: VerifyMessageFn,
  input: Parameters<VerifyMessageFn>[0]
): Promise<boolean | "unavailable"> {
  try {
    return await verifyMessage(input)
  } catch (error) {
    return error instanceof VerificationUnavailableError ? "unavailable" : false
  }
}

async function validateReplayableInvalidation(
  policy: NonNullable<VerifyRequestArgs["policy"]>,
  candidate: SelectedSignature
): Promise<Failure | null> {
  if (candidate.params.nonce) return null
  if (!policy.replayableNotBefore && !policy.replayableInvalidated) {
    return { ok: false, reason: "replayable_not_allowed" }
  }
  const [notBefore, invalidated] = await Promise.all([
    policy.replayableNotBefore?.(candidate.params.keyid),
    policy.replayableInvalidated?.({
      keyid: candidate.params.keyid,
      signature: bytesToHex(base64Decode(candidate.sigB64) ?? new Uint8Array())
    })
  ])
  if (typeof notBefore === "number" && candidate.params.created < notBefore) {
    return { ok: false, reason: "replayable_not_allowed" }
  }
  return invalidated ? { ok: false, reason: "replayable_not_allowed" } : null
}

async function consumeNonce(plan: NoncePlan): Promise<Failure | null> {
  if (!plan.replayKey || !plan.replayStore) return null
  return (await plan.replayStore.consume(plan.replayKey, plan.replayTtlSeconds))
    ? null
    : { ok: false, reason: "nonce_reused" }
}

function validateGrantTime(args: {
  created: number
  expires: number
  now: number
  skew: number
  maxValidity: number
}): Failure | null {
  if (
    !Number.isInteger(args.created) ||
    !Number.isInteger(args.expires) ||
    args.expires <= args.created
  ) {
    return { ok: false, reason: "invalid_time" }
  }
  if (args.now + args.skew < args.created) {
    return { ok: false, reason: "grant_not_yet_valid" }
  }
  if (args.now - args.skew > args.expires) {
    return { ok: false, reason: "grant_expired" }
  }
  if (args.expires - args.created > args.maxValidity) {
    return { ok: false, reason: "grant_validity_too_long" }
  }
  return null
}

function resolveAudience(
  request: Request,
  configured: string | string[] | ((request: Request) => string) | undefined
): string {
  const requestOrigin = normalizeAudienceOrigin(sanitizeUrl(request.url).origin)
  if (configured === undefined) return requestOrigin
  if (typeof configured === "function") {
    const resolved = normalizeAudienceOrigin(configured(request))
    if (resolved !== requestOrigin) {
      throw new Erc8128Error(
        "INVALID_OPTIONS",
        "Resolved audience does not match the received request origin."
      )
    }
    return resolved
  }
  if (typeof configured === "string") {
    const resolved = normalizeAudienceOrigin(configured)
    if (resolved !== requestOrigin) {
      throw new Erc8128Error(
        "INVALID_OPTIONS",
        "Configured audience does not match the received request origin."
      )
    }
    return resolved
  }
  const normalized = configured.map(normalizeAudienceOrigin)
  if (!normalized.includes(requestOrigin)) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Request origin is not an accepted audience."
    )
  }
  return requestOrigin
}

function identityKey(identity: { chainId: number; address: string }): string {
  return `eip155:${identity.chainId}:${identity.address.toLowerCase()}`
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : fallback
}

function isUnavailableFailure(failure: Failure): boolean {
  return (
    failure.reason === "signature_verification_unavailable" ||
    failure.reason === "grant_verification_unavailable" ||
    failure.reason === "critical_extension_unavailable"
  )
}

type RequestShape = {
  hasQuery: boolean
  hasBody: boolean
  hasContentDigest: boolean
  hasContentType: boolean
}
