import { buildAcceptSignatureHeader } from "./lib/acceptSignature"
import {
  DEFAULT_MAX_DELEGATION_CHAIN_DEPTH,
  resolveDelegationChain
} from "./lib/delegation/delegationChain"
import {
  DELEGATION_COMPONENT,
  DELEGATION_FIELD_NAME,
  hashDelegation,
  normalizeAudienceOrigin,
  parseDelegationField,
  TAG_DELEGATED,
  TAG_REQUEST
} from "./lib/delegation/delegationField"
import { Erc8128Error, VerificationUnavailableError } from "./lib/Erc8128Error"
import { verifyCanonicalEoaSignature } from "./lib/ecdsa"
import { includesComponent } from "./lib/engine/componentIdentifier"
import { verifyContentDigest } from "./lib/engine/contentDigest"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase"
import { selectSignatureFromHeaders } from "./lib/engine/signatureHeaders"
import { parseKeyId } from "./lib/keyId"
import { requiredRequestBoundComponents } from "./lib/policies/isRequestBound"
import {
  ensureAuthority,
  normalizeClassBoundPolicies,
  normalizeComponentsList
} from "./lib/policies/normalizePolicies"
import {
  base64Decode,
  bytesToHex,
  readBodyBytes,
  sanitizeUrl,
  unixNow
} from "./lib/utilities"
import { buildAttempts, runNonceChecks, runTimeChecks } from "./lib/verifyUtils"
import type {
  Attempt,
  ComponentIdentifier,
  DelegationLink,
  NoncePlan,
  ParsedDelegationField,
  ResolvedDelegationChain,
  SelectedSignature,
  VerifyCandidate,
  VerifyDigestFn,
  VerifyMessageFn,
  VerifyRequestArgs,
  VerifyResult
} from "./types"

const DEFAULT_MAX_CANDIDATES = 8
const DEFAULT_GRANT_CACHE_TTL_SEC = 60

type ParsedKeyId = NonNullable<ReturnType<typeof parseKeyId>>
type Failure = Extract<VerifyResult, { ok: false }>
type RequestShape = {
  hasQuery: boolean
  hasBody: boolean
  hasContentDigest: boolean
  hasContentType: boolean
}
type AccountVerificationBudget = { remaining: number }

export async function verifyRequest(
  args: VerifyRequestArgs
): Promise<VerifyResult> {
  const { request, verifyMessage, verifyDigest, nonceStore, policy = {} } = args
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

  const candidates = selected.selected.filter(
    ({ params }) => params.tag === TAG_REQUEST || params.tag === TAG_DELEGATED
  )
  if (candidates.length === 0) {
    return { ok: false, reason: "no_acceptable_signature" }
  }
  const maximumCandidates = positiveInteger(
    policy.maxSignatureVerifications,
    DEFAULT_MAX_CANDIDATES
  )
  if (candidates.length > maximumCandidates) {
    return { ok: false, reason: "signature_too_large" }
  }

  const policyNow = policy.now?.()
  const now = finiteNonNegativeNumber(policyNow) ? policyNow : unixNow()
  const skew = finiteNonNegativeNumber(policy.clockSkewSec)
    ? policy.clockSkewSec
    : 30
  sanitizeUrl(request.url)
  const bodyBytes =
    request.body === null ? new Uint8Array() : await readBodyBytes(request)
  const shape: RequestShape = {
    hasQuery: true,
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
  const maximumChainDepth = positiveInteger(
    policy.delegation?.maxChainDepth,
    DEFAULT_MAX_DELEGATION_CHAIN_DEPTH
  )
  const accountVerificationBudget: AccountVerificationBudget = {
    remaining: positiveInteger(
      policy.maxAccountVerificationCalls,
      maximumCandidates + maximumChainDepth
    )
  }

  if (args.setHeaders) {
    try {
      args.setHeaders(
        "Accept-Signature",
        buildAcceptSignatureHeader({
          requestBoundRequired,
          classBoundPolicies,
          allowReplayable: policy.replayable ?? false
        })
      )
    } catch {
      // Advisory response headers cannot affect authentication.
    }
  }

  const context = {
    request,
    bodyBytes,
    shape,
    requestBoundExtras,
    requestBoundRequired,
    classBoundPolicies,
    verifyMessage,
    verifyDigest,
    nonceStore,
    policy,
    now,
    skew,
    accountVerificationBudget
  }
  let firstFailure: Failure | null = null
  let firstUnavailable: Failure | null = null
  for (const candidate of candidates) {
    const failure = validateCandidateEnvelope(candidate)
    if (failure) {
      firstFailure ??= failure
      continue
    }
    const key = parseKeyId(candidate.params.keyid)
    if (key === null) {
      firstFailure ??= { ok: false, reason: "invalid_keyid" }
      continue
    }
    const outcome =
      candidate.params.tag === TAG_DELEGATED
        ? await verifyDelegatedCandidate({
            ...context,
            candidate: { candidate, key }
          })
        : await verifyBaseCandidate({
            ...context,
            candidate: { candidate, key }
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

function validateCandidateEnvelope(
  candidate: SelectedSignature
): Failure | null {
  if (candidate.sigB64 === undefined) {
    return { ok: false, reason: "signature_input_invalid" }
  }
  if (candidate.params.alg !== undefined) {
    return { ok: false, reason: "unsupported_algorithm" }
  }
  return null
}

async function verifyBaseCandidate(
  args: CommonCandidateArgs
): Promise<VerifyResult> {
  const { candidate, key } = args.candidate
  const principal = args.policy.principal ?? "either"
  if (principal === "delegated") {
    return { ok: false, reason: "principal_not_allowed" }
  }
  const requiredWhenPresent = getRequiredWhenPresent(args)
  const built = buildAttempts([args.candidate], {
    ...args.shape,
    requestBoundExtras: args.requestBoundExtras,
    requestBoundRequired: args.requestBoundRequired,
    requiredWhenPresent,
    classBoundPolicies: args.classBoundPolicies
  })
  const attempt = built.attempts[0]
  if (!attempt) return { ok: false, reason: "insufficient_coverage" }
  const common = await validateRequestCandidate({
    ...args,
    attempt,
    allowReplayable: args.policy.replayable ?? false
  })
  if ("failure" in common) return common.failure

  const invalidationFailure = await validateReplayableInvalidation(
    args.policy,
    candidate
  )
  if (invalidationFailure) return invalidationFailure

  const proof =
    args.policy.accountVerification === "eoa-only"
      ? verifyCanonicalEoaSignature({
          address: key.address,
          message: common.signatureBase,
          signature: common.signature
        })
      : await callMessageVerifier(
          args.verifyMessage,
          {
            address: key.address,
            chainId: key.chainId,
            message: { raw: bytesToHex(common.signatureBase) },
            signature: common.signature
          },
          args.accountVerificationBudget
        )
  if (proof === "unavailable") {
    return { ok: false, reason: "signature_verification_unavailable" }
  }
  if (!proof) return { ok: false, reason: "bad_signature" }

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

async function verifyDelegatedCandidate(
  args: CommonCandidateArgs
): Promise<VerifyResult> {
  const delegationPolicy = args.policy.delegation
  if (delegationPolicy === undefined) {
    return { ok: false, reason: "unsupported_delegation" }
  }
  const fieldValue = args.request.headers.get(DELEGATION_FIELD_NAME)
  if (!fieldValue) return { ok: false, reason: "bad_delegation_field" }

  let parsed: ParsedDelegationField
  try {
    parsed = parseDelegationField(fieldValue, delegationPolicy)
  } catch (error) {
    return {
      ok: false,
      reason:
        error instanceof Erc8128Error && error.code === "DELEGATION_TOO_LARGE"
          ? "delegation_too_large"
          : "bad_delegation_field"
    }
  }
  let chain: ResolvedDelegationChain
  try {
    chain = resolveDelegationChain(parsed, delegationPolicy.maxChainDepth)
  } catch (error) {
    if (error instanceof Erc8128Error) {
      if (error.code === "DELEGATION_CHAIN_TOO_LONG") {
        return { ok: false, reason: "delegation_chain_too_long" }
      }
      if (error.code === "DELEGATION_CHAIN_DISCONTINUOUS") {
        return { ok: false, reason: "delegation_chain_discontinuous" }
      }
      if (error.code === "DELEGATION_ATTENUATION_VIOLATION") {
        return { ok: false, reason: "delegation_attenuation_violation" }
      }
    }
    return { ok: false, reason: "bad_delegation_field" }
  }
  const root = chain.chain.links[0]?.grant
  const leaf = chain.chain.links.at(-1)?.grant
  if (root === undefined || leaf === undefined) {
    return { ok: false, reason: "bad_delegation_field" }
  }
  if (args.candidate.candidate.params.keyid !== leaf.delegate) {
    return { ok: false, reason: "delegate_mismatch" }
  }
  if ((args.policy.principal ?? "either") === "direct") {
    return { ok: false, reason: "principal_not_allowed" }
  }

  for (const link of chain.chain.links) {
    const timeFailure = validateGrantTime({
      link,
      now: args.now,
      skew: args.skew,
      maximum: delegationPolicy.maxGrantValiditySec
    })
    if (timeFailure) return timeFailure
  }
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
    requestParams.created < leaf.validAfter - args.skew ||
    requestParams.expires > leaf.validUntil
  ) {
    return { ok: false, reason: "request_outside_grant_window" }
  }
  if (
    requestParams.expires - requestParams.created >
    chain.effectiveMaxRequestValiditySeconds
  ) {
    return { ok: false, reason: "delegation_request_validity_exceeded" }
  }

  let requestOrigin: string
  try {
    requestOrigin = normalizeAudienceOrigin(
      sanitizeUrl(args.request.url).origin,
      delegationPolicy
    )
  } catch {
    return { ok: false, reason: "audience_mismatch" }
  }
  if (!chain.effectiveAudiences.includes(requestOrigin)) {
    return { ok: false, reason: "audience_mismatch" }
  }
  if (
    !includesComponent(
      args.candidate.candidate.components,
      DELEGATION_COMPONENT
    )
  ) {
    return { ok: false, reason: "delegation_not_covered" }
  }
  for (const component of chain.effectiveRequiredComponents) {
    if (!isSupportedDelegationComponent(component)) {
      return { ok: false, reason: "delegation_components_unsupported" }
    }
    if (!includesComponent(args.candidate.candidate.components, component)) {
      return { ok: false, reason: "delegation_components_uncovered" }
    }
  }
  if (
    requestParams.nonce === undefined &&
    chain.effectiveRequireNonReplayable
  ) {
    return { ok: false, reason: "delegation_nonce_required" }
  }
  if (
    chain.chain.links.some(({ grant }) => grant.permissions.length > 0) &&
    delegationPolicy.permissionsSupported === false
  ) {
    return { ok: false, reason: "unsupported_permissions" }
  }
  const requiredWhenPresent = getRequiredWhenPresent(args)
  const built = buildAttempts([args.candidate], {
    ...args.shape,
    requestBoundExtras: args.requestBoundExtras,
    requestBoundRequired: args.requestBoundRequired,
    requiredWhenPresent,
    classBoundPolicies: args.classBoundPolicies
  })
  const attempt = built.attempts[0]
  if (!attempt) return { ok: false, reason: "insufficient_coverage" }
  const common = await validateRequestCandidate({
    ...args,
    attempt,
    allowReplayable:
      !chain.effectiveRequireNonReplayable && (args.policy.replayable ?? false),
    missingNonceReason: "replayable_not_allowed"
  })
  if ("failure" in common) return common.failure

  const invalidationFailure = await validateReplayableInvalidation(
    args.policy,
    args.candidate.candidate
  )
  if (invalidationFailure) return invalidationFailure

  const leafProof = leaf.delegateIsEOA
    ? verifyCanonicalEoaSignature({
        address: args.candidate.key.address,
        message: common.signatureBase,
        signature: common.signature
      })
    : await callMessageVerifier(
        args.verifyMessage,
        {
          address: args.candidate.key.address,
          chainId: args.candidate.key.chainId,
          message: { raw: bytesToHex(common.signatureBase) },
          signature: common.signature
        },
        args.accountVerificationBudget
      )
  if (leafProof === "unavailable") {
    return { ok: false, reason: "signature_verification_unavailable" }
  }
  if (!leafProof) return { ok: false, reason: "bad_signature" }

  for (const link of [...chain.chain.links].reverse()) {
    const proof = await verifyGrantProof({
      link,
      verifyDigest: args.verifyDigest,
      now: args.now,
      cache: delegationPolicy.grantCache,
      cacheTtl: delegationPolicy.grantCacheTtlSec,
      accountVerificationBudget: args.accountVerificationBudget
    })
    if (proof === "unavailable") {
      return { ok: false, reason: "grant_verification_unavailable" }
    }
    if (!proof) return { ok: false, reason: "bad_grant_signature" }
  }
  let statuses: Awaited<ReturnType<typeof delegationPolicy.verifyStatuses>>
  try {
    statuses = await delegationPolicy.verifyStatuses(
      chain.chain.links.map((link) => ({ link, request: args.request }))
    )
  } catch {
    return { ok: false, reason: "revocation_unavailable" }
  }
  if (statuses.length !== chain.chain.links.length) {
    return { ok: false, reason: "revocation_unavailable" }
  }
  for (const status of statuses) {
    if (status === "unavailable") {
      return { ok: false, reason: "revocation_unavailable" }
    }
    if (status === "revoked") {
      return { ok: false, reason: "authorization_revoked" }
    }
    if (status === "epoch-mismatch") {
      return { ok: false, reason: "authorization_epoch_mismatch" }
    }
    if (status !== "valid") {
      return { ok: false, reason: "revocation_unavailable" }
    }
  }

  const requiredPermissions = delegationPolicy.requiredPermissions ?? []
  if (
    requiredPermissions.some(
      (permission) => !chain.effectivePermissions.includes(permission)
    )
  ) {
    return { ok: false, reason: "insufficient_permissions" }
  }
  const nonceFailure = await consumeNonce(common.noncePlan)
  if (nonceFailure) return nonceFailure

  const principal = parseKeyId(root.issuer)
  if (principal === null) return { ok: false, reason: "bad_delegation_field" }
  return {
    ok: true,
    principal,
    signer: args.candidate.key,
    delegated: true,
    binding: attempt.kind,
    replay: common.replayable ? "replayable" : "non-replayable",
    delegationIds: chain.chain.links.map(({ grant }) => grant.id)
  }
}

type CommonCandidateArgs = {
  request: Request
  bodyBytes: Uint8Array
  shape: RequestShape
  requestBoundExtras: ReturnType<typeof normalizeComponentsList>
  requestBoundRequired: ReturnType<typeof requiredRequestBoundComponents>
  classBoundPolicies: ReturnType<typeof normalizeClassBoundPolicies>
  candidate: VerifyCandidate<ParsedKeyId>
  verifyMessage: VerifyMessageFn
  verifyDigest: VerifyDigestFn | undefined
  nonceStore: VerifyRequestArgs["nonceStore"]
  policy: NonNullable<VerifyRequestArgs["policy"]>
  now: number
  skew: number
  accountVerificationBudget: AccountVerificationBudget
}

function getRequiredWhenPresent(args: CommonCandidateArgs) {
  return normalizeComponentsList([
    ...(args.shape.hasBody || args.shape.hasContentDigest
      ? (["content-digest"] as const)
      : []),
    ...(args.shape.hasContentType ? (["content-type"] as const) : []),
    ...(args.policy.requiredCoveredHeadersWhenPresent ?? []).filter(
      (component) =>
        args.request.headers.has(
          typeof component === "string" ? component : component.name
        )
    )
  ])
}

async function validateRequestCandidate(
  args: CommonCandidateArgs & {
    attempt: Attempt<ParsedKeyId>
    allowReplayable: boolean
    missingNonceReason?: "nonce_required" | "replayable_not_allowed"
  }
): Promise<
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
    ...(args.missingNonceReason === undefined
      ? {}
      : { missingNonceReason: args.missingNonceReason })
  })
  if (failure) return { failure }
  if (
    args.bodyBytes.length > 0 &&
    !args.request.headers.has("content-digest")
  ) {
    return { failure: { ok: false, reason: "content_digest_required" } }
  }
  if (
    args.policy.contentDigest === "require" &&
    !args.request.headers.has("content-digest")
  ) {
    return { failure: { ok: false, reason: "content_digest_required" } }
  }
  if (
    args.request.headers.has("content-digest") &&
    !(await verifyContentDigest(args.request, args.bodyBytes))
  ) {
    return { failure: { ok: false, reason: "bad_content_digest" } }
  }
  if (candidate.sigB64 === undefined) {
    return { failure: { ok: false, reason: "signature_input_invalid" } }
  }
  const signatureBytes = base64Decode(candidate.sigB64)
  if (!signatureBytes?.length) {
    return { failure: { ok: false, reason: "bad_signature" } }
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
  return {
    signatureBase,
    signature: bytesToHex(signatureBytes),
    noncePlan: plan,
    replayable: candidate.params.nonce === undefined
  }
}

async function verifyGrantProof(args: {
  link: DelegationLink
  verifyDigest: VerifyDigestFn | undefined
  now: number
  cache: NonNullable<
    NonNullable<VerifyRequestArgs["policy"]>["delegation"]
  >["grantCache"]
  cacheTtl: number | undefined
  accountVerificationBudget: AccountVerificationBudget
}): Promise<boolean | "unavailable"> {
  const digest = hashDelegation(args.link.grant)
  const cacheKey = `${digest}\u0000${args.link.signature}`
  try {
    if ((await args.cache?.get(cacheKey)) === true) return true
  } catch {
    // A proof cache is only an optimization.
  }
  if (args.verifyDigest === undefined) return "unavailable"
  const issuer = parseKeyId(args.link.grant.issuer)
  if (issuer === null) return false
  const proof = await callDigestVerifier(
    args.verifyDigest,
    {
      address: issuer.address,
      chainId: issuer.chainId,
      digest,
      signature: args.link.signature
    },
    args.accountVerificationBudget
  )
  if (proof !== true) return proof
  const ttl = Math.min(
    args.cacheTtl ?? DEFAULT_GRANT_CACHE_TTL_SEC,
    Math.max(1, args.link.grant.validUntil - args.now)
  )
  try {
    await args.cache?.set(cacheKey, args.now + ttl)
  } catch {
    // A failed cache write does not affect the verified proof.
  }
  return true
}

function validateGrantTime(args: {
  link: DelegationLink
  now: number
  skew: number
  maximum: number | undefined
}): Failure | null {
  const { validAfter, validUntil } = args.link.grant
  if (args.now < validAfter - args.skew) {
    return { ok: false, reason: "grant_not_yet_valid" }
  }
  if (args.now > validUntil + args.skew) {
    return { ok: false, reason: "grant_expired" }
  }
  if (args.maximum !== undefined && validUntil - validAfter > args.maximum) {
    return { ok: false, reason: "grant_validity_too_long" }
  }
  return null
}

function isSupportedDelegationComponent(
  component: ComponentIdentifier
): boolean {
  if (component.params?.req || component.params?.tr || component.params?.name) {
    return false
  }
  if (!component.name.startsWith("@")) return true
  return ["@scheme", "@authority", "@method", "@path", "@query"].includes(
    component.name
  )
}

async function callMessageVerifier(
  verify: VerifyMessageFn,
  input: Parameters<VerifyMessageFn>[0],
  budget: AccountVerificationBudget
): Promise<boolean | "unavailable"> {
  if (budget.remaining <= 0) return "unavailable"
  budget.remaining -= 1
  try {
    return await verify(input)
  } catch (error) {
    return error instanceof VerificationUnavailableError ? "unavailable" : false
  }
}

async function callDigestVerifier(
  verify: VerifyDigestFn,
  input: Parameters<VerifyDigestFn>[0],
  budget: AccountVerificationBudget
): Promise<boolean | "unavailable"> {
  if (budget.remaining <= 0) return "unavailable"
  budget.remaining -= 1
  try {
    return await verify(input)
  } catch (error) {
    return error instanceof VerificationUnavailableError ? "unavailable" : false
  }
}

async function validateReplayableInvalidation(
  policy: NonNullable<VerifyRequestArgs["policy"]>,
  candidate: SelectedSignature
): Promise<Failure | null> {
  if (candidate.params.nonce !== undefined) return null
  if (!policy.replayableNotBefore && !policy.replayableInvalidated) {
    return { ok: false, reason: "replayable_not_allowed" }
  }
  let notBefore: number | null | undefined
  let invalidated: boolean | undefined
  try {
    ;[notBefore, invalidated] = await Promise.all([
      policy.replayableNotBefore?.(candidate.params.keyid),
      policy.replayableInvalidated?.({
        keyid: candidate.params.keyid,
        signature: bytesToHex(
          base64Decode(candidate.sigB64 ?? "") ?? new Uint8Array()
        )
      })
    ])
  } catch {
    return { ok: false, reason: "revocation_unavailable" }
  }
  if (
    notBefore !== null &&
    notBefore !== undefined &&
    !finiteNonNegativeNumber(notBefore)
  ) {
    return { ok: false, reason: "replayable_not_allowed" }
  }
  if (typeof notBefore === "number" && candidate.params.created < notBefore) {
    return { ok: false, reason: "replayable_not_allowed" }
  }
  return invalidated ? { ok: false, reason: "replayable_not_allowed" } : null
}

async function consumeNonce(plan: NoncePlan): Promise<Failure | null> {
  if (!plan.replayKey || !plan.replayStore) return null
  try {
    return (await plan.replayStore.consume(
      plan.replayKey,
      plan.replayTtlSeconds
    ))
      ? null
      : { ok: false, reason: "nonce_reused" }
  } catch {
    return { ok: false, reason: "signature_verification_unavailable" }
  }
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : fallback
}

function finiteNonNegativeNumber(value: number | undefined): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
}

function isUnavailableFailure(failure: Failure): boolean {
  return (
    failure.reason === "signature_verification_unavailable" ||
    failure.reason === "grant_verification_unavailable" ||
    failure.reason === "revocation_unavailable"
  )
}
