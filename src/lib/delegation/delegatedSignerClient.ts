import { signDelegatedRequest } from "../../sign"
import type {
  DelegatedSignerClientOptions,
  DelegationAudiencePolicy,
  DelegationChain,
  EthHttpSigner,
  FetchOptions,
  SignerClient,
  SignOptions
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { componentIdentifierEquals } from "../engine/componentIdentifier"
import { collectSignatureLabels } from "../engine/signatureLabels"
import { invokeFetch } from "../invokeFetch"
import { matchRoutePolicy } from "../matchRoutePolicy"
import {
  redirectMethod,
  redirectStatuses,
  unsignedRedirectHeaders
} from "../redirects"
import { resolveContentDigestMode } from "../resolveContentDigest"
import { sanitizeUrl, unixNow } from "../utilities"
import { resolveDelegationChain } from "./delegationChain"
import {
  DELEGATION_COMPONENT,
  DELEGATION_FIELD_NAME,
  formatDelegationField,
  normalizeAudienceOrigin,
  parseDelegationField
} from "./delegationField"

const REQUEST_INIT_KEYS = new Set([
  "method",
  "headers",
  "body",
  "signal",
  "credentials",
  "mode",
  "cache",
  "redirect",
  "referrer",
  "integrity",
  "keepalive",
  "window"
])

export function createDelegatedSignerClient(
  session: EthHttpSigner,
  delegation: DelegationChain,
  defaults?: DelegatedSignerClientOptions
): SignerClient {
  const audiencePolicy = {
    allowLoopbackAudiences: defaults?.allowLoopbackAudiences === true
  }
  const fieldValue = formatDelegationField(delegation)
  const resolved = resolveDelegationChain(
    parseDelegationField(fieldValue, audiencePolicy),
    undefined
  )
  const leaf = resolved.chain.links.at(-1)?.grant
  if (leaf === undefined) {
    throw new Erc8128Error("INVALID_OPTIONS", "Delegation Chain is empty.")
  }
  const leafGrant = leaf
  const expectedDelegate = `eip155:${session.chainId}:${session.address.toLowerCase()}`
  if (leaf.delegate !== expectedDelegate) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Session signer does not match the Leaf Delegate."
    )
  }

  const serverConfigs = new Map(
    defaults?.serverConfigs
      ? Object.entries(defaults.serverConfigs).map(([origin, config]) => [
          normalizeAudienceOrigin(origin, audiencePolicy),
          config
        ])
      : []
  )

  async function signRequestForDelegation(
    input: RequestInfo,
    init: RequestInit | undefined,
    options: SignOptions | undefined,
    useDefaultNonce = true
  ): Promise<Request> {
    const request = new Request(input, init)
    assertAudience(request.url, resolved.effectiveAudiences, audiencePolicy)
    const requestOrigin = sanitizeUrl(request.url).origin
    const serverConfig = serverConfigs.get(requestOrigin)
    const routePolicy = matchRoutePolicy(
      request.method,
      sanitizeUrl(request.url).pathname,
      serverConfig?.route_policies
    )
    const now = unixNow()
    const created = Math.max(
      options?.created ?? defaults?.created ?? now,
      leafGrant.validAfter
    )
    const requestedTtl = Math.min(
      options?.ttlSeconds ?? defaults?.ttlSeconds ?? 60,
      serverConfig?.max_validity_sec ?? Number.POSITIVE_INFINITY,
      resolved.effectiveMaxRequestValiditySeconds
    )
    const expires = Math.min(
      options?.expires ?? defaults?.expires ?? created + requestedTtl,
      created + requestedTtl,
      leafGrant.validUntil
    )
    if (expires <= created) {
      throw new Erc8128Error("INVALID_OPTIONS", "Delegation has expired.")
    }
    const requestedReplayable =
      options?.nonce === null ||
      (options?.nonce === undefined &&
        ((useDefaultNonce && defaults?.nonce === null) ||
          defaults?.preferReplayable === true))
    const replayable = requestedReplayable && routePolicy?.replayable !== false
    if (replayable && resolved.effectiveRequireNonReplayable) {
      throw new Erc8128Error(
        "INVALID_OPTIONS",
        "Delegation requires non-replayable requests."
      )
    }

    const headers = new Headers(request.headers)
    headers.set(DELEGATION_FIELD_NAME, fieldValue)
    const labels = collectSignatureLabels(
      headers.get("signature-input"),
      headers.get("signature")
    )
    let label = options?.label ?? defaults?.label ?? "request"
    let suffix = 2
    while (labels.has(label)) {
      label = `${options?.label ?? defaults?.label ?? "request"}${suffix}`
      suffix += 1
    }
    const components = [...resolved.effectiveRequiredComponents]
    for (const component of [
      ...(defaults?.components ?? []),
      ...(options?.components ?? []),
      ...(routePolicy?.additionalRequestBoundComponents ?? [])
    ]) {
      if (
        !components.some((existing) =>
          componentIdentifierEquals(existing, component)
        )
      ) {
        components.push(
          typeof component === "string" ? { name: component } : component
        )
      }
    }
    components.push(DELEGATION_COMPONENT)
    return signDelegatedRequest(new Request(request, { headers }), session, {
      ...defaults,
      ...options,
      label,
      nonce: replayable
        ? null
        : options?.nonce === null ||
            (useDefaultNonce && defaults?.nonce === null)
          ? undefined
          : (options?.nonce ?? (useDefaultNonce ? defaults?.nonce : undefined)),
      created,
      expires,
      contentDigest: resolveContentDigestMode(
        options?.contentDigest ?? defaults?.contentDigest,
        routePolicy?.contentDigest
      ),
      components
    })
  }

  const signRequestBound: SignerClient["signRequest"] = async (
    input: RequestInfo,
    initOrOptions?: RequestInit | SignOptions,
    options?: SignOptions
  ) => {
    const split = splitInitAndOptions(initOrOptions, options)
    return signRequestForDelegation(input, split.init, split.options)
  }

  const fetchBound: SignerClient["fetch"] = async (
    input: RequestInfo,
    initOrOptions?: RequestInit | FetchOptions,
    options?: FetchOptions
  ) => {
    const split = splitInitAndOptions<FetchOptions>(initOrOptions, options)
    const fetchImpl = split.options?.fetch ?? defaults?.fetch
    const initialRequest = new Request(input, split.init)
    const redirectMode = initialRequest.redirect
    let nextInput: RequestInfo = initialRequest
    let nextInit: RequestInit | undefined
    let signingOptions = split.options
    for (let redirects = 0; redirects <= 10; redirects += 1) {
      const signed = await signRequestForDelegation(
        nextInput,
        nextInit,
        signingOptions,
        redirects === 0
      )
      const redirectedBody =
        signed.method === "GET" || signed.method === "HEAD"
          ? undefined
          : await signed.clone().arrayBuffer()
      const response = await invokeFetch(
        fetchImpl,
        new Request(signed, { redirect: "manual" })
      )
      if (!redirectStatuses.has(response.status)) return response
      if (redirectMode === "manual") return response
      if (redirectMode === "error") {
        throw new Erc8128Error(
          "UNSUPPORTED_REQUEST",
          "A redirect was encountered while redirect mode was set to error."
        )
      }
      const location = response.headers.get("location")
      if (!location) return response
      if (redirects === 10) {
        throw new Erc8128Error("UNSUPPORTED_REQUEST", "Too many redirects.")
      }
      const target = new URL(location, signed.url)
      assertAudience(target.href, resolved.effectiveAudiences, audiencePolicy)
      const method = redirectMethod(response.status, signed.method)
      nextInput = target.href
      if (typeof signingOptions?.nonce === "string") {
        const { nonce: _usedNonce, ...redirectOptions } = signingOptions
        signingOptions = redirectOptions
      }
      nextInit = {
        method,
        headers: unsignedRedirectHeaders(
          signed.headers,
          new URL(signed.url).origin,
          target.origin,
          true
        ),
        redirect: redirectMode,
        ...(method === "GET" || method === "HEAD"
          ? {}
          : { body: redirectedBody })
      }
    }
    throw new Erc8128Error("UNSUPPORTED_REQUEST", "Redirect processing failed.")
  }

  return {
    signRequest: signRequestBound,
    fetch: fetchBound,
    signedFetch: fetchBound,
    setServerConfig(origin, config) {
      const normalized = normalizeAudienceOrigin(origin, audiencePolicy)
      if (config === null) serverConfigs.delete(normalized)
      else serverConfigs.set(normalized, config)
    }
  }
}

function splitInitAndOptions<T extends SignOptions>(
  initOrOptions?: RequestInit | T,
  options?: T
): { init?: RequestInit; options?: T } {
  if (options !== undefined)
    return { init: initOrOptions as RequestInit, options }
  if (
    initOrOptions &&
    Object.keys(initOrOptions).some((key) => REQUEST_INIT_KEYS.has(key))
  ) {
    return { init: initOrOptions as RequestInit }
  }
  return { options: initOrOptions as T | undefined }
}

function assertAudience(
  urlValue: string,
  audiences: string[],
  audiencePolicy: DelegationAudiencePolicy
): void {
  const origin = normalizeAudienceOrigin(
    sanitizeUrl(urlValue).origin,
    audiencePolicy
  )
  if (!audiences.includes(origin)) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      `Origin ${origin} is outside the delegation Audience.`
    )
  }
}
