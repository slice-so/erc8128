import { signDelegatedRequest } from "../../sign"
import type {
  DelegationGrant,
  EthHttpSigner,
  FetchOptions,
  SignerClient,
  SignerClientOptions,
  SignOptions
} from "../../types"
import { Erc8128Error } from "../Erc8128Error"
import { parseSignatureInputHeader } from "../engine/createSignatureInput"
import {
  appendDictionaryMember,
  serializeSignatureHeader,
  serializeSignatureInputHeader
} from "../engine/serializations"
import {
  allocateSignatureLabel,
  collectSignatureLabels
} from "../engine/signatureLabels"
import { invokeFetch } from "../invokeFetch"
import { formatKeyId, keyIdEquals } from "../keyId"
import {
  redirectMethod,
  redirectStatuses,
  unsignedRedirectHeaders
} from "../redirects"
import { sanitizeUrl, unixNow } from "../utilities"
import { getDelegationGrantSignatureBase } from "./createDelegationGrant"
import {
  DELEGATION_COMPONENT,
  DELEGATION_FIELD_NAME,
  normalizeAudienceOrigin,
  parseDelegationField,
  TAG_DELEGATION
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
  grant: DelegationGrant,
  defaults?: Omit<
    SignerClientOptions,
    "authorizationPolicy" | "authorizationExpiresAt"
  >
): SignerClient {
  const resolvedGrant = grant
  getDelegationGrantSignatureBase(resolvedGrant)
  const field = parseDelegationField(resolvedGrant.fieldValue)
  const [grantInput] = parseSignatureInputHeader(
    `authorization=${resolvedGrant.grantSignatureInput}`
  )
  if (
    grantInput === undefined ||
    grantInput.params.tag !== TAG_DELEGATION ||
    grantInput.params.nonce !== undefined ||
    !keyIdEquals(
      grantInput.params.keyid,
      formatKeyId(field.root.chainId, field.root.address)
    ) ||
    grantInput.components.length !== 1 ||
    grantInput.components[0]?.name !== DELEGATION_FIELD_NAME ||
    grantInput.components[0]?.params?.sf !== true
  ) {
    throw new Erc8128Error(
      "PARSE_ERROR",
      "DelegationGrant signature input is invalid."
    )
  }
  if (
    session.chainId !== field.delegate.chainId ||
    session.address.toLowerCase() !== field.delegate.address.toLowerCase()
  ) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      "Session signer does not match delegate."
    )
  }

  const serverConfigs = new Map(
    defaults?.serverConfigs
      ? Object.entries(defaults.serverConfigs).map(([origin, config]) => [
          normalizeAudienceOrigin(origin),
          config
        ])
      : []
  )

  async function signRequestForGrant(
    input: RequestInfo,
    init: RequestInit | undefined,
    options: SignOptions | undefined
  ): Promise<Request> {
    const request = new Request(input, init)
    assertAudience(request.url, field.audiences)
    const requestOrigin = sanitizeUrl(request.url).origin
    const serverConfig = serverConfigs.get(requestOrigin)
    const now = unixNow()
    const created = Math.max(options?.created ?? now, grantInput.params.created)
    const requestedTtl = Math.min(
      options?.ttlSeconds ?? defaults?.ttlSeconds ?? 60,
      serverConfig?.max_validity_sec ?? Number.POSITIVE_INFINITY
    )
    const expires = Math.min(
      options?.expires ?? created + requestedTtl,
      created + requestedTtl,
      field.maxAge === undefined
        ? Number.POSITIVE_INFINITY
        : created + field.maxAge,
      grantInput.params.expires
    )
    if (expires <= created) {
      throw new Erc8128Error("INVALID_OPTIONS", "Delegation grant has expired.")
    }

    const headers = new Headers(request.headers)
    headers.set(DELEGATION_FIELD_NAME, field.fieldValue)
    const usedLabels = collectSignatureLabels(
      headers.get("signature-input"),
      headers.get("signature")
    )
    const authorizationLabel = allocateSignatureLabel(
      "authorization",
      usedLabels
    )
    usedLabels.add(authorizationLabel)
    const requestLabel = allocateSignatureLabel(
      options?.label ?? defaults?.label ?? "request",
      usedLabels
    )
    headers.set(
      "signature-input",
      appendDictionaryMember(
        headers.get("signature-input"),
        serializeSignatureInputHeader(
          authorizationLabel,
          resolvedGrant.grantSignatureInput
        )
      )
    )
    headers.set(
      "signature",
      appendDictionaryMember(
        headers.get("signature"),
        serializeSignatureHeader(
          authorizationLabel,
          resolvedGrant.grantSignatureB64
        )
      )
    )

    const replay = options?.replay ?? "non-replayable"
    if (replay === "replayable" && !field.allowReplayable) {
      throw new Erc8128Error(
        "INVALID_OPTIONS",
        "Delegation does not authorize replayable requests."
      )
    }
    return signDelegatedRequest(new Request(request, { headers }), session, {
      ...defaults,
      ...options,
      label: requestLabel,
      binding: "request-bound",
      replay,
      created,
      expires,
      components: [
        ...field.components,
        ...(options?.components ?? []),
        DELEGATION_COMPONENT
      ]
    })
  }

  const signRequestBound: SignerClient["signRequest"] = async (
    input: RequestInfo,
    initOrOptions?: RequestInit | SignOptions,
    options?: SignOptions
  ) => {
    const split = splitInitAndOptions(initOrOptions, options)
    return signRequestForGrant(input, split.init, split.options)
  }

  const fetchBound: SignerClient["fetch"] = async (
    input: RequestInfo,
    initOrOptions?: RequestInit | FetchOptions,
    options?: FetchOptions
  ) => {
    const split = splitInitAndOptions<FetchOptions>(initOrOptions, options)
    const fetchImpl = split.options?.fetch ?? defaults?.fetch
    let nextInput: RequestInfo = input
    let nextInit = split.init
    let signingOptions = split.options
    for (let redirects = 0; redirects <= 10; redirects += 1) {
      const signed = await signRequestForGrant(
        nextInput,
        nextInit,
        signingOptions
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
      const location = response.headers.get("location")
      if (!location) return response
      if (redirects === 10) {
        throw new Erc8128Error("UNSUPPORTED_REQUEST", "Too many redirects.")
      }
      const target = new URL(location, signed.url)
      assertAudience(target.href, field.audiences)
      const method = redirectMethod(response.status, signed.method)
      nextInput = target.href
      if (typeof signingOptions?.nonce === "string") {
        const { nonce: _usedNonce, ...redirectOptions } = signingOptions
        signingOptions = redirectOptions
      }
      nextInit = {
        method,
        headers: unsignedRedirectHeaders(signed.headers, true),
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
      const normalized = normalizeAudienceOrigin(origin)
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

function assertAudience(urlValue: string, audiences: string[]): void {
  const origin = normalizeAudienceOrigin(sanitizeUrl(urlValue).origin)
  if (!audiences.includes(origin)) {
    throw new Erc8128Error(
      "INVALID_OPTIONS",
      `Origin ${origin} is outside the delegation audience.`
    )
  }
}
