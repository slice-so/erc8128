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
import {
  parseSignatureHeader,
  parseSignatureInputHeader
} from "../engine/createSignatureInput"
import {
  appendDictionaryMember,
  serializeSignatureHeader,
  serializeSignatureInputHeader
} from "../engine/serializations"
import { formatKeyId, keyIdEquals } from "../keyId"
import { sanitizeUrl, unixNow } from "../utilities"
import { validateDelegationGrantArtifact } from "./createDelegationGrant"
import {
  DELEGATION_COMPONENT,
  DELEGATION_FIELD_NAME,
  normalizeAudienceOrigin,
  parseDelegationField,
  TAG_DELEGATION
} from "./delegationField"

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])
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
  validateDelegationGrantArtifact(resolvedGrant)
  const field = parseDelegationField(resolvedGrant.fieldValue)
  const [grantInput] = parseSignatureInputHeader(
    `grant=${resolvedGrant.grantSignatureInput}`
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
    const usedLabels = collectLabels(
      headers.get("signature-input"),
      headers.get("signature")
    )
    const grantLabel = allocateLabel("grant", usedLabels)
    usedLabels.add(grantLabel)
    const requestLabel = allocateLabel(
      options?.label ?? defaults?.label ?? "eth",
      usedLabels
    )
    headers.set(
      "signature-input",
      appendDictionaryMember(
        headers.get("signature-input"),
        serializeSignatureInputHeader(
          grantLabel,
          resolvedGrant.grantSignatureInput
        )
      )
    )
    headers.set(
      "signature",
      appendDictionaryMember(
        headers.get("signature"),
        serializeSignatureHeader(grantLabel, resolvedGrant.grantSignatureB64)
      )
    )

    return signDelegatedRequest(new Request(request, { headers }), session, {
      ...defaults,
      ...options,
      label: requestLabel,
      binding: "request-bound",
      replay: field.replayable ? "replayable" : "non-replayable",
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
    const fetchImpl =
      split.options?.fetch ?? defaults?.fetch ?? globalThis.fetch
    if (typeof fetchImpl !== "function") {
      throw new Erc8128Error(
        "UNSUPPORTED_REQUEST",
        "No fetch implementation available."
      )
    }
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
      const response = await fetchImpl(
        new Request(signed, { redirect: "manual" })
      )
      if (!REDIRECT_STATUSES.has(response.status)) return response
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
        headers: unsignedHeaders(signed.headers),
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

function collectLabels(
  signatureInput: string | null,
  signature: string | null
): Set<string> {
  try {
    return new Set([
      ...(signatureInput === null
        ? []
        : parseSignatureInputHeader(signatureInput).map(({ label }) => label)),
      ...(signature === null ? [] : parseSignatureHeader(signature).keys())
    ])
  } catch {
    throw new Erc8128Error(
      "PARSE_ERROR",
      "Existing signature dictionaries are malformed."
    )
  }
}

function allocateLabel(preferred: string, used: Set<string>): string {
  const base = /^[a-z*][a-z0-9_.*-]*$/.test(preferred) ? preferred : "sig"
  if (!used.has(base)) return base
  for (let index = 1; index < 100; index += 1) {
    const candidate = `${base}${index}`
    if (!used.has(candidate)) return candidate
  }
  throw new Erc8128Error(
    "INVALID_OPTIONS",
    "No collision-free signature label available."
  )
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

function redirectMethod(status: number, method: string): string {
  if (status === 303 && method !== "HEAD") return "GET"
  if ((status === 301 || status === 302) && method === "POST") return "GET"
  return method
}

function unsignedHeaders(input: Headers): Headers {
  const headers = new Headers(input)
  headers.delete("signature")
  headers.delete("signature-input")
  headers.delete("content-digest")
  headers.delete(DELEGATION_FIELD_NAME)
  return headers
}
