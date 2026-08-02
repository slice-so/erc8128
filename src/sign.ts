/* eslint-disable no-control-regex */

import { TAG_DELEGATED, TAG_DIRECT } from "./lib/delegation/delegationField"
import { Erc8128Error } from "./lib/Erc8128Error"
import { includesComponent } from "./lib/engine/componentIdentifier"
import { setContentDigestHeader } from "./lib/engine/contentDigest"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase"
import {
  appendDictionaryMember,
  assertSignatureParamsForSerialization,
  resolveComponents,
  serializeSignatureHeader,
  serializeSignatureInputHeader,
  serializeSignatureParamsInnerList
} from "./lib/engine/serializations"
import {
  allocateSignatureLabel,
  collectSignatureLabels
} from "./lib/engine/signatureLabels"
import { invokeFetch } from "./lib/invokeFetch"
import { formatKeyId } from "./lib/keyId"
import { resolveNonce } from "./lib/nonce"
import {
  redirectMethod,
  redirectStatuses,
  unsignedRedirectHeaders
} from "./lib/redirects"
import {
  base64Encode,
  hexToBytes,
  isEthHttpSigner,
  readBodyBytes,
  sanitizeUrl,
  toRequest,
  unixNow
} from "./lib/utilities"
import type { EthHttpSigner, SignatureParams, SignOptions } from "./types"

const SIGNATURE_TAG = Symbol("ERC-8128 signature tag")
type InternalSignOptions = SignOptions & {
  [SIGNATURE_TAG]?: typeof TAG_DIRECT | typeof TAG_DELEGATED
}

/**
 *   Minimal ERC-8128 signing
 * - Fetch-first: works in browsers, workers, Node 18+.
 * - Minimal RFC 9421 engine: message to sign is an ERFC9421 compliant signature base.
 * - Minimal Structured Fields serialization: enough to serialize Signature-Input + Signature for one label.
 *
 *   IMPORTANT:
 * - This is "signing side" only. Verification is not included here.
 * - For Request-Bound with body: we compute Content-Digest using SHA-256 and include it when required.
 * - SHA-256 requires WebCrypto (crypto.subtle) or Node 'node:crypto'. The library will throw CRYPTO_UNAVAILABLE if neither is available.
 */

/**
 * Sign a fetch Request (or RequestInfo+RequestInit) and return a NEW Request with:
 * - Signature-Input
 * - Signature
 * - Content-Digest (if required)
 */
export async function signRequest(
  input: RequestInfo,
  signer: EthHttpSigner,
  opts?: SignOptions
): Promise<Request>
export async function signRequest(
  input: RequestInfo,
  init: RequestInit | undefined,
  signer: EthHttpSigner,
  opts?: SignOptions
): Promise<Request>
export async function signRequest(
  input: RequestInfo,
  initOrSigner: RequestInit | EthHttpSigner | undefined,
  signerOrOpts?: EthHttpSigner | SignOptions,
  opts?: SignOptions
): Promise<Request> {
  let init: RequestInit | undefined
  let signer: EthHttpSigner
  let signOpts: SignOptions | undefined

  if (isEthHttpSigner(initOrSigner)) {
    signer = initOrSigner
    signOpts = signerOrOpts as SignOptions | undefined
  } else {
    init = initOrSigner
    signer = signerOrOpts as EthHttpSigner
    signOpts = opts
  }

  const resolvedOpts = (signOpts ?? {}) as InternalSignOptions
  const request = toRequest(input, init)

  const label = allocateSignatureLabel(
    resolvedOpts.label ?? "eth",
    collectSignatureLabels(
      request.headers.get("signature-input"),
      request.headers.get("signature")
    )
  )
  const binding = resolvedOpts.binding ?? "request-bound"
  const replay = resolvedOpts.replay ?? "non-replayable"
  const digestMode = resolvedOpts.contentDigest ?? "auto"

  const now = unixNow()
  const created = resolvedOpts.created ?? now
  const ttl = resolvedOpts.ttlSeconds ?? 60
  const expires = resolvedOpts.expires ?? created + ttl

  const nonce =
    replay === "non-replayable" ? await resolveNonce(resolvedOpts) : undefined

  const keyid = formatKeyId(signer.chainId, signer.address)

  const url = sanitizeUrl(request.url)
  const hasQuery = url.search.length > 0
  const bodyBytes =
    request.body === null ? new Uint8Array() : await readBodyBytes(request)
  const hasBody = bodyBytes.length > 0

  let components = resolveComponents({
    binding,
    hasQuery,
    hasBody,
    providedComponents: resolvedOpts.components
  })

  if (
    request.headers.has("content-type") &&
    !includesComponent(components, "content-type")
  ) {
    components.push({ name: "content-type" })
  }
  if (
    request.headers.has("content-digest") &&
    !includesComponent(components, "content-digest")
  ) {
    components.push({ name: "content-digest" })
  }

  let signedRequest = request

  // Set content-digest header if required by components
  if (includesComponent(components, "content-digest")) {
    signedRequest = await setContentDigestHeader(
      signedRequest,
      digestMode,
      bodyBytes
    )
  } else if (hasBody) {
    // Every signed request with content carries and covers its digest.
    components = [...components, { name: "content-digest" }]
    signedRequest = await setContentDigestHeader(
      signedRequest,
      digestMode,
      bodyBytes
    )
  }

  const params: SignatureParams = {
    created,
    expires,
    keyid,
    tag: resolvedOpts[SIGNATURE_TAG] ?? TAG_DIRECT,
    ...(nonce ? { nonce } : {})
  }

  assertSignatureParamsForSerialization(params)

  const signatureParamsValue = serializeSignatureParamsInnerList(
    components,
    params
  )
  const signatureInputHeader = serializeSignatureInputHeader(
    label,
    signatureParamsValue
  )

  const M = createSignatureBaseMinimal({
    request: signedRequest,
    components,
    signatureParamsValue
  })

  const sigHex = await signer.signMessage(M)
  const sigBytes = hexToBytes(sigHex)
  if (sigBytes.length === 0 || sigBytes.length > 65_536)
    throw new Erc8128Error(
      "UNSUPPORTED_REQUEST",
      "Signer returned a signature outside the supported size."
    )

  const sigB64 = base64Encode(sigBytes)
  const signatureHeader = serializeSignatureHeader(label, sigB64)

  const headers = new Headers(signedRequest.headers)
  const combinedSignatureInput = appendDictionaryMember(
    headers.get("Signature-Input"),
    signatureInputHeader
  )
  const combinedSignature = appendDictionaryMember(
    headers.get("Signature"),
    signatureHeader
  )
  if (
    new TextEncoder().encode(combinedSignatureInput).length > 65_536 ||
    new TextEncoder().encode(combinedSignature).length > 65_536
  ) {
    throw new Erc8128Error(
      "UNSUPPORTED_REQUEST",
      "Signature fields exceed the supported size."
    )
  }
  headers.set("Signature-Input", combinedSignatureInput)
  headers.set("Signature", combinedSignature)

  return new Request(signedRequest, { headers })
}

/** Internal delegated profile entrypoint; intentionally absent from package exports. */
export function signDelegatedRequest(
  input: RequestInfo,
  signer: EthHttpSigner,
  options?: SignOptions
): Promise<Request> {
  const internalOptions: InternalSignOptions = {
    ...options,
    [SIGNATURE_TAG]: TAG_DELEGATED
  }
  return signRequest(input, signer, internalOptions)
}

export async function signedFetch(
  input: RequestInfo,
  signer: EthHttpSigner,
  opts?: SignOptions & { fetch?: typeof fetch }
): Promise<Response>
export async function signedFetch(
  input: RequestInfo,
  init: RequestInit | undefined,
  signer: EthHttpSigner,
  opts?: SignOptions & { fetch?: typeof fetch }
): Promise<Response>
export async function signedFetch(
  input: RequestInfo,
  initOrSigner: RequestInit | EthHttpSigner | undefined,
  signerOrOpts?: EthHttpSigner | (SignOptions & { fetch?: typeof fetch }),
  opts?: SignOptions & { fetch?: typeof fetch }
): Promise<Response> {
  let init: RequestInit | undefined
  let signer: EthHttpSigner
  let resolvedOpts: (SignOptions & { fetch?: typeof fetch }) | undefined

  if (isEthHttpSigner(initOrSigner)) {
    signer = initOrSigner
    resolvedOpts = signerOrOpts as
      | (SignOptions & { fetch?: typeof fetch })
      | undefined
  } else {
    init = initOrSigner
    signer = signerOrOpts as EthHttpSigner
    resolvedOpts = opts
  }

  let nextInput = input
  let nextInit = init
  let signingOptions = resolvedOpts
  for (let redirects = 0; redirects <= 10; redirects += 1) {
    const signed = await signRequest(
      nextInput,
      nextInit,
      signer,
      signingOptions
    )
    const redirectedBody =
      signed.method === "GET" || signed.method === "HEAD"
        ? undefined
        : await signed.clone().arrayBuffer()
    const response = await invokeFetch(
      signingOptions?.fetch,
      new Request(signed, { redirect: "manual" })
    )
    if (!redirectStatuses.has(response.status)) return response
    const location = response.headers.get("location")
    if (!location) return response
    if (redirects === 10) {
      throw new Erc8128Error("UNSUPPORTED_REQUEST", "Too many redirects.")
    }
    const target = new URL(location, signed.url)
    const method = redirectMethod(response.status, signed.method)
    nextInput = target.href
    if (typeof signingOptions?.nonce === "string") {
      const { nonce: _usedNonce, ...redirectOptions } = signingOptions
      signingOptions = redirectOptions
    }
    nextInit = {
      method,
      headers: unsignedRedirectHeaders(signed.headers),
      ...(method === "GET" || method === "HEAD" ? {} : { body: redirectedBody })
    }
  }
  throw new Erc8128Error("UNSUPPORTED_REQUEST", "Redirect processing failed.")
}
