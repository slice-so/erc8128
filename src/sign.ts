/* eslint-disable no-control-regex */

import { TAG_DELEGATED, TAG_REQUEST } from "./lib/delegation/delegationField"
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
  [SIGNATURE_TAG]?: typeof TAG_REQUEST | typeof TAG_DELEGATED
}
type FetchSignOptions = SignOptions & { fetch?: typeof fetch }
type SignOptionsResolver = (
  request: Request
) => FetchSignOptions | Promise<FetchSignOptions | undefined> | undefined

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
  return signPreparedRequest(toRequest(input, init), signer, resolvedOpts)
}

async function signPreparedRequest(
  request: Request,
  signer: EthHttpSigner,
  resolvedOpts: InternalSignOptions,
  preparedBodyBytes?: Uint8Array
): Promise<Request> {
  const bodyBytes =
    preparedBodyBytes ??
    (request.body === null ? new Uint8Array() : await readBodyBytes(request))
  const bufferedRequest =
    request.body === null
      ? request
      : new Request(request, { body: toArrayBuffer(bodyBytes) })

  const label = allocateSignatureLabel(
    resolvedOpts.label ?? "request",
    collectSignatureLabels(
      bufferedRequest.headers.get("signature-input"),
      bufferedRequest.headers.get("signature")
    )
  )
  const binding = resolvedOpts.binding ?? "request-bound"
  const digestMode = resolvedOpts.contentDigest ?? "auto"

  const now = unixNow()
  const created = resolvedOpts.created ?? now
  const ttl = resolvedOpts.ttlSeconds ?? 60
  const expires = resolvedOpts.expires ?? created + ttl

  const nonce =
    resolvedOpts.nonce === null ? undefined : await resolveNonce(resolvedOpts)

  const keyid = formatKeyId(signer.chainId, signer.address)

  const url = sanitizeUrl(bufferedRequest.url)
  const hasQuery = url.search.length > 0
  const hasBody = bodyBytes.length > 0

  let components = resolveComponents({
    binding,
    hasQuery,
    hasBody,
    providedComponents: resolvedOpts.components
  })

  if (
    bufferedRequest.headers.has("content-type") &&
    !includesComponent(components, "content-type")
  ) {
    components.push({ name: "content-type" })
  }
  if (
    bufferedRequest.headers.has("content-digest") &&
    !includesComponent(components, "content-digest")
  ) {
    components.push({ name: "content-digest" })
  }

  let signedRequest = bufferedRequest

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
    tag: resolvedOpts[SIGNATURE_TAG] ?? TAG_REQUEST,
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
  if (sigBytes.length === 0 || sigBytes.length > 8_192)
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
    new TextEncoder().encode(combinedSignatureInput).length > 16_384 ||
    new TextEncoder().encode(combinedSignature).length > 16_384
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
  opts?: FetchSignOptions
): Promise<Response>
export async function signedFetch(
  input: RequestInfo,
  init: RequestInit | undefined,
  signer: EthHttpSigner,
  opts?: FetchSignOptions
): Promise<Response>
export async function signedFetch(
  input: RequestInfo,
  initOrSigner: RequestInit | EthHttpSigner | undefined,
  signerOrOpts?: EthHttpSigner | FetchSignOptions,
  opts?: FetchSignOptions
): Promise<Response> {
  let init: RequestInit | undefined
  let signer: EthHttpSigner
  let resolvedOpts: FetchSignOptions | undefined

  if (isEthHttpSigner(initOrSigner)) {
    signer = initOrSigner
    resolvedOpts = signerOrOpts as FetchSignOptions | undefined
  } else {
    init = initOrSigner
    signer = signerOrOpts as EthHttpSigner
    resolvedOpts = opts
  }

  return signedFetchWithOptionsResolver(input, init, signer, () => resolvedOpts)
}

/** Internal route-aware entrypoint used by createSignerClient. */
export async function signedFetchWithOptionsResolver(
  input: RequestInfo,
  init: RequestInit | undefined,
  signer: EthHttpSigner,
  resolveOptions: SignOptionsResolver
): Promise<Response> {
  let nextRequest = toRequest(input, init)
  let bodyBytes =
    nextRequest.body === null
      ? new Uint8Array()
      : await readBodyBytes(nextRequest)
  const redirectMode = nextRequest.redirect

  for (let redirects = 0; redirects <= 10; redirects += 1) {
    const resolvedOptions = (await resolveOptions(nextRequest)) ?? {}
    const signingOptions = withoutConsumedNonce(resolvedOptions, redirects)
    const signed = await signPreparedRequest(
      nextRequest,
      signer,
      signingOptions,
      bodyBytes
    )
    const response = await invokeFetch(
      signingOptions?.fetch,
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
    const method = redirectMethod(response.status, signed.method)
    const keepsBody = method !== "GET" && method !== "HEAD"
    if (!keepsBody) bodyBytes = new Uint8Array()
    nextRequest = new Request(target, {
      method,
      headers: unsignedRedirectHeaders(
        signed.headers,
        new URL(signed.url).origin,
        target.origin
      ),
      ...(keepsBody ? { body: toArrayBuffer(bodyBytes) } : {}),
      cache: nextRequest.cache,
      credentials: nextRequest.credentials,
      integrity: nextRequest.integrity,
      keepalive: nextRequest.keepalive,
      mode: nextRequest.mode,
      redirect: redirectMode,
      referrer: nextRequest.referrer,
      referrerPolicy: nextRequest.referrerPolicy,
      signal: nextRequest.signal
    })
  }
  throw new Erc8128Error("UNSUPPORTED_REQUEST", "Redirect processing failed.")
}

function withoutConsumedNonce(
  options: FetchSignOptions,
  redirects: number
): FetchSignOptions {
  if (redirects === 0 || typeof options.nonce !== "string") return options
  const { nonce: _consumedNonce, ...redirectOptions } = options
  return redirectOptions
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer
}
