/* eslint-disable no-control-regex */
import { setContentDigestHeader } from "./lib/engine/contentDigest.js"
import { createSignatureBaseMinimal } from "./lib/engine/createSignatureBase.js"
import {
  appendDictionaryMember,
  assertSignatureParamsForSerialization,
  resolveComponents,
  serializeSignatureHeader,
  serializeSignatureInputHeader,
  serializeSignatureParamsInnerList
} from "./lib/engine/serializations.js"
import { formatKeyId } from "./lib/keyId.js"
import { resolveNonce } from "./lib/nonce.js"
import { Erc8128Error } from "./lib/types.js"
import {
  base64Encode,
  hexToBytes,
  isEthHttpSigner,
  sanitizeUrl,
  toRequest,
  unixNow
} from "./lib/utilities.js"
export async function signRequest(input, initOrSigner, signerOrOpts, opts) {
  let init
  let signer
  let signOpts
  if (isEthHttpSigner(initOrSigner)) {
    signer = initOrSigner
    signOpts = signerOrOpts
  } else {
    init = initOrSigner
    signer = signerOrOpts
    signOpts = opts
  }
  const resolvedOpts = signOpts ?? {}
  const request = toRequest(input, init)
  const label = resolvedOpts.label ?? "eth"
  const binding = resolvedOpts.binding ?? "request-bound"
  const replay = resolvedOpts.replay ?? "non-replayable"
  const headerMode = resolvedOpts.headerMode ?? "replace"
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
  const hasBody = request.body != null
  let components = resolveComponents({
    binding,
    hasQuery,
    hasBody,
    providedComponents: resolvedOpts.components
  })
  let signedRequest = request
  // Set content-digest header if required by components
  if (components.includes("content-digest")) {
    signedRequest = await setContentDigestHeader(signedRequest, digestMode)
  } else if (binding === "request-bound" && hasBody) {
    // Auto-add content-digest for request-bound with body
    components = [...components, "content-digest"]
    signedRequest = await setContentDigestHeader(signedRequest, digestMode)
  }
  const params = {
    created,
    expires,
    keyid,
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
  if (sigBytes.length === 0)
    throw new Erc8128Error(
      "UNSUPPORTED_REQUEST",
      "Signer returned empty signature."
    )
  const sigB64 = base64Encode(sigBytes)
  const signatureHeader = serializeSignatureHeader(label, sigB64)
  const headers = new Headers(signedRequest.headers)
  if (headerMode === "replace") {
    headers.set("Signature-Input", signatureInputHeader)
    headers.set("Signature", signatureHeader)
  } else {
    headers.set(
      "Signature-Input",
      appendDictionaryMember(
        headers.get("Signature-Input"),
        signatureInputHeader
      )
    )
    headers.set(
      "Signature",
      appendDictionaryMember(headers.get("Signature"), signatureHeader)
    )
  }
  return new Request(signedRequest, { headers })
}
export async function signedFetch(input, initOrSigner, signerOrOpts, opts) {
  let init
  let signer
  let resolvedOpts
  if (isEthHttpSigner(initOrSigner)) {
    signer = initOrSigner
    resolvedOpts = signerOrOpts
  } else {
    init = initOrSigner
    signer = signerOrOpts
    resolvedOpts = opts
  }
  const req = await signRequest(input, init, signer, resolvedOpts)
  const f = resolvedOpts?.fetch ?? globalThis.fetch
  if (typeof f !== "function")
    throw new Erc8128Error(
      "UNSUPPORTED_REQUEST",
      "No fetch implementation available. Provide opts.fetch."
    )
  return f(req)
}
//# sourceMappingURL=sign.js.map
