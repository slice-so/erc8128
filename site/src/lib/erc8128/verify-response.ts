import type { VerifyResult } from "@slicekit/erc8128"
import type { ContentfulStatusCode } from "hono/utils/http-status"
import type {
  CacheStrategy,
  StorageMode,
  VerificationHttpResponse
} from "../../types"

type VerificationMetadata = {
  verifyMs: number
  storageMode: StorageMode
  cacheStrategy: CacheStrategy
  cachedVerification: boolean
}

function withCachedVerification(metadata: VerificationMetadata) {
  return {
    ...metadata,
    "cached-verification": metadata.cachedVerification
  }
}

function reasonToStatus(reason: string): ContentfulStatusCode {
  if (
    reason === "signature_verification_unavailable" ||
    reason === "grant_verification_unavailable" ||
    reason === "critical_extension_unavailable"
  ) {
    return 503
  }

  return 401
}

function copyHeaders(source: Headers) {
  const target = new Headers()
  for (const [key, value] of source.entries()) {
    target.set(key, value)
  }
  return target
}

export function buildVerifyResultResponse(args: {
  verifyResult: VerifyResult
  responseHeaders: Headers
  metadata: VerificationMetadata
}): VerificationHttpResponse {
  const { verifyResult, responseHeaders, metadata } = args

  if (verifyResult.ok) {
    return {
      status: 200,
      payload: {
        ok: true,
        principal: verifyResult.principal,
        signer: verifyResult.signer,
        delegated: verifyResult.delegated,
        ...(verifyResult.delegated
          ? { delegationId: bytesToHex(verifyResult.delegationId) }
          : {}),
        label: verifyResult.label,
        components: verifyResult.components,
        binding: verifyResult.binding,
        replayable: verifyResult.replay === "replayable",
        params: verifyResult.params,
        ...withCachedVerification(metadata)
      },
      headers: copyHeaders(responseHeaders)
    }
  }

  const acceptSignature = responseHeaders.get("accept-signature")

  return {
    status: reasonToStatus(verifyResult.reason),
    payload: {
      ok: false,
      reason: verifyResult.reason,
      ...(verifyResult.detail ? { detail: verifyResult.detail } : {}),
      ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
      ...withCachedVerification(metadata)
    },
    headers: copyHeaders(responseHeaders)
  }
}

function bytesToHex(bytes: Uint8Array) {
  return `0x${Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("")}`
}

export function buildVerifyExceptionResponse(args: {
  error: Error | string | null | undefined
  verifyMs: number
}): VerificationHttpResponse {
  const { error, verifyMs } = args
  const detail =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "unknown_error"

  return {
    status: 500,
    payload: {
      ok: false,
      verified: false,
      error: "verification_error",
      detail,
      verifyMs
    },
    headers: new Headers()
  }
}
