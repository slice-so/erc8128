import {
  formatErc8128ProblemDetails,
  type VerifyResult
} from "@slicekit/erc8128"
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
          ? { delegationIds: verifyResult.delegationIds }
          : {
              label: verifyResult.label,
              components: verifyResult.components,
              params: verifyResult.params
            }),
        binding: verifyResult.binding,
        replayable: verifyResult.replay === "replayable",
        ...withCachedVerification(metadata)
      },
      headers: copyHeaders(responseHeaders)
    }
  }

  const acceptSignature = responseHeaders.get("accept-signature")
  const problem = formatErc8128ProblemDetails(verifyResult)

  return {
    status: problem.status,
    payload: {
      ...problem,
      ok: false,
      ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
      ...withCachedVerification(metadata)
    },
    headers: copyHeaders(responseHeaders)
  }
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
