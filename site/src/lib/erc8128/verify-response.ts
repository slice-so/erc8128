import type { ContentfulStatusCode } from "hono/utils/http-status"
import type { AuthInstance, CacheStrategy } from "./backend-config"
import type { StorageMode } from "./storage-header"

type VerifyProtectResult = Awaited<
  ReturnType<AuthInstance["erc8128"]["protect"]>
>
type VerifyRequestResult = Awaited<
  ReturnType<AuthInstance["erc8128"]["verifyRequest"]>
>

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

export type VerificationHttpResponse = {
  status: ContentfulStatusCode
  payload: Record<string, unknown>
  headers: Headers
}

function mapErrorReason(reason: string): string {
  if (reason === "missing_signature") return "missing_headers"
  if (reason === "missing_request_context") return "missing_headers"
  return reason
}

function reasonToStatus(reason: string): ContentfulStatusCode {
  if (
    reason === "missing_headers" ||
    reason === "bad_signature_input" ||
    reason === "bad_keyid"
  ) {
    return 400
  }

  return 401
}

function withHeaders(target: Headers, source: Headers) {
  for (const [key, value] of source.entries()) {
    target.set(key, value)
  }
  return target
}

export async function buildVerifyResultResponse(args: {
  verifyResult: VerifyRequestResult
  metadata: VerificationMetadata
}): Promise<VerificationHttpResponse> {
  const { verifyResult, metadata } = args

  if (verifyResult.ok) {
    const verification = {
      ok: true as const,
      address: verifyResult.verification.address,
      chainId: verifyResult.verification.chainId,
      label: verifyResult.verification.label,
      components: verifyResult.verification.components,
      binding: verifyResult.verification.binding,
      replayable: verifyResult.verification.replayable,
      params: verifyResult.verification.params
    }

    return {
      status: 200,
      payload: { ...verification, ...withCachedVerification(metadata) },
      headers: withHeaders(new Headers(), verifyResult.responseHeaders)
    }
  }

  const authResponseText = await verifyResult.response.clone().text()
  const body =
    authResponseText.length > 0
      ? (() => {
          try {
            return JSON.parse(authResponseText) as Record<string, unknown>
          } catch {
            return null
          }
        })()
      : null

  const acceptSignature = verifyResult.responseHeaders.get("accept-signature")
  const reason = mapErrorReason((body?.reason as string) || "unknown")
  const detail = (body?.detail as string) || (body?.message as string) || ""

  return {
    status: reasonToStatus(reason),
    payload: {
      ok: false,
      reason,
      ...(detail ? { detail } : {}),
      ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
      ...withCachedVerification(metadata)
    },
    headers: withHeaders(new Headers(), verifyResult.responseHeaders)
  }
}

export async function buildVerifyProtectResponse(args: {
  protectResult: VerifyProtectResult
  metadata: VerificationMetadata
}): Promise<VerificationHttpResponse> {
  const { protectResult, metadata } = args

  if (protectResult.ok) {
    if (protectResult.verification == null) {
      return {
        status: 500,
        payload: {
          ok: false,
          error: "verification_error",
          detail: "ERC-8128 verification result was not attached",
          ...withCachedVerification(metadata)
        },
        headers: withHeaders(new Headers(), protectResult.responseHeaders)
      }
    }

    const verification = {
      ok: true as const,
      address: protectResult.verification.address,
      chainId: protectResult.verification.chainId,
      label: protectResult.verification.label,
      components: protectResult.verification.components,
      binding: protectResult.verification.binding,
      replayable: protectResult.verification.replayable,
      params: protectResult.verification.params
    }

    return {
      status: 200,
      payload: { ...verification, ...withCachedVerification(metadata) },
      headers: withHeaders(new Headers(), protectResult.responseHeaders)
    }
  }

  const authResponseText = await protectResult.response.clone().text()
  const body =
    authResponseText.length > 0
      ? (() => {
          try {
            return JSON.parse(authResponseText) as Record<string, unknown>
          } catch {
            return null
          }
        })()
      : null

  const acceptSignature = protectResult.responseHeaders.get("accept-signature")
  const reason = mapErrorReason((body?.reason as string) || "unknown")
  const detail = (body?.detail as string) || (body?.message as string) || ""
  const verification = {
    ok: false as const,
    reason,
    ...(detail ? { detail } : {})
  }

  return {
    status: reasonToStatus(reason),
    payload: {
      ...verification,
      ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
      ...withCachedVerification(metadata)
    },
    headers: withHeaders(new Headers(), protectResult.responseHeaders)
  }
}

export function buildVerifyExceptionResponse(args: {
  error: unknown
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
