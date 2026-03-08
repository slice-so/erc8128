import type { ContentfulStatusCode } from "hono/utils/http-status"
import type { AuthInstance, CacheStrategy } from "./backend-config"
import type { StorageMode } from "./storage-header"

type VerifyProtectResult = Awaited<
  ReturnType<AuthInstance["erc8128"]["protect"]>
>

type HeaderMap = Record<string, string[]>

type VerificationMetadata = {
  verifyMs: number
  storageMode: StorageMode
  cacheStrategy: CacheStrategy
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

function collectHeaders(headers: Headers): HeaderMap {
  const result: HeaderMap = {}
  for (const [key, value] of headers.entries()) {
    const normalizedKey = key.toLowerCase()
    if (!result[normalizedKey]) {
      result[normalizedKey] = []
    }
    result[normalizedKey].push(value)
  }
  return result
}

function buildVerbosePayload(
  request: Request,
  verification: Record<string, unknown>
) {
  const url = new URL(request.url)
  return {
    ok: verification.ok,
    verified: verification.ok,
    receivedAt: new Date().toISOString(),
    request: {
      method: request.method,
      path: url.pathname,
      query: url.search,
      authority: request.headers.get("host")
    },
    signatureHeaders: {
      signatureInput: request.headers.get("signature-input"),
      signature: request.headers.get("signature")
    },
    verification,
    headers: collectHeaders(request.headers)
  }
}

function withHeaders(target: Headers, source: Headers) {
  for (const [key, value] of source.entries()) {
    target.set(key, value)
  }
  return target
}

export async function buildVerifyProtectResponse(args: {
  request: Request
  protectResult: VerifyProtectResult
  verbose: boolean
  metadata: VerificationMetadata
}): Promise<VerificationHttpResponse> {
  const { request, protectResult, verbose, metadata } = args

  if (protectResult.ok) {
    if (protectResult.verification == null) {
      return {
        status: 500,
        payload: {
          ok: false,
          error: "verification_error",
          detail: "ERC-8128 verification result was not attached",
          ...metadata
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
      payload: verbose
        ? { ...buildVerbosePayload(request, verification), ...metadata }
        : { ...verification, ...metadata },
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
    payload: verbose
      ? {
          ...buildVerbosePayload(request, verification),
          ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
          ...metadata
        }
      : {
          ...verification,
          ...(acceptSignature ? { "accept-signature": acceptSignature } : {}),
          ...metadata
        },
    headers: withHeaders(new Headers(), protectResult.responseHeaders)
  }
}

export function buildVerifyExceptionResponse(args: {
  request: Request
  error: unknown
  verifyMs: number
  verbose: boolean
}): VerificationHttpResponse {
  const { request, error, verifyMs, verbose } = args
  const detail =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "unknown_error"

  return {
    status: 500,
    payload: verbose
      ? {
          ok: false,
          verified: false,
          error: "verification_error",
          detail,
          request: {
            method: request.method,
            path: new URL(request.url).pathname,
            query: new URL(request.url).search,
            authority: request.headers.get("host")
          },
          signatureHeaders: {
            signatureInput: request.headers.get("signature-input"),
            signature: request.headers.get("signature")
          },
          verifyMs
        }
      : {
          ok: false,
          verified: false,
          error: "verification_error",
          detail,
          verifyMs
        },
    headers: new Headers()
  }
}
