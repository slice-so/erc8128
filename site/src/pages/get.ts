import type { NonceStore } from "@slicekit/erc8128"
import { createVerifierClient } from "@slicekit/erc8128"
import type { APIRoute } from "astro"
import { createPublicClient, http } from "viem"

export const prerender = false

type HeaderMap = Record<string, string[]>

const DEFAULT_RPC_URL = "https://eth.llamarpc.com"

const nonceExpirations = new Map<string, number>()
const nonceStore: NonceStore = {
  async consume(key: string, ttlSeconds: number) {
    const now = Date.now()

    for (const [storedKey, expiresAt] of nonceExpirations.entries()) {
      if (expiresAt <= now) nonceExpirations.delete(storedKey)
    }

    const existingExpiry = nonceExpirations.get(key)
    if (typeof existingExpiry === "number" && existingExpiry > now) return false

    nonceExpirations.set(key, now + Math.max(ttlSeconds, 0) * 1000)
    return true
  }
}

const publicClient = createPublicClient({
  transport: http(import.meta.env.ERC8128_DEMO_RPC_URL ?? DEFAULT_RPC_URL)
})

const verifier = createVerifierClient({
  verifyMessage: publicClient.verifyMessage,
  nonceStore,
  defaults: {
    strictLabel: false,
    maxValiditySec: 300
  }
})

const collectHeaders = (headers: Headers): HeaderMap => {
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

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "*"
    }
  })

const isVerboseRequest = (request: Request): boolean => {
  const verbose = new URL(request.url).searchParams.get("verbose")
  return verbose === "1" || verbose === "true"
}

const createVerbosePayload = (
  request: Request,
  verification: Awaited<ReturnType<typeof verifier.verifyRequest>>
) => {
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

const verificationStatus = (
  verification: Awaited<ReturnType<typeof verifier.verifyRequest>>
): number => {
  if (verification.ok) return 200

  if (
    verification.reason === "missing_headers" ||
    verification.reason === "bad_signature_input" ||
    verification.reason === "bad_keyid"
  ) {
    return 400
  }

  return 401
}

const createErrorPayload = (
  request: Request,
  error: unknown,
  verbose: boolean
) => {
  const url = new URL(request.url)
  const detail =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "unknown_error"

  if (!verbose) {
    return {
      ok: false,
      verified: false,
      error: "verification_error",
      detail
    }
  }

  return {
    ok: false,
    verified: false,
    error: "verification_error",
    detail,
    request: {
      method: request.method,
      path: url.pathname,
      query: url.search,
      authority: request.headers.get("host")
    },
    signatureHeaders: {
      signatureInput: request.headers.get("signature-input"),
      signature: request.headers.get("signature")
    }
  }
}

export const OPTIONS: APIRoute = async () =>
  new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "*",
      "access-control-max-age": "86400"
    }
  })

export const GET: APIRoute = async ({ request }) => {
  const verbose = isVerboseRequest(request)

  try {
    const verification = await verifier.verifyRequest({
      request: request.clone()
    })
    if (!verbose) {
      return json(verification, verificationStatus(verification))
    }

    return json(
      createVerbosePayload(request, verification),
      verificationStatus(verification)
    )
  } catch (error) {
    return json(createErrorPayload(request, error, verbose), 500)
  }
}
